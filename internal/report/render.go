package report

import (
	"bytes"
	"embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/amit/47certificates/internal/csvsafe"
	"github.com/amit/47certificates/internal/x509eval"
)

//go:embed templates/*.html
var templateFS embed.FS

var tmpl = template.Must(template.New("").Funcs(template.FuncMap{
	"when":        func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") },
	"json":        func(v any) string { b, _ := json.MarshalIndent(v, "", "  "); return string(b) },
	"hasFindings": func(o reportObs) bool { return len(o.Findings) > 0 },
	"findingType": func(f x509eval.Finding) string { return f.Type },
	"endpoints":   func(o reportObs) string { return endpointList(o) },
	"findingSentence": func(f x509eval.Finding) string {
		switch f.Type {
		case x509eval.ViolatesCurrentPhase:
			return fmt.Sprintf("lifetime %v days exceeds %v allowed for certificates issued after the current phase began", f.Detail["lifetime_days"], f.Detail["max_days"])
		case x509eval.GrandfatheredTooLong:
			return fmt.Sprintf("lifetime %v days exceeds today's %v-day limit; issued before the current phase began", f.Detail["lifetime_days"], f.Detail["max_days"])
		case x509eval.Exceeds47Target:
			return fmt.Sprintf("lifetime %v days exceeds the 47-day target", f.Detail["lifetime_days"])
		case x509eval.ExpiresSoon:
			return fmt.Sprintf("expires in %v days", f.Detail["days_left"])
		case x509eval.ExpiredServed:
			return "expired but still served"
		default:
			return f.Type
		}
	},
}).ParseFS(templateFS, "templates/*.html"))

// endpointList renders the endpoints of one certificate as "host:port" pairs.
func endpointList(o reportObs) string {
	parts := make([]string, 0, len(o.Endpoints))
	for _, ep := range o.Endpoints {
		parts = append(parts, fmt.Sprintf("%s:%d", ep.Host, ep.Port))
	}
	return strings.Join(parts, ", ")
}

func renderHTML(kind Kind, v reportView) ([]byte, error) {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, string(kind)+".html", v); err != nil {
		return nil, fmt.Errorf("report: render %s: %w", kind, err)
	}
	return buf.Bytes(), nil
}

// renderCSV writes one row per certificate, then one row per endpoint. The
// header block carries the provenance every format must embed.
func renderCSV(v reportView) []byte {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"# 47c report"})
	_ = w.Write([]string{"# report_id=" + fmt.Sprint(v.ReportID)})
	_ = w.Write([]string{"# scan_id=" + fmt.Sprint(v.ScanID)})
	_ = w.Write([]string{"# scan_time=" + v.ScanTime.UTC().Format(time.RFC3339)})
	_ = w.Write([]string{"# generated_at=" + v.GeneratedAt.UTC().Format(time.RFC3339)})
	_ = w.Write([]string{"# kind=" + string(v.Kind)})
	_ = w.Write([]string{"# version=" + v.Version})
	_ = w.Write([]string{"# phase=" + v.Phase.Name})
	_ = w.Write([]string{"# scope=" + v.Scope})
	_ = w.Write([]string{"# notice=" + v.Notice})
	_ = w.Write([]string{"# certs"})
	_ = w.Write([]string{"fingerprint_sha256", "subject", "issuer", "not_before", "not_after", "lifetime_days", "trust", "bucket", "severity", "key_alg", "key_bits", "sig_alg", "sans", "endpoints"})
	for _, o := range append(append([]reportObs{}, v.Public...), v.Private...) {
		_ = w.Write(csvsafe.Row([]string{
			o.Fingerprint, o.Subject, o.Issuer,
			o.NotBefore.UTC().Format(time.RFC3339), o.NotAfter.UTC().Format(time.RFC3339),
			fmt.Sprint(o.LifetimeDays), o.Trust, o.Bucket, o.Severity,
			o.KeyAlg, fmt.Sprint(o.KeyBits), o.SigAlg,
			strings.Join(o.SANs, " "), endpointList(o),
		}))
	}
	_ = w.Write([]string{"# endpoints"})
	_ = w.Write([]string{"host", "port", "ip", "fingerprint_sha256", "tls_version", "cipher", "chain_valid", "hostname_valid", "trust"})
	for _, o := range append(append([]reportObs{}, v.Public...), v.Private...) {
		for _, ep := range o.Endpoints {
			_ = w.Write(csvsafe.Row([]string{
				ep.Host, fmt.Sprint(ep.Port), ep.IP, o.Fingerprint,
				fmt.Sprintf("0x%04x", ep.TLSVersion), fmt.Sprintf("0x%04x", ep.Cipher),
				fmt.Sprint(ep.ChainValid), fmt.Sprint(ep.HostnameValid), ep.Trust,
			}))
		}
	}
	w.Flush()
	return buf.Bytes()
}

func renderJSON(v reportView) ([]byte, error) {
	type endpointJSON struct {
		Host          string `json:"host"`
		Port          int    `json:"port"`
		IP            string `json:"ip"`
		Trust         string `json:"trust"`
		ChainValid    bool   `json:"chain_valid"`
		HostnameValid bool   `json:"hostname_valid"`
		TLSVersion    string `json:"tls_version"`
		Cipher        string `json:"cipher"`
	}
	type certJSON struct {
		Fingerprint   string          `json:"fingerprint_sha256"`
		Subject       string          `json:"subject"`
		Issuer        string          `json:"issuer"`
		NotBefore     string          `json:"not_before"`
		NotAfter      string          `json:"not_after"`
		LifetimeDays  int             `json:"lifetime_days"`
		Trust         string          `json:"trust"`
		ChainValid    bool            `json:"chain_valid"`
		HostnameValid bool            `json:"hostname_valid"`
		Bucket        string          `json:"bucket"`
		Severity      string          `json:"severity"`
		KeyAlg        string          `json:"key_alg"`
		KeyBits       int             `json:"key_bits"`
		SigAlg        string          `json:"sig_alg"`
		SANs          []string        `json:"sans"`
		Findings      []string        `json:"findings"`
		Endpoints     []endpointJSON  `json:"endpoints"`
	}
	toCerts := func(in []reportObs) []certJSON {
		out := make([]certJSON, 0, len(in))
		for _, o := range in {
			fs := make([]string, 0, len(o.Findings))
			for _, f := range o.Findings {
				fs = append(fs, f.Type)
			}
			eps := make([]endpointJSON, 0, len(o.Endpoints))
			for _, ep := range o.Endpoints {
				eps = append(eps, endpointJSON{
					Host:          ep.Host,
					Port:          ep.Port,
					IP:            ep.IP,
					Trust:         ep.Trust,
					ChainValid:    ep.ChainValid,
					HostnameValid: ep.HostnameValid,
					TLSVersion:    fmt.Sprintf("0x%04x", ep.TLSVersion),
					Cipher:        fmt.Sprintf("0x%04x", ep.Cipher),
				})
			}
			out = append(out, certJSON{
				Fingerprint:   o.Fingerprint,
				Subject:       o.Subject,
				Issuer:        o.Issuer,
				NotBefore:     o.NotBefore.UTC().Format(time.RFC3339),
				NotAfter:      o.NotAfter.UTC().Format(time.RFC3339),
				LifetimeDays:  o.LifetimeDays,
				Trust:         o.Trust,
				ChainValid:    o.ChainValid,
				HostnameValid: o.HostnameValid,
				Bucket:        o.Bucket,
				Severity:      o.Severity,
				KeyAlg:        o.KeyAlg,
				KeyBits:       o.KeyBits,
				SigAlg:        o.SigAlg,
				SANs:          o.SANs,
				Findings:      fs,
				Endpoints:     eps,
			})
		}
		return out
	}
	doc := map[string]any{
		"schema_version":   1,
		"report_id":        v.ReportID,
		"scan_id":          v.ScanID,
		"scan_time":        v.ScanTime.UTC().Format(time.RFC3339),
		"kind":             v.Kind,
		"domain":           v.Domain,
		"generated_at":     v.GeneratedAt.UTC().Format(time.RFC3339),
		"scope":            v.Scope,
		"version":          v.Version,
		"phase":            v.Phase.Name,
		"notice":           v.Notice,
		"delta":            v.Delta,
		"counts":           v.Counts,
		"total":            v.Total,
		"certificates":     toCerts(v.Public),
		"appendix_private": toCerts(v.Private),
	}
	return json.MarshalIndent(doc, "", "  ")
}
