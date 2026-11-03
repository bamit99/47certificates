package report

import (
	"bytes"
	"embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"time"

	"github.com/amit/47certificates/internal/x509eval"
)

//go:embed templates/*.html
var templateFS embed.FS

var tmpl = template.Must(template.New("").Funcs(template.FuncMap{
	"when":        func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") },
	"json":        func(v any) string { b, _ := json.MarshalIndent(v, "", "  "); return string(b) },
	"hasFindings": func(o reportObs) bool { return len(o.Findings) > 0 },
	"findingType": func(f x509eval.Finding) string { return f.Type },
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

func renderHTML(kind Kind, v reportView) ([]byte, error) {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, string(kind)+".html", v); err != nil {
		return nil, fmt.Errorf("report: render %s: %w", kind, err)
	}
	return buf.Bytes(), nil
}

func renderCSV(v reportView) []byte {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"# 47c report", "report_id=" + fmt.Sprint(v.ReportID), "scan_id=" + fmt.Sprint(v.ScanID), "kind=" + string(v.Kind)})
	_ = w.Write([]string{"# certs"})
	_ = w.Write([]string{"fingerprint_sha256", "subject", "issuer", "host", "port", "ip", "not_before", "not_after", "lifetime_days", "trust", "bucket", "severity", "key_alg", "key_bits", "sig_alg"})
	for _, o := range v.Public {
		_ = w.Write([]string{
			o.Fingerprint, o.Subject, o.Issuer, o.Host, fmt.Sprint(o.Port), o.IP,
			o.NotBefore.UTC().Format(time.RFC3339), o.NotAfter.UTC().Format(time.RFC3339),
			fmt.Sprint(o.LifetimeDays), o.Trust, o.Bucket, o.Severity, o.KeyAlg, fmt.Sprint(o.KeyBits), o.SigAlg,
		})
	}
	for _, o := range v.Private {
		_ = w.Write([]string{
			o.Fingerprint, o.Subject, o.Issuer, o.Host, fmt.Sprint(o.Port), o.IP,
			o.NotBefore.UTC().Format(time.RFC3339), o.NotAfter.UTC().Format(time.RFC3339),
			fmt.Sprint(o.LifetimeDays), o.Trust, o.Bucket, o.Severity, o.KeyAlg, fmt.Sprint(o.KeyBits), o.SigAlg,
		})
	}
	_ = w.Write([]string{"# endpoints"})
	_ = w.Write([]string{"host", "port", "ip", "fingerprint_sha256", "tls_version", "cipher", "chain_valid", "hostname_valid", "trust"})
	for _, o := range append(append([]reportObs{}, v.Public...), v.Private...) {
		_ = w.Write([]string{
			o.Host, fmt.Sprint(o.Port), o.IP, o.Fingerprint,
			fmt.Sprintf("0x%04x", o.TLSVersion), fmt.Sprintf("0x%04x", o.Cipher),
			fmt.Sprint(o.ChainValid), fmt.Sprint(o.HostnameValid), o.Trust,
		})
	}
	w.Flush()
	return buf.Bytes()
}

func renderJSON(v reportView) ([]byte, error) {
	type obsJSON struct {
		Fingerprint  string   `json:"fingerprint_sha256"`
		Host         string   `json:"host"`
		Port         int      `json:"port"`
		IP           string   `json:"ip"`
		Subject      string   `json:"subject"`
		Issuer       string   `json:"issuer"`
		NotBefore    string   `json:"not_before"`
		NotAfter     string   `json:"not_after"`
		LifetimeDays int      `json:"lifetime_days"`
		Trust        string   `json:"trust"`
		Bucket       string   `json:"bucket"`
		Severity     string   `json:"severity"`
		KeyAlg       string   `json:"key_alg"`
		KeyBits      int      `json:"key_bits"`
		SigAlg       string   `json:"sig_alg"`
		Findings     []string `json:"findings"`
	}
	toObs := func(in []reportObs) []obsJSON {
		out := make([]obsJSON, 0, len(in))
		for _, o := range in {
			fs := make([]string, 0, len(o.Findings))
			for _, f := range o.Findings {
				fs = append(fs, f.Type)
			}
			out = append(out, obsJSON{
				Fingerprint:  o.Fingerprint,
				Host:         o.Host,
				Port:         o.Port,
				IP:           o.IP,
				Subject:      o.Subject,
				Issuer:       o.Issuer,
				NotBefore:    o.NotBefore.UTC().Format(time.RFC3339),
				NotAfter:     o.NotAfter.UTC().Format(time.RFC3339),
				LifetimeDays: o.LifetimeDays,
				Trust:        o.Trust,
				Bucket:       o.Bucket,
				Severity:     o.Severity,
				KeyAlg:       o.KeyAlg,
				KeyBits:      o.KeyBits,
				SigAlg:       o.SigAlg,
				Findings:     fs,
			})
		}
		return out
	}
	doc := map[string]any{
		"schema_version":   1,
		"report_id":        v.ReportID,
		"scan_id":          v.ScanID,
		"kind":             v.Kind,
		"domain":           v.Domain,
		"generated_at":     v.GeneratedAt.UTC().Format(time.RFC3339),
		"scope":            v.Scope,
		"version":          v.Version,
		"phase":            v.Phase.Name,
		"delta":            v.Delta,
		"counts":           v.Counts,
		"total":            v.Total,
		"observations":     toObs(v.Public),
		"appendix_private": toObs(v.Private),
	}
	return json.MarshalIndent(doc, "", "  ")
}
