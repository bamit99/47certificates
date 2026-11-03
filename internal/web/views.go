package web

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/amit/47certificates/internal/store"
	"github.com/amit/47certificates/internal/x509eval"
)

// FindingView is a persisted finding interpreted for display.
type FindingView struct {
	Type     string         `json:"type"`
	Status   string         `json:"status"`
	Detail   map[string]any `json:"detail,omitempty"`
	Severity string         `json:"severity"`
	Bucket   string         `json:"bucket"`
	Sentence string         `json:"sentence"`
}

// CertView is a certificate with derived classification.
type CertView struct {
	Fingerprint  string        `json:"fingerprint_sha256"`
	ShortFP      string        `json:"short_fingerprint"`
	Subject      string        `json:"subject"`
	Issuer       string        `json:"issuer"`
	NotBefore    time.Time     `json:"not_before"`
	NotAfter     time.Time     `json:"not_after"`
	LifetimeDays int           `json:"lifetime_days"`
	KeyAlg       string        `json:"key_alg"`
	KeyBits      int           `json:"key_bits"`
	SigAlg       string        `json:"sig_alg"`
	SANs         []string      `json:"sans"`
	FirstSeen    time.Time     `json:"first_seen"`
	LastSeen     *time.Time    `json:"last_seen,omitempty"`
	Retired      bool          `json:"retired"`
	HasRaw       bool          `json:"has_raw"`
	Findings     []FindingView `json:"findings"`
	Bucket       string        `json:"bucket"`
	Severity     string        `json:"severity"`
	DaysLeft     int           `json:"days_left"`
	ID           int64         `json:"-"`
}

// bucketLabels orders the dashboard.
var bucketLabels = []struct {
	Key   string
	Label string
}{
	{"violation", "Violations"},
	{"grandfathered", "Grandfathered"},
	{"expiring", "Expiring"},
	{"target", "Above 47-day target"},
	{"info", "Informational"},
	{"ok", "Compliant"},
}

var severityRank = map[string]int{
	"critical": 5,
	"high":     4,
	"medium":   3,
	"low":      2,
	"info":     1,
	"ok":       0,
}

func buildCertView(c store.CertSummary, now time.Time) CertView {
	v := CertView{
		Fingerprint:  c.Fingerprint,
		ShortFP:      shortFP(c.Fingerprint),
		Subject:      c.Subject,
		Issuer:       c.Issuer,
		NotBefore:    c.NotBefore,
		NotAfter:     c.NotAfter,
		LifetimeDays: c.LifetimeDays,
		KeyAlg:       c.KeyAlg,
		KeyBits:      c.KeyBits,
		SigAlg:       c.SigAlg,
		SANs:         c.SANs,
		FirstSeen:    c.FirstSeen,
		LastSeen:     c.LastSeen,
		Retired:      c.RetiredAt != nil,
		HasRaw:       c.HasRaw,
		DaysLeft:     int(c.NotAfter.Sub(now) / (24 * time.Hour)),
		ID:           c.ID,
	}
	for _, f := range c.Findings {
		v.Findings = append(v.Findings, buildFindingView(f, now))
	}
	v.Bucket = bucketOfViews(v.Findings)
	v.Severity = severityOfViews(v.Findings)
	return v
}

func buildFindingView(f store.Finding, now time.Time) FindingView {
	detail := map[string]any{}
	if f.Detail != "" {
		_ = json.Unmarshal([]byte(f.Detail), &detail)
	}
	// JSON numbers decode to float64; findings code expects int.
	if d, ok := detail["days_left"].(float64); ok {
		detail["days_left"] = int(d)
	}
	xf := x509eval.Finding{Type: f.Type, Detail: detail}
	return FindingView{
		Type:     f.Type,
		Status:   f.Status,
		Detail:   detail,
		Severity: x509eval.Severity(xf, now),
		Bucket:   x509eval.Bucket([]x509eval.Finding{xf}),
		Sentence: describe(xf),
	}
}

func bucketOfViews(fs []FindingView) string {
	var xf []x509eval.Finding
	for _, f := range fs {
		if f.Status == "resolved" {
			continue
		}
		xf = append(xf, x509eval.Finding{Type: f.Type})
	}
	return x509eval.Bucket(xf)
}

func severityOfViews(fs []FindingView) string {
	best := "ok"
	for _, f := range fs {
		if f.Status == "resolved" {
			continue
		}
		if severityRank[f.Severity] > severityRank[best] {
			best = f.Severity
		}
	}
	return best
}

func shortFP(fp string) string {
	if len(fp) <= 16 {
		return fp
	}
	return fp[:16]
}

func detailInt(d map[string]any, key string) int {
	switch v := d[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return 0
}

func describe(f x509eval.Finding) string {
	switch f.Type {
	case x509eval.ViolatesCurrentPhase:
		start := "2026-03-15"
		if m := detailInt(f.Detail, "max_days"); m == 100 {
			start = "2027-03-15"
		} else if m == 47 {
			start = "2029-03-15"
		}
		return fmt.Sprintf("lifetime %dd exceeds %dd allowed for certificates issued after %s",
			detailInt(f.Detail, "lifetime_days"), detailInt(f.Detail, "max_days"), start)
	case x509eval.GrandfatheredTooLong:
		return fmt.Sprintf("lifetime %dd exceeds today's %dd limit; issued before the current phase began",
			detailInt(f.Detail, "lifetime_days"), detailInt(f.Detail, "max_days"))
	case x509eval.Exceeds47Target:
		return fmt.Sprintf("lifetime %dd exceeds the 47-day target", detailInt(f.Detail, "lifetime_days"))
	case x509eval.ExpiresSoon:
		return fmt.Sprintf("expires in %d days", detailInt(f.Detail, "days_left"))
	case x509eval.ExpiredServed:
		d := detailInt(f.Detail, "days_left")
		if d < 0 {
			d = -d
		}
		return fmt.Sprintf("expired %d days ago but is still served", d)
	case x509eval.HostnameMismatch:
		return "served certificate does not match the hostname"
	case x509eval.UntrustedChain:
		return "chain does not anchor in a public root (" + fmt.Sprint(f.Detail["reason"]) + ")"
	case x509eval.PrivateTrust:
		return "chain anchors in a server-provided root (private CA)"
	default:
		return f.Type
	}
}

func sortCertViews(vs []CertView) {
	sort.SliceStable(vs, func(i, j int) bool {
		if ri, rj := severityRank[vs[i].Severity], severityRank[vs[j].Severity]; ri != rj {
			return ri > rj
		}
		return vs[i].NotAfter.Before(vs[j].NotAfter)
	})
}

func matchesQuery(v CertView, q string) bool {
	if q == "" {
		return true
	}
	q = strings.ToLower(q)
	hay := strings.ToLower(strings.Join([]string{
		v.Fingerprint, v.Subject, v.Issuer, strings.Join(v.SANs, " "),
	}, " "))
	return strings.Contains(hay, q)
}
