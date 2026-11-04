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
	ID            int64          `json:"id"`
	Type          string         `json:"type"`
	Status        string         `json:"status"`
	SnoozeUntil   *time.Time     `json:"snooze_until,omitempty"`
	Detail        map[string]any `json:"detail,omitempty"`
	Severity      string         `json:"severity"`
	Bucket        string         `json:"bucket"`
	Sentence      string         `json:"sentence"`
	EffectiveOpen bool           `json:"effective_open"`
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
	OpenCount    int           `json:"open_count"`
	AckCount     int           `json:"ack_count"`
	SnoozeCount  int           `json:"snooze_count"`
	Endpoints    []string      `json:"endpoints"`
	Trust        string        `json:"trust"`
	ChainValid   bool          `json:"chain_valid"`
	HostnameOK   bool          `json:"hostname_valid"`
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
		DaysLeft:     x509eval.DaysLeft(c.NotAfter, now),
		ID:           c.ID,
	}
	for _, f := range c.Findings {
		v.Findings = append(v.Findings, buildFindingView(f, now, c.NotBefore, c.NotAfter))
	}
	v.Bucket = bucketOfViews(openViews(v.Findings))
	v.Severity = severityOfViews(openViews(v.Findings))
	for _, e := range c.Endpoints {
		v.Endpoints = append(v.Endpoints, fmt.Sprintf("%s:%d", e.Host, e.Port))
		if v.Trust == "" || e.Trust == "public" {
			v.Trust = e.Trust
		}
		if e.ChainValid {
			v.ChainValid = true
		}
		if e.HostnameValid {
			v.HostnameOK = true
		}
	}
	for _, f := range v.Findings {
		switch {
		case f.EffectiveOpen:
			v.OpenCount++
		case f.Status == "ack":
			v.AckCount++
		case f.Status == "snoozed":
			v.SnoozeCount++
		}
	}
	return v
}

func buildFindingView(f store.Finding, now time.Time, notBefore, notAfter time.Time) FindingView {
	detail := map[string]any{}
	if f.Detail != "" {
		_ = json.Unmarshal([]byte(f.Detail), &detail)
	}
	// JSON numbers decode to float64; findings code expects int.
	if d, ok := detail["days_left"].(float64); ok {
		detail["days_left"] = int(d)
	}
	// Severity derives from the certificate dates at read time, not from the
	// persisted scan-time detail.
	if _, ok := detail["days_left"]; ok {
		detail["days_left"] = x509eval.DaysLeft(notAfter, now)
	}
	xf := x509eval.Finding{Type: f.Type, Detail: detail}
	return FindingView{
		ID:            f.ID,
		Type:          f.Type,
		Status:        f.Status,
		SnoozeUntil:   f.SnoozeUntil,
		Detail:        detail,
		Severity:      x509eval.Severity(xf, now),
		Bucket:        x509eval.Bucket([]x509eval.Finding{xf}),
		Sentence:      describe(xf),
		EffectiveOpen: effectiveOpen(f.Status, f.SnoozeUntil, now),
	}
}

// effectiveOpen reports whether a finding should count as open at now. A
// snoozed finding comes back automatically when its snooze expires.
func effectiveOpen(status string, until *time.Time, now time.Time) bool {
	if status == "open" {
		return true
	}
	if status == "snoozed" && until != nil && !until.After(now) {
		return true
	}
	return false
}

// openViews returns only findings that count as open at read time.
func openViews(fs []FindingView) []FindingView {
	var out []FindingView
	for _, f := range fs {
		if f.EffectiveOpen {
			out = append(out, f)
		}
	}
	return out
}

// matchStatus reports whether a certificate view matches a ?status= filter.
//
// "open" means the certificate is not fully triaged: it still has a finding
// nobody has acknowledged, or it has no findings at all. A compliant
// certificate is not hidden for having nothing wrong with it; only a
// certificate whose findings have all been acknowledged or snoozed drops out
// of the default view.
func matchStatus(v CertView, status string) bool {
	switch status {
	case "", "open":
		return v.OpenCount > 0 || len(v.Findings) == 0
	case "acked":
		return v.AckCount > 0
	case "snoozed":
		return v.SnoozeCount > 0
	case "all":
		return true
	default:
		return v.OpenCount > 0 || len(v.Findings) == 0
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
