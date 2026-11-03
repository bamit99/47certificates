// Package report renders immutable evidence files for a completed scan.
package report

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/amit/47certificates/internal/phase"
	"github.com/amit/47certificates/internal/store"
	"github.com/amit/47certificates/internal/x509eval"
)

const Version = "dev"

// Kind names the four report types.
type Kind string

const (
	Executive Kind = "executive"
	Worklist  Kind = "worklist"
	Inventory Kind = "inventory"
	Domain    Kind = "domain"
)

var validKinds = map[Kind]bool{Executive: true, Worklist: true, Inventory: true, Domain: true}

// ErrScanNotDone is returned when the scan is not in status done.
var ErrScanNotDone = fmt.Errorf("report: scan is not done")

// Artifacts are the three immutable outputs.
type Artifacts struct {
	HTML []byte
	CSV  []byte
	JSON []byte
}

// Delta compares against the most recent earlier report of the same kind.
type Delta struct {
	New      int      `json:"new"`
	Retired  int      `json:"retired"`
	Changed  []string `json:"lifetime_changed,omitempty"`
	Sentence string   `json:"sentence"`
	BaseScan int64    `json:"base_scan_id"` // 0 when there is nothing to compare against
}

type reportObs struct {
	Fingerprint   string
	ShortFP       string
	Host          string
	Port          int
	IP            string
	Subject       string
	Issuer        string
	NotBefore     time.Time
	NotAfter      time.Time
	LifetimeDays  int
	KeyAlg        string
	KeyBits       int
	SigAlg        string
	SANs          []string
	Trust         string
	ChainValid    bool
	HostnameValid bool
	TLSVersion    uint16
	Cipher        uint16
	Findings      []x509eval.Finding
	Bucket        string
	Severity      string
}

type reportView struct {
	ReportID    int64
	ScanID      int64
	Kind        Kind
	Domain      string
	GeneratedAt time.Time
	Scope       string
	Version     string
	Phase       phase.Rules
	Delta       Delta
	Public      []reportObs
	Private     []reportObs
	Counts      map[string]int
	Total       int
}

// Generate renders one report for a done scan. reportID is embedded into the
// artifacts; insert the report row first and pass its id.
func Generate(ctx context.Context, st *store.Store, reportID, scanID int64, kind Kind, domain string, now time.Time) (Artifacts, error) {
	if !validKinds[kind] {
		return Artifacts{}, fmt.Errorf("report: unknown kind %q", kind)
	}
	sc, err := st.ScanByID(ctx, scanID)
	if err != nil {
		return Artifacts{}, fmt.Errorf("report: load scan: %w", err)
	}
	if sc.Status != "done" {
		return Artifacts{}, ErrScanNotDone
	}

	rows, err := st.ScanObservationRows(ctx, scanID)
	if err != nil {
		return Artifacts{}, err
	}
	certSummaries, err := st.ListCerts(ctx)
	if err != nil {
		return Artifacts{}, err
	}
	byFP := map[string]store.CertSummary{}
	for _, c := range certSummaries {
		byFP[c.Fingerprint] = c
	}

	var public, private []reportObs
	for _, r := range rows {
		c, ok := byFP[r.Fingerprint]
		if !ok {
			c = store.CertSummary{
				Fingerprint:  r.Fingerprint,
				Subject:      r.Subject,
				Issuer:       r.Issuer,
				NotBefore:    r.NotBefore,
				NotAfter:     r.NotAfter,
				LifetimeDays: r.LifetimeDays,
				KeyAlg:       r.KeyAlg,
				KeyBits:      r.KeyBits,
				SigAlg:       r.SigAlg,
			}
		}
		cert := x509eval.Cert{
			Fingerprint:  c.Fingerprint,
			NotBefore:    c.NotBefore,
			NotAfter:     c.NotAfter,
			LifetimeDays: c.LifetimeDays,
		}
		v := x509eval.Verdict{
			Trust:         r.Trust,
			ChainValid:    r.ChainValid,
			HostnameValid: r.HostnameValid,
		}
		fm := x509eval.Findings(cert, v, now)
		obs := reportObs{
			Fingerprint:   r.Fingerprint,
			ShortFP:       short(r.Fingerprint),
			Host:          r.Host,
			Port:          r.Port,
			IP:            r.IP,
			Subject:       c.Subject,
			Issuer:        c.Issuer,
			NotBefore:     c.NotBefore,
			NotAfter:      c.NotAfter,
			LifetimeDays:  c.LifetimeDays,
			KeyAlg:        c.KeyAlg,
			KeyBits:       c.KeyBits,
			SigAlg:        c.SigAlg,
			SANs:          c.SANs,
			Trust:         r.Trust,
			ChainValid:    r.ChainValid,
			HostnameValid: r.HostnameValid,
			TLSVersion:    r.TLSVersion,
			Cipher:        r.Cipher,
			Findings:      fm,
			Bucket:        x509eval.Bucket(fm),
			Severity:      maxSeverity(fm, now),
		}
		if r.Trust == "public" {
			public = append(public, obs)
		} else {
			private = append(private, obs)
		}
	}

	if kind == Domain {
		if domain == "" {
			return Artifacts{}, fmt.Errorf("report: domain report requires a domain")
		}
		public = filterDomain(public, domain)
		private = filterDomain(private, domain)
	}
	if kind == Worklist {
		public = onlyFlagged(public)
	}

	counts := map[string]int{}
	for _, o := range public {
		counts[o.Bucket]++
	}

	scopeString, err := scopeString(ctx, st)
	if err != nil {
		return Artifacts{}, err
	}

	delta, err := computeDelta(ctx, st, scanID, kind)
	if err != nil {
		return Artifacts{}, err
	}

	view := reportView{
		ReportID:    reportID,
		ScanID:      scanID,
		Kind:        kind,
		Domain:      domain,
		GeneratedAt: now,
		Scope:       scopeString,
		Version:     Version,
		Phase:       phase.For(now),
		Public:      public,
		Private:     private,
		Counts:      counts,
		Total:       len(public),
		Delta:       delta,
	}

	html, err := renderHTML(kind, view)
	if err != nil {
		return Artifacts{}, err
	}
	csv := renderCSV(view)
	jsonBytes, err := renderJSON(view)
	if err != nil {
		return Artifacts{}, err
	}
	return Artifacts{HTML: html, CSV: csv, JSON: jsonBytes}, nil
}

func filterDomain(in []reportObs, domain string) []reportObs {
	var out []reportObs
	for _, o := range in {
		if o.Host == domain || strings.HasSuffix(o.Host, "."+domain) {
			out = append(out, o)
		}
	}
	return out
}

func onlyFlagged(in []reportObs) []reportObs {
	var out []reportObs
	for _, o := range in {
		if len(o.Findings) > 0 {
			out = append(out, o)
		}
	}
	return out
}

func short(fp string) string {
	if len(fp) <= 16 {
		return fp
	}
	return fp[:16]
}

func maxSeverity(fs []x509eval.Finding, now time.Time) string {
	best := "ok"
	order := map[string]int{"ok": 0, "info": 1, "medium": 3, "high": 4, "critical": 5}
	for _, f := range fs {
		if s := x509eval.Severity(f, now); order[s] > order[best] {
			best = s
		}
	}
	return best
}

func scopeString(ctx context.Context, st *store.Store) (string, error) {
	entries, err := st.ListScope(ctx)
	if err != nil {
		return "", err
	}
	var in, ex, seeds []string
	for _, e := range entries {
		switch e.Kind {
		case "include":
			in = append(in, e.Value)
		case "exclude":
			ex = append(ex, e.Value)
		case "seed":
			seeds = append(seeds, e.Value)
		}
	}
	out := ""
	if len(in) > 0 {
		out += "include: " + strings.Join(in, ", ")
	}
	if len(ex) > 0 {
		out += "; exclude: " + strings.Join(ex, ", ")
	}
	if len(seeds) > 0 {
		out += "; seed: " + strings.Join(seeds, ", ")
	}
	return strings.TrimPrefix(out, "; "), nil
}

// computeDelta compares the observation sets of scanID against the previous
// done scan that had a report of this kind.
func computeDelta(ctx context.Context, st *store.Store, scanID int64, kind Kind) (Delta, error) {
	prev, err := st.LatestDoneReport(ctx, string(kind), scanID)
	if err != nil {
		return Delta{}, err
	}
	if prev == nil {
		return Delta{Sentence: "no baseline", BaseScan: 0}, nil
	}
	current, err := st.ScanObservationRows(ctx, scanID)
	if err != nil {
		return Delta{}, err
	}
	before, err := st.ScanObservationRows(ctx, prev.ScanID)
	if err != nil {
		return Delta{}, err
	}
	cur := map[string]int{}
	for _, r := range current {
		cur[r.Fingerprint] = r.LifetimeDays
	}
	old := map[string]int{}
	for _, r := range before {
		old[r.Fingerprint] = r.LifetimeDays
	}
	for fp, lt := range old {
		if newLt, ok := cur[fp]; ok && newLt != lt {
			_ = newLt
			_ = fp
		}
	}
	newCerts := countInNotIn(cur, old)
	retiredCerts := countInNotIn(old, cur)
	d := Delta{BaseScan: prev.ScanID, New: newCerts, Retired: retiredCerts}
	for fp, lt := range cur {
		if oldLt, ok := old[fp]; ok && oldLt != lt {
			d.Changed = append(d.Changed, fp)
		}
	}
	d.Sentence = fmt.Sprintf("%d new certificate%s, %d retired", newCerts, plural(newCerts), retiredCerts)
	if len(d.Changed) > 0 {
		d.Sentence += fmt.Sprintf(", %d lifetime change%s", len(d.Changed), plural(len(d.Changed)))
	}
	return d, nil
}

func countInNotIn(a, b map[string]int) int {
	n := 0
	for k := range a {
		if _, ok := b[k]; !ok {
			n++
		}
	}
	return n
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
