// Package report renders immutable evidence files for a completed scan.
package report

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/amit/47certificates/internal/phase"
	"github.com/amit/47certificates/internal/store"
	"github.com/amit/47certificates/internal/x509eval"
)

const Version = "dev"

// Notice is the sentence every generated artefact carries. It states the
// scope of the analysis so a reader cannot mistake the report for a private
// PKI inventory.
const Notice = "publicly-trusted certificates only; private-CA observations are excluded."

// Kind names the four report types.
type Kind string

const (
	Executive Kind = "executive"
	Worklist  Kind = "worklist"
	Inventory Kind = "inventory"
	Domain    Kind = "domain"
)

var validKinds = map[Kind]bool{Executive: true, Worklist: true, Inventory: true, Domain: true}

// ValidKind reports whether kind is a report kind.
func ValidKind(k Kind) bool { return validKinds[k] }

// ErrScanNotDone is returned when the scan is not in status done.
var ErrScanNotDone = fmt.Errorf("report: scan is not done")

// Artifacts are the three immutable outputs plus the snapshot the delta of a
// later report is computed against.
type Artifacts struct {
	HTML     []byte
	CSV      []byte
	JSON     []byte
	Snapshot []store.SnapshotRow
}

// Delta compares against the most recent earlier report of the same kind.
type Delta struct {
	New              int      `json:"new"`
	Retired          int      `json:"retired"`
	Changed          []string `json:"lifetime_changed,omitempty"`
	NewViolations    int      `json:"new_violations,omitempty"`
	ClosedViolations int      `json:"closed_violations,omitempty"`
	Sentence         string   `json:"sentence"`
	BaseScan         int64    `json:"base_scan_id"` // 0 when there is nothing to compare against
	BaseReport       int64    `json:"base_report_id"`
}

// reportEndpoint is one endpoint that served a certificate.
type reportEndpoint struct {
	Host          string
	Port          int
	IP            string
	Trust         string
	ChainValid    bool
	HostnameValid bool
	TLSVersion    uint16
	Cipher        uint16
}

// reportObs is one certificate. A certificate serving fifty names is still
// one certificate and one renewal, so the row is per certificate and the
// endpoints are listed on it.
type reportObs struct {
	Fingerprint   string
	ShortFP       string
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
	Findings      []x509eval.Finding
	Bucket        string
	Severity      string
	Endpoints     []reportEndpoint
}

type reportView struct {
	ReportID    int64
	ScanID      int64
	ScanTime    time.Time
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
	PhaseGroups []phaseGroup
	Longest     []reportObs
	Expiring    []reportObs
	Notice      string
}

type phaseGroup struct {
	Name      string
	Count     int
	Exceeding int
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

	// Group the observations by certificate. One certificate is one renewal
	// however many endpoints serve it.
	type grouped struct {
		obs       reportObs
		endpoints []reportEndpoint
		seen      map[string]bool
	}
	groups := map[string]*grouped{}
	order := []string{}
	for _, r := range rows {
		g, ok := groups[r.Fingerprint]
		if !ok {
			c, found := byFP[r.Fingerprint]
			if !found {
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
			g = &grouped{
				obs: reportObs{
					Fingerprint:  r.Fingerprint,
					ShortFP:      short(r.Fingerprint),
					Subject:      c.Subject,
					Issuer:       c.Issuer,
					NotBefore:    c.NotBefore,
					NotAfter:     c.NotAfter,
					LifetimeDays: c.LifetimeDays,
					KeyAlg:       c.KeyAlg,
					KeyBits:      c.KeyBits,
					SigAlg:       c.SigAlg,
					SANs:         c.SANs,
				},
				seen: map[string]bool{},
			}
			groups[r.Fingerprint] = g
			order = append(order, r.Fingerprint)
		}
		g.endpoints = append(g.endpoints, reportEndpoint{
			Host:          r.Host,
			Port:          r.Port,
			IP:            r.IP,
			Trust:         r.Trust,
			ChainValid:    r.ChainValid,
			HostnameValid: r.HostnameValid,
			TLSVersion:    r.TLSVersion,
			Cipher:        r.Cipher,
		})
	}

	var public, private []reportObs
	for _, fp := range order {
		g := groups[fp]
		// Merge the per-endpoint verdicts into one certificate-level verdict.
		// A certificate counts as publicly trusted when at least one endpoint
		// chains to a public root; it is compliant when every endpoint agrees
		// on the hostname.
		trust := ""
		chainValid := false
		hostnameValid := true
		merged := map[string]x509eval.Finding{}
		var mergeOrder []string
		for _, ep := range g.endpoints {
			if trust == "" || ep.Trust == "public" {
				trust = ep.Trust
			}
			if ep.ChainValid {
				chainValid = true
			}
			if !ep.HostnameValid {
				hostnameValid = false
			}
			cert := x509eval.Cert{
				Fingerprint:  fp,
				NotBefore:    g.obs.NotBefore,
				NotAfter:     g.obs.NotAfter,
				LifetimeDays: g.obs.LifetimeDays,
			}
			v := x509eval.Verdict{
				Trust:         ep.Trust,
				ChainValid:    ep.ChainValid,
				HostnameValid: ep.HostnameValid,
			}
			for _, f := range x509eval.Findings(cert, v, now) {
				if _, dup := merged[f.Type]; dup {
					continue
				}
				merged[f.Type] = f
				mergeOrder = append(mergeOrder, f.Type)
			}
		}
		findings := make([]x509eval.Finding, 0, len(mergeOrder))
		for _, t := range mergeOrder {
			findings = append(findings, merged[t])
		}

		g.obs.Trust = trust
		g.obs.ChainValid = chainValid
		g.obs.HostnameValid = hostnameValid
		g.obs.Findings = findings
		g.obs.Bucket = x509eval.Bucket(findings)
		g.obs.Severity = maxSeverity(findings, now)
		g.obs.Endpoints = g.endpoints

		if trust == "public" {
			public = append(public, g.obs)
		} else {
			private = append(private, g.obs)
		}
	}

	if kind == Domain {
		if domain == "" {
			return Artifacts{}, fmt.Errorf("report: domain report requires a domain")
		}
		public = filterDomain(public, domain)
		private = filterDomain(private, domain)
	}

	// Counts are per certificate: a certificate served by ten endpoints is
	// counted once.
	counts := map[string]int{}
	for _, o := range public {
		counts[o.Bucket]++
	}

	display := public
	if kind == Worklist {
		display = onlyAboveTarget(public)
	}
	sortRows(display)

	scopeString, err := scopeString(ctx, st)
	if err != nil {
		return Artifacts{}, err
	}

	snapshot := snapshotOf(public)
	delta, err := computeDelta(ctx, st, reportID, kind, snapshot)
	if err != nil {
		return Artifacts{}, err
	}

	view := reportView{
		ReportID:    reportID,
		ScanID:      scanID,
		ScanTime:    sc.StartedAt,
		Kind:        kind,
		Domain:      domain,
		GeneratedAt: now,
		Scope:       scopeString,
		Version:     Version,
		Phase:       phase.For(now),
		Public:      display,
		Private:     private,
		Counts:      counts,
		Total:       len(public),
		PhaseGroups: phaseGroupsOf(public),
		Longest:     longestOf(public, 10),
		Expiring:    expiringWithin(public, now, 30),
		Delta:       delta,
		Notice:      Notice,
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
	return Artifacts{HTML: html, CSV: csv, JSON: jsonBytes, Snapshot: snapshot}, nil
}

// snapshotOf reduces the public certificates to the rows a later report
// diffs against.
func snapshotOf(in []reportObs) []store.SnapshotRow {
	out := make([]store.SnapshotRow, 0, len(in))
	for _, o := range in {
		out = append(out, store.SnapshotRow{
			Fingerprint:  o.Fingerprint,
			LifetimeDays: o.LifetimeDays,
			Violation:    o.Bucket == "violation",
		})
	}
	return out
}

func phaseGroupsOf(in []reportObs) []phaseGroup {
	order := []string{"P0", "P1", "P2", "P3"}
	groups := map[string]*phaseGroup{}
	for _, name := range order {
		groups[name] = &phaseGroup{Name: name}
	}
	for _, o := range in {
		p := phase.For(o.NotBefore)
		g := groups[p.Name]
		g.Count++
		if o.LifetimeDays > p.MaxLifetimeDays {
			g.Exceeding++
		}
	}
	out := make([]phaseGroup, 0, len(order))
	for _, name := range order {
		out = append(out, *groups[name])
	}
	return out
}

func longestOf(in []reportObs, n int) []reportObs {
	out := append([]reportObs{}, in...)
	sort.Slice(out, func(i, j int) bool { return out[i].LifetimeDays > out[j].LifetimeDays })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func expiringWithin(in []reportObs, now time.Time, days int) []reportObs {
	var out []reportObs
	for _, o := range in {
		if o.NotAfter.Sub(now) <= time.Duration(days)*24*time.Hour {
			out = append(out, o)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NotAfter.Before(out[j].NotAfter) })
	return out
}

// filterDomain keeps the certificates that serve the domain, and narrows
// their endpoint list to the domain.
func filterDomain(in []reportObs, domain string) []reportObs {
	var out []reportObs
	for _, o := range in {
		var kept []reportEndpoint
		for _, ep := range o.Endpoints {
			if ep.Host == domain || strings.HasSuffix(ep.Host, "."+domain) {
				kept = append(kept, ep)
			}
		}
		if len(kept) == 0 {
			continue
		}
		o.Endpoints = kept
		out = append(out, o)
	}
	return out
}

// onlyAboveTarget keeps certificates above the 47-day target — the worklist
// spec. Compliant certificates never appear.
func onlyAboveTarget(in []reportObs) []reportObs {
	var out []reportObs
	for _, o := range in {
		if o.LifetimeDays > 47 {
			out = append(out, o)
		}
	}
	return out
}

// sortRows orders findings by severity, then lifetime, then host — the order
// the worklist spec asks for.
func sortRows(in []reportObs) {
	order := map[string]int{"ok": 0, "info": 1, "medium": 2, "high": 3, "critical": 4}
	sort.Slice(in, func(i, j int) bool {
		if a, b := order[in[i].Severity], order[in[j].Severity]; a != b {
			return a > b
		}
		if in[i].LifetimeDays != in[j].LifetimeDays {
			return in[i].LifetimeDays > in[j].LifetimeDays
		}
		return in[i].Fingerprint < in[j].Fingerprint
	})
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

// computeDelta compares this report's certificate set against the previous
// report of the same kind. The baseline is the snapshot stored with that
// report, so the delta survives retention pruning the observations.
func computeDelta(ctx context.Context, st *store.Store, reportID int64, kind Kind, current []store.SnapshotRow) (Delta, error) {
	prev, err := st.LatestDoneReportOfKind(ctx, string(kind), reportID)
	if err != nil {
		return Delta{}, err
	}
	if prev == nil {
		return Delta{Sentence: "no baseline", BaseScan: 0}, nil
	}

	before, err := st.ReportSnapshot(ctx, prev.ID)
	if err != nil {
		return Delta{}, err
	}
	if len(before) == 0 {
		// The previous report predates snapshots. Fall back to the
		// observations of the scan it covered.
		rows, err := st.ScanObservationRows(ctx, prev.ScanID)
		if err != nil {
			return Delta{}, err
		}
		before = snapshotFromRows(rows)
	}

	cur := map[string]store.SnapshotRow{}
	for _, r := range current {
		cur[r.Fingerprint] = r
	}
	old := map[string]store.SnapshotRow{}
	for _, r := range before {
		old[r.Fingerprint] = r
	}

	d := Delta{BaseScan: prev.ScanID, BaseReport: prev.ID}
	for fp, r := range cur {
		oldRow, ok := old[fp]
		if !ok {
			d.New++
			continue
		}
		if oldRow.LifetimeDays != r.LifetimeDays {
			d.Changed = append(d.Changed, fp)
		}
		if r.Violation && !oldRow.Violation {
			d.NewViolations++
		}
		if !r.Violation && oldRow.Violation {
			d.ClosedViolations++
		}
	}
	for fp := range old {
		if _, ok := cur[fp]; !ok {
			d.Retired++
		}
	}
	sort.Strings(d.Changed)

	d.Sentence = fmt.Sprintf("%d new certificate%s, %d retired", d.New, plural(d.New), d.Retired)
	if len(d.Changed) > 0 {
		d.Sentence += fmt.Sprintf(", %d lifetime change%s", len(d.Changed), plural(len(d.Changed)))
	}
	if d.NewViolations > 0 {
		d.Sentence += fmt.Sprintf(", %d new violation%s", d.NewViolations, plural(d.NewViolations))
	}
	if d.ClosedViolations > 0 {
		d.Sentence += fmt.Sprintf(", %d closed violation%s", d.ClosedViolations, plural(d.ClosedViolations))
	}
	return d, nil
}

// snapshotFromRows derives a snapshot from raw observation rows. It is the
// fallback for reports generated before snapshots existed.
func snapshotFromRows(rows []store.ObservationRow) []store.SnapshotRow {
	byFP := map[string]store.SnapshotRow{}
	var order []string
	for _, r := range rows {
		if r.Trust != "public" {
			continue
		}
		row, ok := byFP[r.Fingerprint]
		if !ok {
			order = append(order, r.Fingerprint)
			row = store.SnapshotRow{Fingerprint: r.Fingerprint, LifetimeDays: r.LifetimeDays}
		}
		cert := x509eval.Cert{
			Fingerprint:  r.Fingerprint,
			NotBefore:    r.NotBefore,
			NotAfter:     r.NotAfter,
			LifetimeDays: r.LifetimeDays,
		}
		v := x509eval.Verdict{Trust: r.Trust, ChainValid: r.ChainValid, HostnameValid: r.HostnameValid}
		if x509eval.Bucket(x509eval.Findings(cert, v, time.Now())) == "violation" {
			row.Violation = true
		}
		byFP[r.Fingerprint] = row
	}
	out := make([]store.SnapshotRow, 0, len(order))
	for _, fp := range order {
		out = append(out, byFP[fp])
	}
	return out
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
