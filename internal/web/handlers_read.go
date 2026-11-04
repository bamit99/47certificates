package web

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bamit99/47certificates/internal/phase"
	"github.com/bamit99/47certificates/internal/scan"
	"github.com/bamit99/47certificates/internal/store"
)

var funcMap = map[string]any{
	"sev":    func(vs []FindingView) string { return severityOfViews(vs) },
	"bucket": func(vs []FindingView) string { return bucketOfViews(vs) },
	"days":   func(t time.Time) int { return int(time.Until(t) / (24 * time.Hour)) },
	"when":   func(t time.Time) string { return t.Format("2006-01-02") },
	"json":   func(v any) string { b, _ := json.MarshalIndent(v, "", "  "); return string(b) },
}

type pageData struct {
	Title string
	User  store.User
	CSRF  string
	// Domain is the domain the page is about.
	Domain string
	// Domains are the domains the picker offers.
	Domains []store.Domain
	// DomainSearch is the text in the domain search box.
	DomainSearch string
	// DomainAction is the path the domain picker submits to.
	DomainAction string
}

func (s *Server) base(r *http.Request, title string) pageData {
	u, _ := UserFrom(r.Context())
	pd := pageData{Title: title, User: u, CSRF: CSRFFrom(r.Context())}
	dom, err := s.domainOf(r)
	if err == nil {
		pd.Domain = dom.Name
	}
	if domains, err := s.domainsForPicker(r.Context(), r.URL.Query().Get("q")); err == nil {
		pd.Domains = domains
	}
	pd.DomainSearch = r.URL.Query().Get("q")
	pd.DomainAction = r.URL.Path
	return pd
}

func (s *Server) render(w http.ResponseWriter, page string, data any) {
	s.renderStatus(w, page, http.StatusOK, data)
}

func (s *Server) renderStatus(w http.ResponseWriter, page string, status int, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t, ok := viewTemplates[page]
	if !ok {
		http.Error(w, "unknown page: "+page, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(status)
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, "template: "+err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) loadCertViews(ctx context.Context, domainID int64) ([]CertView, error) {
	cs, err := s.deps.Store.ListCerts(ctx, domainID)
	if err != nil {
		return nil, err
	}
	out := make([]CertView, 0, len(cs))
	for _, c := range cs {
		out = append(out, buildCertView(c, s.now()))
	}
	return out, nil
}

type bucketRow struct {
	Key   string
	Label string
	Count int
}

// phaseRow counts the certificates issued in one CA/B phase and how many of
// them exceed that phase's maximum lifetime.
type phaseRow struct {
	Name      string
	Count     int
	Exceeding int
}

func countBuckets(vs []CertView) map[string]int {
	m := map[string]int{}
	for _, v := range vs {
		m[v.Bucket]++
	}
	return m
}

// countPhases buckets the certificates by the phase in force when they were
// issued, and counts those whose lifetime exceeded that phase's maximum.
func countPhases(vs []CertView) []phaseRow {
	order := []string{"P0", "P1", "P2", "P3"}
	rows := map[string]*phaseRow{}
	for _, name := range order {
		rows[name] = &phaseRow{Name: name}
	}
	for _, v := range vs {
		p := phase.For(v.NotBefore)
		r, ok := rows[p.Name]
		if !ok {
			r = &phaseRow{Name: p.Name}
			rows[p.Name] = r
		}
		r.Count++
		if v.LifetimeDays > p.MaxLifetimeDays {
			r.Exceeding++
		}
	}
	out := make([]phaseRow, 0, len(order))
	for _, name := range order {
		out = append(out, *rows[name])
	}
	return out
}

func activeCerts(vs []CertView) []CertView {
	out := make([]CertView, 0, len(vs))
	for _, v := range vs {
		if !v.Retired {
			out = append(out, v)
		}
	}
	return out
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	dom, err := s.domainOf(r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.setDomainCookie(w, dom)
	views, err := s.loadCertViews(ctx, dom.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	active := activeCerts(views)
	counts := countBuckets(active)
	rows := make([]bucketRow, 0, len(bucketLabels))
	for _, b := range bucketLabels {
		rows = append(rows, bucketRow{Key: b.Key, Label: b.Label, Count: counts[b.Key]})
	}
	sortCertViews(active)
	expiring := make([]CertView, 0, 10)
	for _, v := range active {
		if v.DaysLeft <= 60 && v.OpenCount > 0 {
			expiring = append(expiring, v)
		}
		if len(expiring) == 10 {
			break
		}
	}
	recent, _ := s.deps.Store.ListScans(ctx, dom.ID, 6)
	data := struct {
		pageData
		Total          int
		BucketRows     []bucketRow
		PhaseRows      []phaseRow
		Expiring       []CertView
		RecentScans    []store.Scan
		CurrentPhase   phase.Rules
		BucketLegend   []legendItem
		SeverityLegend []legendItem
		FindingLegend  []legendItem
	}{
		pageData:       s.base(r, "Dashboard"),
		Total:          len(active),
		BucketRows:     rows,
		PhaseRows:      countPhases(active),
		Expiring:       expiring,
		RecentScans:    recent,
		CurrentPhase:   phase.For(s.now()),
		BucketLegend:   bucketLegend,
		SeverityLegend: severityLegend,
		FindingLegend:  findingLegend,
	}
	s.render(w, "dashboard", data)
}

const pageSize = 100

func (s *Server) handleCerts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query().Get("q")
	bucket := r.URL.Query().Get("bucket")
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "open"
	}
	retired := r.URL.Query().Get("retired") == "1"
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	dom, err := s.domainOf(r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.setDomainCookie(w, dom)
	u, _ := UserFrom(ctx)
	views, err := s.loadCertViews(ctx, dom.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	filtered := make([]CertView, 0, len(views))
	for _, v := range views {
		if !retired && v.Retired {
			continue
		}
		if !matchStatus(v, status) {
			continue
		}
		if bucket != "" && v.Bucket != bucket {
			continue
		}
		if !matchesQuery(v, q) {
			continue
		}
		filtered = append(filtered, v)
	}
	sortCertViews(filtered)
	total := len(filtered)
	pages := (total + pageSize - 1) / pageSize
	if pages < 1 {
		pages = 1
	}
	if page > pages {
		page = pages
	}
	start := (page - 1) * pageSize
	end := start + pageSize
	if end > total {
		end = total
	}
	var pageCerts []CertView
	if start < end {
		pageCerts = filtered[start:end]
	}
	// The columns the operator chose.
	chosen, err := s.deps.Store.GetCertColumns(ctx, u.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	columns := columnsFor(chosen)
	data := struct {
		pageData
		Certs         []CertView
		Bucket        string
		Query         string
		Status        string
		Retired       bool
		Page          int
		Pages         int
		PrevPage      int
		NextPage      int
		BucketOptions []struct {
			Key   string
			Label string
		}
		Columns []store.CertColumn
	}{
		pageData:      s.base(r, "Certificates"),
		Certs:         pageCerts,
		Bucket:        bucket,
		Query:         q,
		Status:        status,
		Retired:       retired,
		Page:          page,
		Pages:         pages,
		PrevPage:      page - 1,
		NextPage:      page + 1,
		BucketOptions: bucketLabels,
		Columns:       columns,
	}
	if page == 1 {
		data.PrevPage = 0
	}
	if page == pages {
		data.NextPage = 0
	}
	s.render(w, "certs", data)
}

func (s *Server) handleCertDetail(w http.ResponseWriter, r *http.Request) {
	fp := r.PathValue("fp")
	if fp == "" {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	dom, err := s.domainOf(r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.setDomainCookie(w, dom)
	c, err := s.deps.Store.CertByFingerprint(ctx, dom.ID, fp)
	if err != nil {
		if err == store.ErrNotFound {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	v := buildCertView(c, s.now())
	endpoints, err := s.deps.Store.CertEndpoints(ctx, dom.ID, c.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data := struct {
		pageData
		Cert      CertView
		Endpoints []store.CertEndpoint
	}{
		pageData:  s.base(r, "Certificate "+v.ShortFP),
		Cert:      v,
		Endpoints: endpoints,
	}
	s.render(w, "cert", data)
}

func (s *Server) handleCertPEM(w http.ResponseWriter, r *http.Request) {
	fp := r.PathValue("fp")
	raw, err := s.deps.Store.CertPEM(r.Context(), fp)
	if err != nil {
		if err == store.ErrNotFound {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var buf strings.Builder
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: raw}); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="`+shortFP(fp)+".pem\"")
	_, _ = w.Write([]byte(buf.String()))
}

func (s *Server) handleDomains(w http.ResponseWriter, r *http.Request) {
	added := r.URL.Query().Get("added")
	s.renderDomains(w, r, http.StatusOK, added, "", "")
}

// renderDomains draws the domain list and the scope editor. added is the
// domain the previous POST created; exists is a domain that was already in
// the scope; errMsg is a rejected input.
func (s *Server) renderDomains(w http.ResponseWriter, r *http.Request, status int, added, exists, errMsg string) {
	ctx := r.Context()
	entries, err := s.deps.Store.ListScope(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	domains, err := s.domainsForPicker(ctx, r.URL.Query().Get("q"))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data := struct {
		pageData
		Entries []store.ScopeEntry
		Domains []store.Domain
		Added   string
		Exists  string
		Error   string
	}{
		pageData: s.base(r, "Domains & Scope"),
		Entries:  entries,
		Domains:  domains,
		Added:    added,
		Exists:   exists,
		Error:    errMsg,
	}
	s.renderStatus(w, "domains", status, data)
}

// handleDomainDetail shows one domain: its counts, its certificates and the
// endpoints it serves.
func (s *Server) handleDomainDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("d")
	dom, err := s.deps.Store.DomainByName(ctx, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.setDomainCookie(w, domainRequest{ID: dom.ID, Name: dom.Name})
	views, err := s.loadCertViews(ctx, dom.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	live := activeCerts(views)
	hosts, err := s.deps.Store.DomainHosts(ctx, dom.Name)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	scans, err := s.deps.Store.ListScans(ctx, dom.ID, 10)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data := struct {
		pageData
		Domain  store.Domain
		Certs   []CertView
		Hosts   []string
		Scans   []store.Scan
		Counts  map[string]int
		Total   int
		Retired int
		Open    int
	}{
		pageData: s.base(r, "Domain "+dom.Name),
		Domain:   dom,
		Certs:    live,
		Hosts:    hosts,
		Scans:    scans,
		Counts:   countBuckets(live),
		Total:    len(live),
		Retired:  dom.Retired,
		Open:     dom.Open,
	}
	s.render(w, "domain", data)
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	dom, err := s.domainOf(r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.setDomainCookie(w, dom)
	scans, err := s.deps.Store.ListScans(r.Context(), dom.ID, 100)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data := struct {
		pageData
		Scans []store.Scan
	}{
		pageData: s.base(r, "Scans"),
		Scans:    scans,
	}
	s.render(w, "scans", data)
}

func (s *Server) handleScanDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	sc, err := s.deps.Store.ScanByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var stats map[string]any
	if sc.Stats != "" {
		_ = json.Unmarshal([]byte(sc.Stats), &stats)
	}
	rows, err := s.deps.Store.ScanObservationRows(r.Context(), id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data := struct {
		pageData
		Scan  store.Scan
		Stats map[string]any
		Rows  []store.ObservationRow
	}{
		pageData: s.base(r, fmt.Sprintf("Scan #%d", sc.ID)),
		Scan:     sc,
		Stats:    stats,
		Rows:     rows,
	}
	s.render(w, "scan", data)
}

func (s *Server) handleScanEvents(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ctx := r.Context()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	// The counters of the previous tick, so only the ones that changed are
	// sent.
	prev := map[string]int{}
	prevStage := ""
	prevDetail := ""
	for {
		sc, err := s.deps.Store.ScanByID(ctx, id)
		if err != nil {
			fmt.Fprintf(w, "event: error\ndata: %q\n\n", err.Error())
			flusher.Flush()
			return
		}
		// The counters are decoded loosely: the document holds strings and
		// lists as well as numbers.
		var stats map[string]any
		if sc.Stats != "" {
			_ = json.Unmarshal([]byte(sc.Stats), &stats)
		}
		count := func(key string) (int, bool) {
			v, ok := stats[key].(float64)
			if !ok {
				return 0, false
			}
			return int(v), true
		}
		send := func(event string, data map[string]any) {
			payload, _ := json.Marshal(data)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, payload)
			flusher.Flush()
		}
		if v, ok := count("hosts"); ok && v != prev["hosts"] {
			send("discovered", map[string]any{"hosts": v})
		}
		if v, ok := count("observed"); ok && v != prev["observed"] {
			endpoints, _ := count("endpoints")
			send("dialed", map[string]any{"observed": v, "endpoints": endpoints})
		}
		if v, ok := count("failed"); ok && v != prev["failed"] {
			send("failed", map[string]any{"failed": v})
		}
		detail, _ := stats["detail"].(string)
		if v, ok := stats["stage"].(string); ok && v != "" && (v != prevStage || detail != prevDetail) {
			send("phase", map[string]any{"stage": v, "detail": detail})
			prevStage = v
			prevDetail = detail
		}
		for _, key := range []string{"hosts", "observed", "failed", "endpoints"} {
			if v, ok := count(key); ok {
				prev[key] = v
			}
		}

		payload, _ := json.Marshal(map[string]any{
			"status": sc.Status,
			"stats":  stats,
			"id":     sc.ID,
		})
		fmt.Fprintf(w, "data: %s\n\n", payload)
		flusher.Flush()
		if sc.Status == "done" || sc.Status == "failed" || sc.Status == "cancelled" {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) handleAPICerts(w http.ResponseWriter, r *http.Request) {
	dom, err := s.domainOf(r)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	views, err := s.loadCertViews(r.Context(), dom.ID)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	active := activeCerts(views)
	sortCertViews(active)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(active)
}

func (s *Server) handleAPIScans(w http.ResponseWriter, r *http.Request) {
	dom, err := s.domainOf(r)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	scans, err := s.deps.Store.ListScans(r.Context(), dom.ID, 100)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(scans)
}

// handleExport writes the current certificate inventory as CSV or JSON, for
// an offline copy.
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format != "csv" && format != "json" {
		http.Error(w, "format must be csv or json", http.StatusBadRequest)
		return
	}
	dom, err := s.domainOf(r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	scanID, err := strconv.ParseInt(r.URL.Query().Get("scan_id"), 10, 64)
	if err != nil {
		// Without a scan, export the newest done scan of the domain.
		scanID, err = s.latestDoneScanOf(r, dom.ID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				http.Error(w, "no completed scan to export", http.StatusNotFound)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	sc, err := s.deps.Store.ScanByID(r.Context(), scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if sc.Status != "done" {
		http.Error(w, "that scan is not complete", http.StatusBadRequest)
		return
	}

	var buf bytes.Buffer
	switch format {
	case "csv":
		if err := scan.ExportCSV(r.Context(), s.deps.Store, scanID, &buf); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	case "json":
		if err := scan.ExportJSON(r.Context(), s.deps.Store, scanID, &buf); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"47c-export-%d.%s\"", scanID, format))
	_, _ = w.Write(buf.Bytes())
}

// latestDoneScanOf returns the newest completed scan of a domain.
func (s *Server) latestDoneScanOf(r *http.Request, domainID int64) (int64, error) {
	scans, err := s.deps.Store.ListScans(r.Context(), domainID, 100)
	if err != nil {
		return 0, err
	}
	for _, sc := range scans {
		if sc.Status == "done" {
			return sc.ID, nil
		}
	}
	return 0, store.ErrNotFound
}

func staticHandler() http.Handler {
	sub, err := fs.Sub(assets, "static")
	if err != nil {
		return http.NotFoundHandler()
	}
	return http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
}
