package web

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/amit/47certificates/internal/phase"
	"github.com/amit/47certificates/internal/store"
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
}

func (s *Server) base(r *http.Request, title string) pageData {
	u, _ := UserFrom(r.Context())
	return pageData{Title: title, User: u, CSRF: CSRFFrom(r.Context())}
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

func (s *Server) loadCertViews(ctx context.Context) ([]CertView, error) {
	cs, err := s.deps.Store.ListCerts(ctx)
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

func countBuckets(vs []CertView) map[string]int {
	m := map[string]int{}
	for _, v := range vs {
		m[v.Bucket]++
	}
	return m
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
	views, err := s.loadCertViews(ctx)
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
	recent, _ := s.deps.Store.ListScans(ctx, 6)
	data := struct {
		pageData
		Total        int
		BucketRows   []bucketRow
		Expiring     []CertView
		RecentScans  []store.Scan
		CurrentPhase phase.Rules
	}{
		pageData:     s.base(r, "Dashboard"),
		Total:        len(active),
		BucketRows:   rows,
		Expiring:     expiring,
		RecentScans:  recent,
		CurrentPhase: phase.For(s.now()),
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

	views, err := s.loadCertViews(ctx)
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
	c, err := s.deps.Store.CertByFingerprint(ctx, fp)
	if err != nil {
		if err == store.ErrNotFound {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	v := buildCertView(c, s.now())
	endpoints, err := s.deps.Store.CertEndpoints(ctx, c.ID)
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
	entries, err := s.deps.Store.ListScope(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data := struct {
		pageData
		Entries []store.ScopeEntry
	}{
		pageData: s.base(r, "Domains & Scope"),
		Entries:  entries,
	}
	s.render(w, "domains", data)
}

func (s *Server) handleDomainDetail(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("d")
	hosts, err := s.deps.Store.DomainHosts(r.Context(), domain)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data := struct {
		pageData
		Domain string
		Hosts  []string
	}{
		pageData: s.base(r, "Domain "+domain),
		Domain:   domain,
		Hosts:    hosts,
	}
	s.render(w, "domain", data)
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	scans, err := s.deps.Store.ListScans(r.Context(), 100)
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
	for {
		sc, err := s.deps.Store.ScanByID(ctx, id)
		if err != nil {
			fmt.Fprintf(w, "event: error\ndata: %q\n\n", err.Error())
			flusher.Flush()
			return
		}
		var stats json.RawMessage
		if sc.Stats != "" {
			stats = json.RawMessage(sc.Stats)
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
	views, err := s.loadCertViews(r.Context())
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
	scans, err := s.deps.Store.ListScans(r.Context(), 100)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(scans)
}

func staticHandler() http.Handler {
	sub, err := fs.Sub(assets, "static")
	if err != nil {
		return http.NotFoundHandler()
	}
	return http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
}
