package web

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/amit/47certificates/internal/report"
	"github.com/amit/47certificates/internal/store"
)

func (s *Server) dataDir() string {
	if s.deps.DataDir != "" {
		return s.deps.DataDir
	}
	if p := s.deps.Store.Path(); p != "" {
		return filepath.Dir(p)
	}
	return "./data"
}

func (s *Server) reportsDir(id int64) string {
	return filepath.Join(s.dataDir(), "reports", strconv.FormatInt(id, 10))
}

func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	dom, err := s.domainOf(r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.setDomainCookie(w, dom)
	reports, err := s.deps.Store.ListReports(ctx, 20)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	scans, err := s.deps.Store.ListScans(ctx, dom.ID, 50)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var done []store.Scan
	for _, sc := range scans {
		if sc.Status == "done" {
			done = append(done, sc)
		}
	}
	data := struct {
		pageData
		Reports []store.Report
		Scans   []store.Scan
		Saved   bool
	}{
		pageData: s.base(r, "Reports"),
		Reports:  reports,
		Scans:    done,
		Saved:    r.URL.Query().Get("saved") == "1",
	}
	s.render(w, "reports", data)
}

func (s *Server) handleReportCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	u, _ := UserFrom(ctx)

	kind := report.Kind(r.PostFormValue("kind"))
	if !report.ValidKind(kind) {
		http.Error(w, "unknown report kind", http.StatusBadRequest)
		return
	}
	scanID, err := strconv.ParseInt(r.PostFormValue("scan_id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid scan_id", http.StatusBadRequest)
		return
	}
	domain := strings.TrimSpace(r.PostFormValue("domain"))
	if kind == report.Domain && domain == "" {
		http.Error(w, "a domain report requires a domain", http.StatusBadRequest)
		return
	}

	rp, genErr := report.GenerateAndStore(ctx, s.deps.Store, filepath.Join(s.dataDir(), "reports"), kind, scanID, domain, &u.ID, s.now())
	if genErr != nil {
		_ = s.deps.Store.Audit(ctx, &u.ID, "report.fail", strconv.FormatInt(scanID, 10),
			[]byte(fmt.Sprintf(`{"error":%q}`, genErr.Error())), clientIP(r))
		// The audit log keeps the detail; the client gets a generic message.
		if errors.Is(genErr, report.ErrScanNotDone) {
			http.Error(w, "that scan is not complete", http.StatusBadRequest)
			return
		}
		http.Error(w, "report generation failed", http.StatusInternalServerError)
		return
	}
	_ = s.deps.Store.Audit(ctx, &u.ID, "report.generate", strconv.FormatInt(rp.ID, 10),
		[]byte(fmt.Sprintf(`{"kind":%q,"scan_id":%d}`, kind, scanID)), clientIP(r))
	http.Redirect(w, r, "/reports/"+strconv.FormatInt(rp.ID, 10), http.StatusSeeOther)
}

func (s *Server) handleReportDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	rp, err := s.deps.Store.ReportByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := struct {
		pageData
		Report  store.Report
		Formats []formatChoice
	}{
		pageData: s.base(r, fmt.Sprintf("Report #%d", id)),
		Report:   rp,
		Formats:  formatChoices(rp.Kind),
	}
	s.render(w, "report", data)
}

// formatChoice is one download format of a report.
type formatChoice struct {
	Key     string
	Label   string
	Default bool
	Last    bool
}

// formatChoices returns the formats a report kind offers, with the one that
// suits it marked as the default.
func formatChoices(kind string) []formatChoice {
	def := report.DefaultFormat(report.Kind(kind))
	all := []struct{ key, label string }{
		{"pdf", "PDF"},
		{"html", "HTML"},
		{"csv", "CSV"},
		{"json", "JSON"},
		{"md", "Markdown"},
	}
	var out []formatChoice
	for i, f := range all {
		out = append(out, formatChoice{
			Key:     f.key,
			Label:   f.label,
			Default: f.key == def,
			Last:    i == len(all)-1,
		})
	}
	return out
}

func (s *Server) handleReportDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	u, _ := UserFrom(ctx)
	if err := s.deps.Store.DeleteReport(ctx, id); err != nil {
		http.NotFound(w, r)
		return
	}
	_ = os.RemoveAll(s.reportsDir(id))
	_ = s.deps.Store.Audit(ctx, &u.ID, "report.delete", strconv.FormatInt(id, 10), nil, clientIP(r))
	http.Redirect(w, r, "/reports", http.StatusSeeOther)
}

func (s *Server) handleReportDownload(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	format := r.URL.Query().Get("format")
	rp, err := s.deps.Store.ReportByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if rp.Status != "done" {
		http.Error(w, "report is not complete", http.StatusConflict)
		return
	}
	switch format {
	case "html", "csv", "json", "md", "pdf":
		var path, contentType string
		switch format {
		case "html":
			path, contentType = rp.HTMLPath, "text/html; charset=utf-8"
		case "csv":
			path, contentType = rp.CSVPath, "text/csv; charset=utf-8"
		case "json":
			path, contentType = rp.JSONPath, "application/json"
		case "md":
			path, contentType = rp.MDPath, "text/markdown; charset=utf-8"
		case "pdf":
			path, contentType = rp.PDFPath, "application/pdf"
		}
		if path == "" {
			http.Error(w, "that format is not available", http.StatusNotFound)
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"47c-report-%d.%s\"", id, format))
		_, _ = w.Write(data)
	case "zip":
		files := map[string]string{
			"report.html": rp.HTMLPath,
			"report.csv":  rp.CSVPath,
			"report.json": rp.JSONPath,
			"report.md":   rp.MDPath,
			"report.pdf":  rp.PDFPath,
		}
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for name, path := range files {
			data, err := os.ReadFile(path)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			hdr := &zip.FileHeader{Name: name, Method: zip.Store}
			fw, err := zw.CreateHeader(hdr)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if _, err := io.Copy(fw, bytes.NewReader(data)); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}
		if err := zw.Close(); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"47c-report-%d.zip\"", id))
		_, _ = w.Write(buf.Bytes())
	default:
		http.Error(w, "unknown format", http.StatusBadRequest)
	}
}
