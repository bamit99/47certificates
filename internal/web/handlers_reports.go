package web

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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
	reports, err := s.deps.Store.ListReports(ctx, 20)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	scans, err := s.deps.Store.ListScans(ctx, 50)
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
	scanID, err := strconv.ParseInt(r.PostFormValue("scan_id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid scan_id", http.StatusBadRequest)
		return
	}
	domain := strings.TrimSpace(r.PostFormValue("domain"))

	params := fmt.Sprintf(`{"domain":%q}`, domain)
	reportID, err := s.deps.Store.CreateReport(ctx, scanID, string(kind), &u.ID, []byte(params))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	artifacts, genErr := report.Generate(ctx, s.deps.Store, reportID, scanID, kind, domain, s.now())
	if genErr != nil {
		_ = s.deps.Store.FailReport(ctx, reportID, genErr.Error())
		_ = s.deps.Store.Audit(ctx, &u.ID, "report.fail", strconv.FormatInt(reportID, 10),
			[]byte(fmt.Sprintf(`{"error":%q}`, genErr.Error())), clientIP(r))
		http.Error(w, "report generation failed: "+genErr.Error(), http.StatusInternalServerError)
		return
	}

	// Write the artifacts under <DataDir>/reports/<id>/ and record their hashes.
	if err := s.writeReportArtifacts(reportID, artifacts); err != nil {
		_ = s.deps.Store.FailReport(ctx, reportID, err.Error())
		http.Error(w, "report write failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	paths := []string{
		filepath.Join(s.reportsDir(reportID), "report.html"),
		filepath.Join(s.reportsDir(reportID), "report.csv"),
		filepath.Join(s.reportsDir(reportID), "report.json"),
	}
	sizeTotal, shaJSON, err := hashReportFiles(paths[0], paths[1], paths[2])
	if err != nil {
		_ = s.deps.Store.FailReport(ctx, reportID, err.Error())
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.deps.Store.SaveReportFiles(ctx, reportID, paths[0], paths[1], paths[2], sizeTotal, shaJSON); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_ = s.deps.Store.Audit(ctx, &u.ID, "report.generate", strconv.FormatInt(reportID, 10),
		[]byte(fmt.Sprintf(`{"kind":%q,"scan_id":%d}`, kind, scanID)), clientIP(r))
	http.Redirect(w, r, "/reports/"+strconv.FormatInt(reportID, 10), http.StatusSeeOther)
}

func (s *Server) writeReportArtifacts(id int64, a report.Artifacts) error {
	dir := s.reportsDir(id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	files := map[string][]byte{
		"report.html": a.HTML,
		"report.csv":  a.CSV,
		"report.json": a.JSON,
	}
	for name, data := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func hashReportFiles(htmlPath, csvPath, jsonPath string) (int64, string, error) {
	type part struct {
		name string
		path string
	}
	parts := []part{{"html", htmlPath}, {"csv", csvPath}, {"json", jsonPath}}
	hashes := map[string]string{}
	var total int64
	for _, p := range parts {
		data, err := os.ReadFile(p.path)
		if err != nil {
			return 0, "", err
		}
		sum := sha256.Sum256(data)
		hashes[p.name] = hex.EncodeToString(sum[:])
		total += int64(len(data))
	}
	shaSum := sha256.Sum256([]byte(fmt.Sprintf("%s %s %s", hashes["html"], hashes["csv"], hashes["json"])))
	shaJSON := fmt.Sprintf(`{"combined":%q,"html":%q,"csv":%q,"json":%q}`,
		hex.EncodeToString(shaSum[:]), hashes["html"], hashes["csv"], hashes["json"])
	return total, shaJSON, nil
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
		Report store.Report
	}{
		pageData: s.base(r, fmt.Sprintf("Report #%d", id)),
		Report:   rp,
	}
	s.render(w, "report", data)
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
	case "html", "csv", "json":
		var path, contentType string
		switch format {
		case "html":
			path, contentType = rp.HTMLPath, "text/html; charset=utf-8"
		case "csv":
			path, contentType = rp.CSVPath, "text/csv; charset=utf-8"
		case "json":
			path, contentType = rp.JSONPath, "application/json"
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
