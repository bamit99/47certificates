package web

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/amit/47certificates/internal/x509eval"
)

func seedReportTestScan(t *testing.T, s *Server, public bool) int64 {
	t.Helper()
	ctx := context.Background()
	id, err := s.deps.Store.BeginScan(ctx, "cli", nil)
	if err != nil {
		t.Fatal(err)
	}
	cb := "public"
	if !public {
		cb = "private"
	}
	_ = cb

	nb := readTestNow.AddDate(0, 0, -10)
	cert := x509eval.Cert{
		Fingerprint:  "9999999999999999999999999999999999999999999999999999999999999999",
		Subject:      "CN=report.example.com",
		Issuer:       "CN=Test CA",
		NotBefore:    nb,
		NotAfter:     nb.Add(90 * 24 * time.Hour),
		LifetimeDays: 90,
		KeyAlg:       "ECDSA", KeyBits: 256, SigAlg: "ECDSA-SHA256",
		SANs: []string{"report.example.com"}, Raw: []byte("raw-report"),
	}
	certID, err := s.deps.Store.UpsertCert(ctx, cert)
	if err != nil {
		t.Fatal(err)
	}
	ep, err := s.deps.Store.UpsertEndpoint(ctx, "report.example.com", 443, "192.0.2.50", id)
	if err != nil {
		t.Fatal(err)
	}
	trust := "public"
	if !public {
		trust = "private"
	}
	v := x509eval.Verdict{Trust: trust, ChainValid: true, HostnameValid: true}
	if err := s.deps.Store.RecordObservation(ctx, id, ep, certID, v, 0x0304, 0x1301, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.deps.Store.FinishScan(ctx, id, "done", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestReportLifecycle(t *testing.T) {
	s, _, cookie := newReadTestServer(t)
	scanID := seedReportTestScan(t, s, true)

	// Generate.
	rec := post(s, "/reports", url.Values{
		"kind":    {"worklist"},
		"scan_id": {fmt.Sprint(scanID)},
	}, cookie, s.csrfToken(cookie.Value))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create status = %d: %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")

	// Detail page renders.
	rec = getAuth(s, loc, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("detail status = %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("done")) {
		t.Fatalf("detail body: %s", rec.Body.String())
	}

	// HTML download serves bytes.
	rec = getAuth(s, loc+"/download?format=html", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("html status = %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("9999999999999999")) {
		t.Fatal("html should include the fingerprint")
	}

	// ZIP download is a valid archive containing report.json.
	rec = getAuth(s, loc+"/download?format=zip", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("zip status = %d", rec.Code)
	}
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("zip: %v", err)
	}
	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
	}
	for _, want := range []string{"report.html", "report.csv", "report.json"} {
		if !names[want] {
			t.Fatalf("zip missing %s: %v", want, names)
		}
	}

	// Failing generation for an unknown kind is rejected at 500 with the report marked failed.
	badRec := post(s, "/reports", url.Values{
		"kind":    {"bogus"},
		"scan_id": {fmt.Sprint(scanID)},
	}, cookie, s.csrfToken(cookie.Value))
	if badRec.Code != http.StatusInternalServerError {
		t.Fatalf("bogus kind status = %d", badRec.Code)
	}

	// Delete removes the row and the directory.
	rec = post(s, loc+"/delete", url.Values{}, cookie, s.csrfToken(cookie.Value))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("delete status = %d", rec.Code)
	}
	rec = getAuth(s, loc, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("deleted report should 404, got %d", rec.Code)
	}
	reportDir := filepath.Join(filepath.Dir(s.deps.Store.Path()), "reports", filepath.Base(loc))
	if _, err := os.Stat(reportDir); !os.IsNotExist(err) {
		t.Fatalf("report directory should be gone: %s", reportDir)
	}
}

func TestReportGenerateRejectsMissingScan(t *testing.T) {
	s, _, cookie := newReadTestServer(t)
	rec := post(s, "/reports", url.Values{
		"kind":    {"executive"},
		"scan_id": {"99999"},
	}, cookie, s.csrfToken(cookie.Value))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
}
