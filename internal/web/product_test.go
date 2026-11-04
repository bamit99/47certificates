package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/amit/47certificates/internal/x509eval"
)

// The export route writes the inventory of a completed scan.
func TestExportCSVAndJSON(t *testing.T) {
	s, st, cookie := newReadTestServer(t)
	ctx := context.Background()

	scanID, err := st.BeginScan(ctx, "cli", nil)
	if err != nil {
		t.Fatal(err)
	}
	cert := x509eval.Cert{
		Fingerprint: "ee", Subject: "CN=a.example.com", Issuer: "CN=Test CA",
		NotBefore: time.Now().AddDate(0, 0, -5), NotAfter: time.Now().AddDate(0, 0, 85),
		LifetimeDays: 90, KeyAlg: "ECDSA", KeyBits: 256, SigAlg: "ECDSA-SHA256",
		SANs: []string{"a.example.com"}, Raw: []byte("raw"),
	}
	certID, err := st.UpsertCert(ctx, cert)
	if err != nil {
		t.Fatal(err)
	}
	ep, err := st.UpsertEndpoint(ctx, "a.example.com", 443, "192.0.2.1", scanID)
	if err != nil {
		t.Fatal(err)
	}
	v := x509eval.Verdict{Trust: "public", ChainValid: true, HostnameValid: true}
	if err := st.RecordObservation(ctx, scanID, ep, certID, v, 0x0304, 0x1301, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.FinishScan(ctx, scanID, "done", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}

	rec := getAuth(s, "/export?format=csv", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("csv status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "a.example.com") {
		t.Fatalf("csv body = %s", rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, ".csv") {
		t.Fatalf("Content-Disposition = %q", cd)
	}

	rec = getAuth(s, "/export?format=json", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("json status = %d", rec.Code)
	}
	var doc struct {
		ScanID int64 `json:"scan_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.ScanID != scanID {
		t.Fatalf("scan_id = %d, want %d", doc.ScanID, scanID)
	}

	// An unknown format is refused.
	rec = getAuth(s, "/export?format=pdf", cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad format status = %d", rec.Code)
	}
}

// The dashboard shows the phase buckets: how many certificates were issued
// in each phase and how many exceeded that phase's maximum.
func TestDashboardShowsPhaseBuckets(t *testing.T) {
	s, st, cookie := newReadTestServer(t)
	ctx := context.Background()

	certs := []struct {
		fp   string
		days int
	}{
		{"a1", 90},  // issued now: P1 (max 200), so not exceeding
		{"a2", 300}, // issued now: P1 (max 200), so exceeding
		{"a3", 300}, // issued in 2024: P0 (max 398), so not exceeding
	}
	for i, c := range certs {
		nb := time.Now().AddDate(0, 0, -5)
		if i == 2 {
			nb = time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
		}
		cert := x509eval.Cert{
			Fingerprint: c.fp, Subject: "CN=" + c.fp, Issuer: "CN=Test CA",
			NotBefore: nb, NotAfter: nb.AddDate(0, 0, c.days),
			LifetimeDays: c.days, KeyAlg: "ECDSA", KeyBits: 256, SigAlg: "ECDSA-SHA256",
			SANs: []string{c.fp + ".example.com"}, Raw: []byte("raw"),
		}
		if _, err := st.UpsertCert(ctx, cert); err != nil {
			t.Fatal(err)
		}
	}

	rec := getAuth(s, "/", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Phase exposure") {
		t.Fatalf("dashboard has no phase table:\n%s", body)
	}
	for _, name := range []string{"P0", "P1"} {
		if !strings.Contains(body, ">"+name+"<") {
			t.Fatalf("dashboard missing phase %s", name)
		}
	}
}

// The live progress counters are written while a scan runs, so the UI can
// show movement rather than a blank page.
func TestScanStatsAreWrittenWhileRunning(t *testing.T) {
	_, st, _ := newReadTestServer(t)
	ctx := context.Background()

	scanID, err := st.BeginScan(ctx, "cli", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.MarkRunning(ctx, scanID); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"stage":"probe","hosts":3,"observed":2,"failed":1}`)
	if err := st.UpdateScanStats(ctx, scanID, payload); err != nil {
		t.Fatal(err)
	}
	sc, err := st.ScanByID(ctx, scanID)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Stats == "" {
		t.Fatal("stats were not written during the scan")
	}
	if !strings.Contains(sc.Stats, "\"observed\":2") {
		t.Fatalf("stats = %s", sc.Stats)
	}
	// The status is not disturbed by a stats update.
	if sc.Status != "running" {
		t.Fatalf("status = %s, want running", sc.Status)
	}

	// A finished scan keeps its final counters.
	if err := st.FinishScan(ctx, scanID, "done", []byte(`{"stage":"done","observed":9}`), ""); err != nil {
		t.Fatal(err)
	}
	sc, _ = st.ScanByID(ctx, scanID)
	if !strings.Contains(sc.Stats, "\"observed\":9") {
		t.Fatalf("stats = %s", sc.Stats)
	}
}

// The settings form reports the retention as a number of scans.
func TestRetentionSettingIsAScanCount(t *testing.T) {
	s, _, cookie := newReadTestServer(t)
	rec := post(s, "/settings", url.Values{
		"retention": {"90"},
	}, cookie, s.csrfToken(cookie.Value))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", rec.Code)
	}
	v, err := s.deps.Store.GetSetting(context.Background(), "retention")
	if err != nil {
		t.Fatal(err)
	}
	if v != "90" {
		t.Fatalf("retention = %q", v)
	}
}

// The store keeps the counters of a running scan separate from the terminal
// record.
func TestUpdateScanStatsLeavesTerminalScansAlone(t *testing.T) {
	_, st, _ := newReadTestServer(t)
	ctx := context.Background()
	scanID, err := st.BeginScan(ctx, "cli", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.FinishScan(ctx, scanID, "done", []byte(`{"observed":1}`), ""); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateScanStats(ctx, scanID, []byte(`{"observed":99}`)); err != nil {
		t.Fatal(err)
	}
	sc, _ := st.ScanByID(ctx, scanID)
	if !strings.Contains(sc.Stats, `"observed":1`) {
		t.Fatalf("a finished scan's counters were overwritten: %s", sc.Stats)
	}
}
