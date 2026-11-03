package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/amit/47certificates/internal/auth"
	"github.com/amit/47certificates/internal/store"
	"github.com/amit/47certificates/internal/x509eval"
)

var readTestNow = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func newReadTestServer(t *testing.T) (*Server, *store.Store, *http.Cookie) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(); err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser(context.Background(), "admin", hash); err != nil {
		t.Fatal(err)
	}
	s := New(Deps{
		Store: st,
		Now:   func() time.Time { return readTestNow },
	}).(*Server)

	cookie := login(t, s)
	return s, st, cookie
}

func getAuth(s *Server, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func TestCertsListFiltersByBucket(t *testing.T) {
	s, st, cookie := newReadTestServer(t)
	ctx := context.Background()

	// Seed grandfathered cert (P0 issued 2025, 397d)
	certA := x509eval.Cert{
		Fingerprint:  "1111111111111111111111111111111111111111111111111111111111111111",
		Subject:      "CN=grandfathered.example.com",
		Issuer:       "CN=Test CA",
		NotBefore:    time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC).Add(397 * 24 * time.Hour),
		LifetimeDays: 397,
		KeyAlg:       "ECDSA",
		KeyBits:      256,
		SigAlg:       "ECDSA-SHA256",
		Raw:          []byte("rawA"),
	}
	idA, err := st.UpsertCert(ctx, certA)
	if err != nil {
		t.Fatal(err)
	}
	findingsA := x509eval.Findings(certA, x509eval.Verdict{Trust: "public", ChainValid: true, HostnameValid: true}, readTestNow)
	if err := st.SyncFindings(ctx, 1, idA, nil, findingsA, readTestNow); err != nil {
		t.Fatal(err)
	}

	// Seed compliant cert (P1 issued 2026-04, 90d)
	certB := x509eval.Cert{
		Fingerprint:  "2222222222222222222222222222222222222222222222222222222222222222",
		Subject:      "CN=compliant.example.com",
		Issuer:       "CN=Test CA",
		NotBefore:    time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		LifetimeDays: 90,
		KeyAlg:       "ECDSA",
		KeyBits:      256,
		SigAlg:       "ECDSA-SHA256",
		Raw:          []byte("rawB"),
	}
	idB, err := st.UpsertCert(ctx, certB)
	if err != nil {
		t.Fatal(err)
	}
	findingsB := x509eval.Findings(certB, x509eval.Verdict{Trust: "public", ChainValid: true, HostnameValid: true}, readTestNow)
	if err := st.SyncFindings(ctx, 1, idB, nil, findingsB, readTestNow); err != nil {
		t.Fatal(err)
	}

	rec := getAuth(s, "/certs?bucket=grandfathered", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, certA.Fingerprint) && !strings.Contains(body, certA.Fingerprint[:16]) {
		t.Fatalf("body should contain certA: %s", body)
	}
	if strings.Contains(body, certB.Fingerprint) || strings.Contains(body, certB.Fingerprint[:16]) {
		t.Fatalf("body should NOT contain certB: %s", body)
	}
}

func TestCertDetailShowsEndpointAndWhy(t *testing.T) {
	s, st, cookie := newReadTestServer(t)
	ctx := context.Background()

	// Seed scan 1
	scanID, err := st.BeginScan(ctx, "manual", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Seed cert with 397d issued after 2026-03-15 boundary (P1 violation)
	nb := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	cert := x509eval.Cert{
		Fingerprint:  "3333333333333333333333333333333333333333333333333333333333333333",
		Subject:      "CN=multi.example.com",
		Issuer:       "CN=Test CA",
		NotBefore:    nb,
		NotAfter:     nb.Add(397 * 24 * time.Hour),
		LifetimeDays: 397,
		KeyAlg:       "ECDSA",
		KeyBits:      256,
		SigAlg:       "ECDSA-SHA256",
		Raw:          []byte("raw3"),
	}
	certID, err := st.UpsertCert(ctx, cert)
	if err != nil {
		t.Fatal(err)
	}

	ep1, err := st.UpsertEndpoint(ctx, "ep1.example.com", 443, "192.0.2.1", scanID)
	if err != nil {
		t.Fatal(err)
	}
	ep2, err := st.UpsertEndpoint(ctx, "ep2.example.com", 8443, "192.0.2.2", scanID)
	if err != nil {
		t.Fatal(err)
	}

	v := x509eval.Verdict{Trust: "public", ChainValid: true, HostnameValid: true}
	_ = st.RecordObservation(ctx, scanID, ep1, certID, v, 0x0304, 0x1301, nil)
	_ = st.RecordObservation(ctx, scanID, ep2, certID, v, 0x0304, 0x1301, nil)

	findings := x509eval.Findings(cert, v, readTestNow)
	if err := st.SyncFindings(ctx, scanID, certID, &ep1, findings, readTestNow); err != nil {
		t.Fatal(err)
	}

	rec := getAuth(s, fmt.Sprintf("/certs/%s", cert.Fingerprint), cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "ep1.example.com") || !strings.Contains(body, "ep2.example.com") {
		t.Fatalf("body must show both hostnames: %s", body)
	}
	wantSentence := "lifetime 397d exceeds 200d allowed for certificates issued after 2026-03-15"
	if !strings.Contains(body, wantSentence) {
		t.Fatalf("body must contain finding sentence %q: %s", wantSentence, body)
	}
}

func TestDashboardCountsBucketsNotRows(t *testing.T) {
	s, st, cookie := newReadTestServer(t)
	ctx := context.Background()

	// Seed cert with exceeds_47_target and grandfathered_too_long
	nb := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	cert := x509eval.Cert{
		Fingerprint:  "4444444444444444444444444444444444444444444444444444444444444444",
		Subject:      "CN=grandfathered.example.com",
		Issuer:       "CN=Test CA",
		NotBefore:    nb,
		NotAfter:     nb.Add(397 * 24 * time.Hour),
		LifetimeDays: 397,
		KeyAlg:       "ECDSA",
		KeyBits:      256,
		SigAlg:       "ECDSA-SHA256",
		Raw:          []byte("raw4"),
	}
	certID, err := st.UpsertCert(ctx, cert)
	if err != nil {
		t.Fatal(err)
	}
	v := x509eval.Verdict{Trust: "public", ChainValid: true, HostnameValid: true}
	findings := x509eval.Findings(cert, v, readTestNow)
	if err := st.SyncFindings(ctx, 1, certID, nil, findings, readTestNow); err != nil {
		t.Fatal(err)
	}

	rec := getAuth(s, "/", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()

	// Assert grandfathered count is 1
	reGrandfathered := regexp.MustCompile(`data-bucket="grandfathered"[^>]*>[\s\S]*?<div class="count">(\d+)</div>`)
	matchG := reGrandfathered.FindStringSubmatch(body)
	if len(matchG) < 2 || matchG[1] != "1" {
		t.Fatalf("expected grandfathered count 1, matched: %v in body:\n%s", matchG, body)
	}

	// Assert info count is 0
	reInfo := regexp.MustCompile(`data-bucket="info"[^>]*>[\s\S]*?<div class="count">(\d+)</div>`)
	matchI := reInfo.FindStringSubmatch(body)
	if len(matchI) < 2 || matchI[1] != "0" {
		t.Fatalf("expected info count 0, matched: %v in body:\n%s", matchI, body)
	}
}
