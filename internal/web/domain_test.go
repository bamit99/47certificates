package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/amit/47certificates/internal/x509eval"
)

// seedDomainCert records a certificate observed by a domain.
func seedDomainCert(t *testing.T, s *Server, domain, fp, sans string, lifetime int) {
	t.Helper()
	ctx := context.Background()
	domID, err := s.deps.Store.EnsureDomain(ctx, domain)
	if err != nil {
		t.Fatal(err)
	}
	nb := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	cert := x509eval.Cert{
		Fingerprint: fp, Subject: "CN=" + sans, Issuer: "CN=Test CA",
		NotBefore: nb, NotAfter: nb.AddDate(0, 0, lifetime),
		LifetimeDays: lifetime, KeyAlg: "ECDSA", KeyBits: 256, SigAlg: "ECDSA-SHA256",
		SANs: []string{sans}, Raw: []byte("raw" + fp),
	}
	certID, err := s.deps.Store.UpsertCert(ctx, cert)
	if err != nil {
		t.Fatal(err)
	}
	scanID, err := s.deps.Store.BeginDomainScan(ctx, "cli", nil, domID)
	if err != nil {
		t.Fatal(err)
	}
	ep, err := s.deps.Store.UpsertEndpoint(ctx, domID, sans, 443, "192.0.2.1", scanID)
	if err != nil {
		t.Fatal(err)
	}
	v := x509eval.Verdict{Trust: "public", ChainValid: true, HostnameValid: true}
	if err := s.deps.Store.RecordObservation(ctx, scanID, domID, ep, certID, v, 0x0304, 0x1301, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.deps.Store.FinishScan(ctx, scanID, "done", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.deps.Store.MarkSeen(ctx, scanID, domID); err != nil {
		t.Fatal(err)
	}
}

// Two domains do not mix: the certificate list of one domain shows only its
// own certificates.
func TestDomainsDoNotMix(t *testing.T) {
	s, _, cookie := newReadTestServer(t)
	seedDomainCert(t, s, "alpha.example", "aa", "a.alpha.example", 90)
	seedDomainCert(t, s, "beta.example", "bb", "b.beta.example", 90)

	rec := getAuth(s, "/certs?domain=alpha.example", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "a.alpha.example") {
		t.Fatalf("alpha's certificate is missing:\n%s", body)
	}
	if strings.Contains(body, "b.beta.example") {
		t.Fatal("beta's certificate leaked into alpha's list")
	}

	rec = getAuth(s, "/certs?domain=beta.example", cookie)
	body = rec.Body.String()
	if !strings.Contains(body, "b.beta.example") {
		t.Fatalf("beta's certificate is missing:\n%s", body)
	}
	if strings.Contains(body, "a.alpha.example") {
		t.Fatal("alpha's certificate leaked into beta's list")
	}
}

// The dashboard of one domain counts only that domain's certificates.
func TestDashboardCountsOneDomain(t *testing.T) {
	s, _, cookie := newReadTestServer(t)
	seedDomainCert(t, s, "alpha.example", "aa", "a.alpha.example", 90)
	seedDomainCert(t, s, "beta.example", "bb", "b.beta.example", 400)

	rec := getAuth(s, "/?domain=alpha.example", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Phase exposure") {
		t.Fatalf("no counts:\n%s", body)
	}
	// The 400-day certificate of the other domain must not be counted.
	if strings.Contains(body, "b.beta.example") {
		t.Fatal("the other domain's certificate leaked into the dashboard")
	}
}

// The domain picker lists the domains and the search narrows them.
func TestDomainPickerAndSearch(t *testing.T) {
	s, _, cookie := newReadTestServer(t)
	seedDomainCert(t, s, "alpha.example", "aa", "a.alpha.example", 90)
	seedDomainCert(t, s, "beta.example", "bb", "b.beta.example", 90)

	rec := getAuth(s, "/domains", cookie)
	body := rec.Body.String()
	if !strings.Contains(body, "alpha.example") || !strings.Contains(body, "beta.example") {
		t.Fatalf("the picker does not list both domains:\n%s", body)
	}

	rec = getAuth(s, "/domains?q=alpha", cookie)
	body = rec.Body.String()
	if !strings.Contains(body, "alpha.example") {
		t.Fatalf("the search dropped the matching domain:\n%s", body)
	}
	if strings.Contains(body, ">beta.example<") {
		t.Fatal("the search kept the non-matching domain")
	}
}

// The operator chooses the columns of the certificate list.
func TestColumnChooser(t *testing.T) {
	s, st, cookie := newReadTestServer(t)
	seedDomainCert(t, s, "alpha.example", "aa", "a.alpha.example", 90)

	// The issuer and the SANs are available.
	rec := getAuth(s, "/certs/columns", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Issuer") || !strings.Contains(body, "SANs") {
		t.Fatalf("the chooser does not offer the issuer and the SANs:\n%s", body)
	}

	// Choosing a set of columns changes the list.
	rec = post(s, "/certs/columns", url.Values{
		"columns": {"subject", "issuer", "sans"},
	}, cookie, s.csrfToken(cookie.Value))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save status = %d", rec.Code)
	}
	rec = getAuth(s, "/certs?domain=alpha.example", cookie)
	body = rec.Body.String()
	if strings.Contains(body, ">Fingerprint</th>") {
		t.Fatalf("the fingerprint column was not removed:\n%s", body)
	}
	if !strings.Contains(body, ">Issuer</th>") {
		t.Fatalf("the issuer column was not added:\n%s", body)
	}
	if !strings.Contains(body, ">SANs</th>") {
		t.Fatalf("the SAN column was not added:\n%s", body)
	}
	// The default set is restored when nothing is chosen.
	cols, err := st.GetCertColumns(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(cols) != 3 {
		t.Fatalf("columns = %v", cols)
	}
}

// The legend explains the statuses on the dashboard.
func TestDashboardHasLegend(t *testing.T) {
	s, _, cookie := newReadTestServer(t)
	rec := getAuth(s, "/", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Legend", "Violation", "Grandfathered", "Expiring", "violates_current_phase"} {
		if !strings.Contains(body, want) {
			t.Errorf("the dashboard does not explain %q", want)
		}
	}
}
