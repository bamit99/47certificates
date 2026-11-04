package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/amit/47certificates/internal/x509eval"
)

// seedFinding returns a fingerprint and all open finding ids for the cert.
func seedFinding(t *testing.T, s *Server, fp, sans string) (fingerprint string, findingIDs []int64) {
	t.Helper()
	ctx := context.Background()
	domID, err := s.deps.Store.EnsureDomain(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}

	nb := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	cert := x509eval.Cert{
		Fingerprint:  fp,
		Subject:      "CN=" + sans,
		Issuer:       "CN=Test CA",
		NotBefore:    nb,
		NotAfter:     nb.Add(397 * 24 * time.Hour),
		LifetimeDays: 397,
		KeyAlg:       "ECDSA", KeyBits: 256, SigAlg: "ECDSA-SHA256",
		SANs: []string{sans},
		Raw:  []byte("raw" + fp),
	}
	certID, err2 := s.deps.Store.UpsertCert(ctx, cert)
	if err2 != nil {
		t.Fatal(err2)
	}
	v := x509eval.Verdict{Trust: "public", ChainValid: true, HostnameValid: true}
	findings := x509eval.Findings(cert, v, readTestNow)
	if err := s.deps.Store.SyncFindings(ctx, 1, domID, certID, nil, findings, readTestNow); err != nil {
		t.Fatal(err)
	}
	rows, err := s.deps.Store.DB().Query(`SELECT id FROM findings WHERE cert_id = ?`, certID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		findingIDs = append(findingIDs, id)
	}
	return fp, findingIDs
}

func TestAckHidesFromDefaultListButKeepsRow(t *testing.T) {
	s, st, cookie := newReadTestServer(t)
	fpA, findingIDs := seedFinding(t, s, "5555555555555555555555555555555555555555555555555555555555555555", "ack.example.com")

	rec := getAuth(s, "/certs", cookie)
	if !strings.Contains(rec.Body.String(), fpA[:16]) {
		t.Fatalf("cert should be listed by default: %s", rec.Body.String())
	}

	for _, id := range findingIDs {
		rec := post(s, fmt.Sprintf("/findings/%d/ack", id), url.Values{
			"note": {"accepted"},
			"next": {"/certs"},
		}, cookie, s.csrfToken(cookie.Value))
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("ack status = %d: %s", rec.Code, rec.Body.String())
		}
	}

	rec = getAuth(s, "/certs", cookie)
	if strings.Contains(rec.Body.String(), fpA[:16]) {
		t.Fatalf("acked cert must be hidden from the default list: %s", rec.Body.String())
	}

	rec = getAuth(s, "/certs?status=acked", cookie)
	if !strings.Contains(rec.Body.String(), fpA[:16]) {
		t.Fatalf("acked cert must be listed under ?status=acked: %s", rec.Body.String())
	}

	var status string
	var ackBy *int64
	if err := st.DB().QueryRow(`SELECT status, ack_by FROM findings WHERE id = ?`, findingIDs[0]).Scan(&status, &ackBy); err != nil {
		t.Fatal(err)
	}
	if status != "ack" || ackBy == nil {
		t.Fatalf("status = %q ack_by = %v", status, ackBy)
	}
}

func TestSnoozeExpires(t *testing.T) {
	s, st, cookie := newReadTestServer(t)
	fp, findingIDs := seedFinding(t, s, "6666666666666666666666666666666666666666666666666666666666666666", "snooze.example.com")

	ctx := context.Background()
	domID, err := st.EnsureDomain(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range findingIDs {
		if err := st.SnoozeFinding(ctx, id, 1, readTestNow.Add(time.Hour), readTestNow, ""); err != nil {
			t.Fatal(err)
		}
	}

	c, err2 := st.CertByFingerprint(ctx, domID, fp)
	if err2 != nil {
		t.Fatal(err2)
	}
	v := buildCertView(c, readTestNow)
	if v.OpenCount != 0 {
		t.Fatalf("snoozed finding must not count as open: open=%d", v.OpenCount)
	}

	// Two hours later the same rows read as open again, with no write.
	v2 := buildCertView(c, readTestNow.Add(2*time.Hour))
	if v2.OpenCount != len(findingIDs) {
		t.Fatalf("expired snooze must return to open: open=%d", v2.OpenCount)
	}
	_ = cookie

	// The default list hides it now, and ?status=snoozed shows it.
	rec := getAuth(s, "/certs", cookie)
	if strings.Contains(rec.Body.String(), fp[:16]) {
		t.Fatalf("snoozed cert must be hidden: %s", rec.Body.String())
	}
	rec = getAuth(s, "/certs?status=snoozed", cookie)
	if !strings.Contains(rec.Body.String(), fp[:16]) {
		t.Fatalf("snoozed cert must be listed under ?status=snoozed: %s", rec.Body.String())
	}
}

func TestNewCertIsNotAcked(t *testing.T) {
	s, st, cookie := newReadTestServer(t)
	_, findingIDs := seedFinding(t, s, "7777777777777777777777777777777777777777777777777777777777777777", "first.example.com")
	_ = st

	for _, id := range findingIDs {
		rec := post(s, fmt.Sprintf("/findings/%d/ack", id), url.Values{
			"note": {""},
			"next": {"/certs"},
		}, cookie, s.csrfToken(cookie.Value))
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("ack status = %d", rec.Code)
		}
	}

	// Second certificate with the same finding type.
	fpB, _ := seedFinding(t, s, "8888888888888888888888888888888888888888888888888888888888888888", "second.example.com")

	rec2 := getAuth(s, "/certs", cookie)
	if !strings.Contains(rec2.Body.String(), fpB[:16]) {
		t.Fatalf("a new certificate must show as open: %s", rec2.Body.String())
	}
	if strings.Contains(rec2.Body.String(), "7777777777777777") {
		t.Fatalf("acked cert must stay hidden: %s", rec2.Body.String())
	}
}
