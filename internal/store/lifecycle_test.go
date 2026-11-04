package store

import (
	"context"
	"testing"
	"time"

	"github.com/amit/47certificates/internal/x509eval"
)

// A cancelled scan must not move last_seen or resurrect a retired
// certificate. Lifecycle fields belong to scans that end "done".
func TestCancelledScanDoesNotMoveLifecycle(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now()

	certID, err := s.UpsertCert(ctx, x509eval.Cert{
		Fingerprint: "cc", Subject: "CN=a", Issuer: "CN=ca",
		NotBefore: now.Add(-10 * 24 * time.Hour), NotAfter: now.Add(100 * 24 * time.Hour),
		LifetimeDays: 110, KeyAlg: "ECDSA", KeyBits: 256, SigAlg: "ECDSA-SHA256",
	})
	if err != nil {
		t.Fatal(err)
	}

	// A done scan that observes the certificate sets last_seen.
	s1, _ := s.BeginScan(ctx, "cli", nil)
	ep, _ := s.UpsertEndpoint(ctx, "a.example.com", 443, "127.0.0.1", s1)
	v := x509eval.Verdict{Trust: "public", ChainValid: true, HostnameValid: true}
	if err := s.RecordObservation(ctx, s1, ep, certID, v, 0x0304, 0x1301, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishScan(ctx, s1, "done", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkSeen(ctx, s1); err != nil {
		t.Fatal(err)
	}
	seen := lastSeen(t, s, certID)
	if seen == nil {
		t.Fatal("a done scan must set last_seen")
	}
	firstSeen := *seen

	// A cancelled scan observes the certificate again. last_seen must not move.
	s2, _ := s.BeginScan(ctx, "cli", nil)
	ep2, _ := s.UpsertEndpoint(ctx, "b.example.com", 443, "127.0.0.2", s2)
	if err := s.RecordObservation(ctx, s2, ep2, certID, v, 0x0304, 0x1301, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishScan(ctx, s2, "cancelled", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkSeen(ctx, s2); err != nil {
		t.Fatal(err)
	}
	seen = lastSeen(t, s, certID)
	if seen == nil || !seen.Equal(firstSeen) {
		t.Fatalf("a cancelled scan moved last_seen: %v -> %v", firstSeen, seen)
	}
}

// A retired certificate that is served again becomes active, but only after a
// scan that ends "done".
func TestReobservedCertIsUnretiredOnlyOnDoneScan(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now()

	certID, err := s.UpsertCert(ctx, x509eval.Cert{
		Fingerprint: "dd", Subject: "CN=a", Issuer: "CN=ca",
		NotBefore: now.Add(-10 * 24 * time.Hour), NotAfter: now.Add(100 * 24 * time.Hour),
		LifetimeDays: 110, KeyAlg: "ECDSA", KeyBits: 256, SigAlg: "ECDSA-SHA256",
	})
	if err != nil {
		t.Fatal(err)
	}
	v := x509eval.Verdict{Trust: "public", ChainValid: true, HostnameValid: true}

	// Scan 1 observes it.
	s1, _ := s.BeginScan(ctx, "cli", nil)
	ep, _ := s.UpsertEndpoint(ctx, "a.example.com", 443, "127.0.0.1", s1)
	if err := s.RecordObservation(ctx, s1, ep, certID, v, 0x0304, 0x1301, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishScan(ctx, s1, "done", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkSeen(ctx, s1); err != nil {
		t.Fatal(err)
	}

	// Scan 2 does not observe it: it is retired.
	s2, _ := s.BeginScan(ctx, "cli", nil)
	if err := s.FinishScan(ctx, s2, "done", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.RetireUnseen(ctx, s2); err != nil {
		t.Fatal(err)
	}
	if !retired(t, s, certID) {
		t.Fatal("cert not retired by a done scan that no longer observes it")
	}

	// Scan 3 is cancelled but observes it again: it stays retired.
	s3, _ := s.BeginScan(ctx, "cli", nil)
	ep3, _ := s.UpsertEndpoint(ctx, "c.example.com", 443, "127.0.0.3", s3)
	if err := s.RecordObservation(ctx, s3, ep3, certID, v, 0x0304, 0x1301, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishScan(ctx, s3, "cancelled", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkSeen(ctx, s3); err != nil {
		t.Fatal(err)
	}
	if !retired(t, s, certID) {
		t.Fatal("a cancelled scan must not resurrect a retired certificate")
	}

	// Scan 4 is done and observes it: it is active again.
	s4, _ := s.BeginScan(ctx, "cli", nil)
	ep4, _ := s.UpsertEndpoint(ctx, "d.example.com", 443, "127.0.0.4", s4)
	if err := s.RecordObservation(ctx, s4, ep4, certID, v, 0x0304, 0x1301, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishScan(ctx, s4, "done", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkSeen(ctx, s4); err != nil {
		t.Fatal(err)
	}
	if retired(t, s, certID) {
		t.Fatal("a done scan that observes the certificate must clear retired_at")
	}
}

// A finding whose condition no longer holds is closed; one that still holds
// stays open.
func TestFindingsAreClosedWhenConditionEnds(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now()

	certID, err := s.UpsertCert(ctx, x509eval.Cert{
		Fingerprint: "ff", Subject: "CN=a", Issuer: "CN=ca",
		NotBefore: now.Add(-10 * 24 * time.Hour), NotAfter: now.Add(100 * 24 * time.Hour),
		LifetimeDays: 110, KeyAlg: "ECDSA", KeyBits: 256, SigAlg: "ECDSA-SHA256",
	})
	if err != nil {
		t.Fatal(err)
	}

	// The certificate is too long for the phase: one cert-level finding.
	fs := []x509eval.Finding{{Type: x509eval.Exceeds47Target, Detail: map[string]any{"lifetime_days": 110}}}
	if err := s.SyncFindings(ctx, 1, certID, nil, fs, now); err != nil {
		t.Fatal(err)
	}
	if status := findingStatus(t, s, certID, x509eval.Exceeds47Target); status != "open" {
		t.Fatalf("status = %q, want open", status)
	}

	// The next scan finds no such condition: the finding is closed.
	if err := s.SyncFindings(ctx, 2, certID, nil, nil, now); err != nil {
		t.Fatal(err)
	}
	if status := findingStatus(t, s, certID, x509eval.Exceeds47Target); status != "resolved" {
		t.Fatalf("status = %q, want resolved", status)
	}

	// The condition returns: the finding is open again.
	if err := s.SyncFindings(ctx, 3, certID, nil, fs, now); err != nil {
		t.Fatal(err)
	}
	if status := findingStatus(t, s, certID, x509eval.Exceeds47Target); status != "open" {
		t.Fatalf("status = %q, want open again", status)
	}
}

// An acknowledged finding is a decision, not a live condition: it is not
// closed when the condition disappears.
func TestAcknowledgedFindingIsNotClosed(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now()

	certID, err := s.UpsertCert(ctx, x509eval.Cert{
		Fingerprint: "gg", Subject: "CN=a", Issuer: "CN=ca",
		NotBefore: now.Add(-10 * 24 * time.Hour), NotAfter: now.Add(100 * 24 * time.Hour),
		LifetimeDays: 110, KeyAlg: "ECDSA", KeyBits: 256, SigAlg: "ECDSA-SHA256",
	})
	if err != nil {
		t.Fatal(err)
	}
	fs := []x509eval.Finding{{Type: x509eval.Exceeds47Target, Detail: map[string]any{"lifetime_days": 110}}}
	if err := s.SyncFindings(ctx, 1, certID, nil, fs, now); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, "admin", "hash"); err != nil {
		t.Fatal(err)
	}
	var userID int64
	if err := s.db.QueryRow(`SELECT id FROM users WHERE username = 'admin'`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if err := s.AckFinding(ctx, findingID(t, s, certID, x509eval.Exceeds47Target), userID, "accepted"); err != nil {
		t.Fatal(err)
	}
	if err := s.SyncFindings(ctx, 2, certID, nil, nil, now); err != nil {
		t.Fatal(err)
	}
	if status := findingStatus(t, s, certID, x509eval.Exceeds47Target); status != "ack" {
		t.Fatalf("status = %q, want ack", status)
	}
}

// A certificate-level finding is stored once, however many endpoints serve
// the certificate.
func TestCertLevelFindingIsStoredOnce(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now()

	certID, err := s.UpsertCert(ctx, x509eval.Cert{
		Fingerprint: "hh", Subject: "CN=a", Issuer: "CN=ca",
		NotBefore: now.Add(-10 * 24 * time.Hour), NotAfter: now.Add(100 * 24 * time.Hour),
		LifetimeDays: 110, KeyAlg: "ECDSA", KeyBits: 256, SigAlg: "ECDSA-SHA256",
	})
	if err != nil {
		t.Fatal(err)
	}
	fs := []x509eval.Finding{{Type: x509eval.Exceeds47Target, Detail: map[string]any{"lifetime_days": 110}}}
	for i := 0; i < 5; i++ {
		ep, _ := s.UpsertEndpoint(ctx, "a.example.com", 443+i, "127.0.0.1", 1)
		if err := s.SyncFindings(ctx, 1, certID, nil, fs, now); err != nil {
			t.Fatal(err)
		}
		if err := s.SyncFindings(ctx, 1, certID, &ep, nil, now); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM findings WHERE cert_id = ? AND type = ?`,
		certID, x509eval.Exceeds47Target).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("cert-level findings = %d, want 1", n)
	}
}

func lastSeen(t *testing.T, s *Store, certID int64) *time.Time {
	t.Helper()
	var v *int64
	if err := s.db.QueryRow("SELECT last_seen FROM certs WHERE id=?", certID).Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v == nil {
		return nil
	}
	at := fromUnix(*v)
	return &at
}

func findingStatus(t *testing.T, s *Store, certID int64, ftype string) string {
	t.Helper()
	var status string
	err := s.db.QueryRow(`SELECT status FROM findings WHERE cert_id = ? AND type = ?`, certID, ftype).Scan(&status)
	if err != nil {
		t.Fatal(err)
	}
	return status
}

func findingID(t *testing.T, s *Store, certID int64, ftype string) int64 {
	t.Helper()
	var id int64
	err := s.db.QueryRow(`SELECT id FROM findings WHERE cert_id = ? AND type = ?`, certID, ftype).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
