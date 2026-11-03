package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/amit/47certificates/internal/x509eval"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Migrate(); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMigrateAndOpenTwice(t *testing.T) {
	s := openTest(t)
	if err := s.Migrate(); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	var mode string
	if err := s.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Fatalf("journal_mode = %s", mode)
	}
}

func TestOnlyDoneScansRetireCerts(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now()

	certID, err := s.UpsertCert(ctx, x509eval.Cert{
		Fingerprint: "aa", Subject: "CN=a", Issuer: "CN=ca",
		NotBefore: now.Add(-10 * 24 * time.Hour), NotAfter: now.Add(100 * 24 * time.Hour),
		LifetimeDays: 110, KeyAlg: "ECDSA", KeyBits: 256, SigAlg: "ECDSA-SHA256",
	})
	if err != nil {
		t.Fatal(err)
	}
	s1, _ := s.BeginScan(ctx, "cli", nil)
	ep, _ := s.UpsertEndpoint(ctx, "a.example.com", 443, "127.0.0.1", s1)
	if err := s.RecordObservation(ctx, s1, ep, certID, x509eval.Verdict{Trust: "public", ChainValid: true, HostnameValid: true}, 0x0304, 0x1301, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishScan(ctx, s1, "done", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.RetireUnseen(ctx, s1); err != nil {
		t.Fatal(err)
	}
	if retired(t, s, certID) {
		t.Fatal("cert observed by a done scan must not be retired")
	}

	s2, _ := s.BeginScan(ctx, "manual", nil)
	if err := s.FinishScan(ctx, s2, "cancelled", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.RetireUnseen(ctx, s2); err != nil {
		t.Fatal(err)
	}
	if retired(t, s, certID) {
		t.Fatal("cancelled scan must not retire certs")
	}

	s3, _ := s.BeginScan(ctx, "schedule", nil)
	if err := s.FinishScan(ctx, s3, "done", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.RetireUnseen(ctx, s3); err != nil {
		t.Fatal(err)
	}
	if !retired(t, s, certID) {
		t.Fatal("a done scan that no longer observes the cert must retire it")
	}
}

func retired(t *testing.T, s *Store, certID int64) bool {
	t.Helper()
	var at *int64
	if err := s.db.QueryRow("SELECT retired_at FROM certs WHERE id=?", certID).Scan(&at); err != nil {
		t.Fatal(err)
	}
	return at != nil
}

func TestScanLockIsExclusive(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	release, err := s.AcquireScanLock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcquireScanLock(ctx); !errors.Is(err, ErrScanInProgress) {
		t.Fatalf("second acquire err = %v", err)
	}
	release()
	if _, err := s.AcquireScanLock(ctx); err != nil {
		t.Fatalf("after release: %v", err)
	}
}
