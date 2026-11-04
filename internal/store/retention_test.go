package store

import (
	"context"
	"testing"
	"time"

	"github.com/amit/47certificates/internal/x509eval"
)

func TestPruneKeepsNewestScans(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now()
	domID, err := s.EnsureDomain(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}

	certID, err2 := s.UpsertCert(ctx, x509eval.Cert{
		Fingerprint:  "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		Subject:      "CN=prune.example.com",
		Issuer:       "CN=Test CA",
		NotBefore:    now.Add(-10 * 24 * time.Hour),
		NotAfter:     now.Add(100 * 24 * time.Hour),
		LifetimeDays: 110, KeyAlg: "ECDSA", KeyBits: 256, SigAlg: "ECDSA-SHA256",
	})
	if err2 != nil {
		t.Fatal(err2)
	}
	if err := s.SyncFindings(ctx, 1, domID, certID, nil, []x509eval.Finding{{Type: "exceeds_47_target", Detail: map[string]any{"lifetime_days": 110}}}, now); err != nil {
		t.Fatal(err)
	}

	v := x509eval.Verdict{Trust: "public", ChainValid: true, HostnameValid: true}

	for i := 1; i <= 5; i++ {
		id, err := s.BeginScan(ctx, "cli", nil)
		if err != nil {
			t.Fatal(err)
		}
		ep, err := s.UpsertEndpoint(ctx, domID, "prune.example.com", 443, "192.0.2.9", id)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.RecordObservation(ctx, id, domID, ep, certID, v, 0x0304, 0x1301, nil); err != nil {
			t.Fatal(err)
		}
		if err := s.FinishScan(ctx, id, "done", []byte(`{}`), ""); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.PruneObservations(ctx, 2); err != nil {
		t.Fatal(err)
	}
	var obs int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM observations`).Scan(&obs); err != nil {
		t.Fatal(err)
	}
	if obs != 2 {
		t.Fatalf("observations = %d, want 2", obs)
	}

	var certs int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM certs`).Scan(&certs); err != nil {
		t.Fatal(err)
	}
	if certs != 1 {
		t.Fatalf("certs = %d, want 1", certs)
	}

	var findings int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM findings`).Scan(&findings); err != nil {
		t.Fatal(err)
	}
	if findings != 1 {
		t.Fatalf("findings = %d, want 1", findings)
	}
}
