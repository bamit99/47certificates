package x509eval

import (
	"testing"
	"time"

	"github.com/amit/47certificates/internal/testutil"
)

func TestParseMetadata(t *testing.T) {
	ca, caKey := testutil.NewCA(t)
	nb := time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC)
	der, _ := testutil.NewLeaf(t, ca, caKey, testutil.LeafOpts{
		DNSNames:  []string{"a.example.com"},
		NotBefore: nb,
		NotAfter:  nb.Add(397 * 24 * time.Hour),
	})
	c, err := Parse(der, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.LifetimeDays != 397 {
		t.Fatalf("lifetime = %d", c.LifetimeDays)
	}
	if len(c.Fingerprint) != 64 {
		t.Fatalf("fingerprint = %q", c.Fingerprint)
	}
	if len(c.SANs) != 1 || c.SANs[0] != "a.example.com" {
		t.Fatalf("sans = %v", c.SANs)
	}
	if c.KeyAlg != "ECDSA" || c.KeyBits != 256 {
		t.Fatalf("key = %s/%d", c.KeyAlg, c.KeyBits)
	}
	if c.Subject == "" || c.Issuer == "" || c.SigAlg == "" {
		t.Fatalf("%+v", c)
	}
	if !c.NotAfter.Equal(nb.Add(397 * 24 * time.Hour)) {
		t.Fatalf("notAfter = %s", c.NotAfter)
	}
}

func TestParseBackdatedNotBefore(t *testing.T) {
	ca, caKey := testutil.NewCA(t)
	nb := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	der, _ := testutil.NewLeaf(t, ca, caKey, testutil.LeafOpts{
		DNSNames:  []string{"a.example.com"},
		NotBefore: nb.Add(-48 * time.Hour),
		NotAfter:  nb.Add(199 * 24 * time.Hour),
	})
	c, err := Parse(der, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.LifetimeDays != 201 {
		t.Fatalf("lifetime = %d", c.LifetimeDays)
	}
}
