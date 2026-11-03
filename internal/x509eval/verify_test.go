package x509eval

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/amit/47certificates/internal/roots"
	"github.com/amit/47certificates/internal/testutil"
)

func TestVerifyPublicChain(t *testing.T) {
	ca, caKey := testutil.NewCA(t)
	der, _ := testutil.NewLeaf(t, ca, caKey, testutil.LeafOpts{DNSNames: []string{"a.example.com"}})
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	v := Verify(der, nil, "a.example.com", pool, time.Now())
	if v.Trust != "public" || !v.HostnameValid || !v.ChainValid {
		t.Fatalf("%+v", v)
	}
}

func TestVerifyPrivateRootIsPrivateNotUntrusted(t *testing.T) {
	ca, caKey := testutil.NewCA(t) // deliberately not in the public pool
	der, _ := testutil.NewLeaf(t, ca, caKey, testutil.LeafOpts{DNSNames: []string{"a.example.com"}})
	v := Verify(der, [][]byte{ca.Raw}, "a.example.com", roots.Pool(), time.Now())
	if v.Trust != "private" || v.Reason != "private_root" {
		t.Fatalf("%+v", v)
	}
}

func TestVerifyExpiredStillClassifiesTrust(t *testing.T) {
	ca, caKey := testutil.NewCA(t)
	nb := time.Now().Add(-48 * time.Hour)
	der, _ := testutil.NewLeaf(t, ca, caKey, testutil.LeafOpts{
		DNSNames:  []string{"a.example.com"},
		NotBefore: nb,
		NotAfter:  nb.Add(24 * time.Hour),
	})
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	v := Verify(der, nil, "a.example.com", pool, time.Now())
	if v.Trust != "public" {
		t.Fatalf("%+v", v)
	}
	if v.ChainValid {
		t.Fatal("expired chain must not be valid at now")
	}
}

func TestVerifyHostnameMismatch(t *testing.T) {
	ca, caKey := testutil.NewCA(t)
	der, _ := testutil.NewLeaf(t, ca, caKey, testutil.LeafOpts{DNSNames: []string{"a.example.com"}})
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	v := Verify(der, nil, "b.example.com", pool, time.Now())
	if v.HostnameValid {
		t.Fatal("mismatched hostname must be invalid")
	}
	if v.Trust != "public" {
		t.Fatalf("%+v", v)
	}
}

func TestVerifyIncompleteChain(t *testing.T) {
	ca, caKey := testutil.NewCA(t)
	der, _ := testutil.NewLeaf(t, ca, caKey, testutil.LeafOpts{DNSNames: []string{"a.example.com"}})
	// Intermediate is neither served nor a self-signed root.
	v := Verify(der, nil, "a.example.com", roots.Pool(), time.Now())
	if v.Trust != "untrusted" || v.Reason != "incomplete" {
		t.Fatalf("%+v", v)
	}
}
