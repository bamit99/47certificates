package x509eval

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/bamit99/47certificates/internal/roots"
	"github.com/bamit99/47certificates/internal/testutil"
)

// A self-signed leaf served on its own is a private PKI, not a broken
// chain: it is informational rather than a violation.
func TestVerifySelfSignedLeafIsPrivate(t *testing.T) {
	der, _ := testutil.NewSelfSigned(t, "a.example.com")
	v := Verify(der, nil, "a.example.com", roots.Pool(), time.Now())
	if v.Trust != "private" || v.Reason != "private_root" {
		t.Fatalf("%+v", v)
	}
}

// A leaf signed by a CA that is not in the public bundle is private when the
// server sends the root, and untrusted when it does not.
func TestVerifyPrivateRootNeedsNoAnchor(t *testing.T) {
	ca, caKey := testutil.NewCA(t)
	der, _ := testutil.NewLeaf(t, ca, caKey, testutil.LeafOpts{DNSNames: []string{"a.example.com"}})
	v := Verify(der, [][]byte{ca.Raw}, "a.example.com", roots.Pool(), time.Now())
	if v.Trust != "private" || v.Reason != "private_root" {
		t.Fatalf("%+v", v)
	}

	// Without the root the chain cannot build at all.
	v = Verify(der, nil, "a.example.com", roots.Pool(), time.Now())
	if v.Trust != "untrusted" || v.Reason != "incomplete" {
		t.Fatalf("%+v", v)
	}
}

// A public chain is still public.
func TestVerifyPublicChainStillPublic(t *testing.T) {
	ca, caKey := testutil.NewCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	der, _ := testutil.NewLeaf(t, ca, caKey, testutil.LeafOpts{DNSNames: []string{"a.example.com"}})
	v := Verify(der, nil, "a.example.com", pool, time.Now())
	if v.Trust != "public" {
		t.Fatalf("%+v", v)
	}
}
