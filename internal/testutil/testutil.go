// Package testutil generates certificates for tests. It is not used by the
// production binary.
package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// LeafOpts controls a generated leaf certificate.
type LeafOpts struct {
	DNSNames        []string
	NotBefore       time.Time
	NotAfter        time.Time
	IsCA            bool
	IssuingCertURLs []string
}

// NewCA returns a self-signed ECDSA P-256 CA.
func NewCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "47c test root", Organization: []string{"47c test"}},
		NotBefore:             time.Now().Add(-10 * 365 * 24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// NewLeaf signs a leaf with ca and returns its DER and private key.
func NewLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, opts LeafOpts) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nb := opts.NotBefore
	if nb.IsZero() {
		nb = time.Now().Add(-time.Hour)
	}
	na := opts.NotAfter
	if na.IsZero() {
		na = time.Now().Add(90 * 24 * time.Hour)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: firstDNS(opts.DNSNames), Organization: []string{"47c test"}},
		NotBefore:             nb,
		NotAfter:              na,
		DNSNames:              opts.DNSNames,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  opts.IsCA,
		IssuingCertificateURL: opts.IssuingCertURLs,
	}
	if opts.IsCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

func firstDNS(names []string) string {
	if len(names) == 0 {
		return "localhost"
	}
	return names[0]
}
