// Package x509eval turns raw certificate bytes into the facts the scanner
// stores and the UI explains.
package x509eval

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/amit/47certificates/internal/phase"
)

// Cert holds the persisted facts about one leaf certificate.
type Cert struct {
	Fingerprint  string
	Subject      string
	Issuer       string
	NotBefore    time.Time
	NotAfter     time.Time
	LifetimeDays int
	KeyAlg       string
	KeyBits      int
	SigAlg       string
	SANs         []string
	IsCA         bool
	IssuingURLs  []string
	OCSPURL      string
	CRLURL       string
	// ARIURL is always empty in v1: the renewal-info base is published in the
	// CA's ACME directory, not in the certificate. Kept for a later lookup.
	ARIURL string
	Raw    []byte
}

// Parse extracts metadata from a leaf DER. chainDER is accepted so callers can
// pass the sibling certs without a second signature, but parsing is per leaf.
func Parse(leafDER []byte, _ [][]byte) (Cert, error) {
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return Cert{}, fmt.Errorf("x509eval: parse leaf: %w", err)
	}
	sum := sha256.Sum256(leafDER)
	c := Cert{
		Fingerprint:  hex.EncodeToString(sum[:]),
		Subject:      leaf.Subject.String(),
		Issuer:       leaf.Issuer.String(),
		NotBefore:    leaf.NotBefore.UTC(),
		NotAfter:     leaf.NotAfter.UTC(),
		LifetimeDays: phase.LifetimeDays(leaf.NotBefore, leaf.NotAfter),
		KeyAlg:       leaf.PublicKeyAlgorithm.String(),
		KeyBits:      keyBits(leaf.PublicKey),
		SigAlg:       leaf.SignatureAlgorithm.String(),
		SANs:         append([]string{}, leaf.DNSNames...),
		IsCA:         leaf.IsCA,
		IssuingURLs:  append([]string{}, leaf.IssuingCertificateURL...),
		Raw:          append([]byte{}, leafDER...),
	}
	if len(leaf.OCSPServer) > 0 {
		c.OCSPURL = leaf.OCSPServer[0]
	}
	if len(leaf.CRLDistributionPoints) > 0 {
		c.CRLURL = leaf.CRLDistributionPoints[0]
	}
	return c, nil
}

func keyBits(pub any) int {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}
