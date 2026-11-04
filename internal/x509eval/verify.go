package x509eval

import (
	"crypto/x509"
	"time"
)

// Verdict is the outcome of checking one served chain against the public trust
// store. Trust is "public", "private", "untrusted", or "" when unknown.
type Verdict struct {
	Trust         string
	ChainValid    bool
	HostnameValid bool
	Reason        string
}

// Verify classifies the chain and checks hostname and validity.
//
// Trust is decided inside the certificate's own validity window so that an
// expired certificate is still reported as "public": expiry is a finding, not
// a trust failure. ChainValid, by contrast, is evaluated at now.
func Verify(leafDER []byte, chainDER [][]byte, host string, roots *x509.CertPool, now time.Time) Verdict {
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return Verdict{Trust: "", Reason: "parse_error"}
	}

	inter := x509.NewCertPool()
	var servedRoot *x509.Certificate
	for _, der := range chainDER {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		inter.AddCert(c)
		if c.IsCA && c.CheckSignatureFrom(c) == nil {
			servedRoot = c
		}
	}
	// A self-signed leaf is its own root. A server that sends only such a
	// leaf is running a private PKI, which is informational, not a trust
	// failure: the chain is not "incomplete", there is simply no public
	// anchor.
	if servedRoot == nil && isSelfSigned(leaf) {
		servedRoot = leaf
	}

	v := Verdict{HostnameValid: leaf.VerifyHostname(host) == nil}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		DNSName:       host,
		CurrentTime:   now,
	}); err == nil {
		v.ChainValid = true
	}

	// Trust path, ignoring hostname and time: try a few instants inside the
	// leaf's window so a backdated leaf is not rejected because its issuer was
	// not yet valid at notBefore.
	trustPool := roots
	for _, at := range candidateTimes(leaf) {
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:         trustPool,
			Intermediates: inter,
			CurrentTime:   at,
		}); err == nil {
			v.Trust = "public"
			return v
		}
	}
	if servedRoot != nil {
		private := x509.NewCertPool()
		private.AddCert(servedRoot)
		for _, at := range candidateTimes(leaf) {
			if _, err := leaf.Verify(x509.VerifyOptions{
				Roots:         private,
				Intermediates: inter,
				CurrentTime:   at,
			}); err == nil {
				v.Trust = "private"
				v.Reason = "private_root"
				return v
			}
		}
	}
	v.Trust = "untrusted"
	if servedRoot != nil {
		v.Reason = "untrusted_root"
	} else {
		v.Reason = "incomplete"
	}
	return v
}

// isSelfSigned reports whether the certificate signed itself.
func isSelfSigned(c *x509.Certificate) bool {
	return c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

// candidateTimes returns instants likely to sit inside both the leaf's and its
// issuers' validity windows.
func candidateTimes(leaf *x509.Certificate) []time.Time {
	start := leaf.NotBefore.Add(time.Minute)
	end := leaf.NotAfter.Add(-time.Minute)
	if end.Before(start) {
		return []time.Time{leaf.NotBefore}
	}
	mid := start.Add(end.Sub(start) / 2)
	now := time.Now()
	seen := map[int64]bool{}
	out := make([]time.Time, 0, 4)
	for _, t := range []time.Time{start, mid, end, now} {
		if seen[t.Unix()] {
			continue
		}
		seen[t.Unix()] = true
		out = append(out, t)
	}
	return out
}
