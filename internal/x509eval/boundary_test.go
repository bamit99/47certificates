package x509eval

import (
	"testing"
	"time"
)

// The day count is rounded up, so the boundaries the schedule uses land on
// the right side: 30.9 days is 31 days away and is not yet "expires soon",
// 14.9 days is 15 days away and is not yet the high-severity case.
func TestDaysLeftRoundsUp(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		offset time.Duration
		want   int
	}{
		{0, 0},
		{time.Hour, 1},
		{24 * time.Hour, 1},
		{24*time.Hour + time.Hour, 2},
		{30 * 24 * time.Hour, 30},
		{30*24*time.Hour + time.Hour, 31},
		{14 * 24 * time.Hour, 14},
		{14*24*time.Hour + time.Hour, 15},
		{-time.Hour, -1},
		{-24 * time.Hour, -1},
		{-25 * time.Hour, -2},
	}
	for _, c := range cases {
		if got := DaysLeft(now.Add(c.offset), now); got != c.want {
			t.Errorf("DaysLeft(+%v) = %d, want %d", c.offset, got, c.want)
		}
	}
}

// A certificate expiring in 30.9 days is not yet expiring; one in 29 days is.
func TestExpiresSoonBoundary(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	cert := Cert{
		NotBefore: now.AddDate(0, 0, -60),
		NotAfter:  now.Add(30*24*time.Hour + time.Hour),
	}
	if hasType(Findings(cert, Verdict{Trust: "public", ChainValid: true, HostnameValid: true}, now), ExpiresSoon) {
		t.Error("a certificate 30.9 days out must not be expires_soon")
	}
	cert.NotAfter = now.Add(29 * 24 * time.Hour)
	if !hasType(Findings(cert, Verdict{Trust: "public", ChainValid: true, HostnameValid: true}, now), ExpiresSoon) {
		t.Error("a certificate 29 days out must be expires_soon")
	}
}

// The severity thresholds follow the day count.
func TestExpiresSoonSeverityBoundary(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	cert := Cert{NotBefore: now.AddDate(0, 0, -60), NotAfter: now.Add(14 * 24 * time.Hour)}
	fm := Findings(cert, Verdict{Trust: "public", ChainValid: true, HostnameValid: true}, now)
	if got := Severity(findType(t, fm, ExpiresSoon), now); got != "high" {
		t.Errorf("severity at 14 days = %q, want high", got)
	}
	cert.NotAfter = now.Add(15 * 24 * time.Hour)
	fm = Findings(cert, Verdict{Trust: "public", ChainValid: true, HostnameValid: true}, now)
	if got := Severity(findType(t, fm, ExpiresSoon), now); got != "medium" {
		t.Errorf("severity at 15 days = %q, want medium", got)
	}
}

func findType(t *testing.T, fs []Finding, ftype string) Finding {
	t.Helper()
	for _, f := range fs {
		if f.Type == ftype {
			return f
		}
	}
	t.Fatalf("finding %q not present in %v", ftype, fs)
	return Finding{}
}

// Certificate-level findings are the ones that depend only on the
// certificate; endpoint-level findings depend on the served chain.
func TestSplitFindings(t *testing.T) {
	certLevel, endpointLevel := SplitFindings([]Finding{
		{Type: ViolatesCurrentPhase},
		{Type: GrandfatheredTooLong},
		{Type: Exceeds47Target},
		{Type: ExpiresSoon},
		{Type: ExpiredServed},
		{Type: HostnameMismatch},
		{Type: UntrustedChain},
		{Type: PrivateTrust},
	})
	if len(certLevel) != 5 {
		t.Errorf("cert-level findings = %d, want 5", len(certLevel))
	}
	if len(endpointLevel) != 3 {
		t.Errorf("endpoint-level findings = %d, want 3", len(endpointLevel))
	}
}

func hasType(fs []Finding, t string) bool {
	for _, f := range fs {
		if f.Type == t {
			return true
		}
	}
	return false
}
