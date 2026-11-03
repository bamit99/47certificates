package x509eval

import (
	"testing"
	"time"
)

var testNow = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func certWithLifetime(nb time.Time, days int) Cert {
	return Cert{
		NotBefore:    nb,
		NotAfter:     nb.Add(time.Duration(days) * 24 * time.Hour),
		LifetimeDays: days,
	}
}

func types(fs []Finding) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[f.Type] = true
	}
	return m
}

func TestFindingsAreIndependent(t *testing.T) {
	// 397 days was legal under P0, so this cert is grandfathered, not a
	// violation, but still above the 47-day target.
	c := certWithLifetime(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), 397)
	got := types(Findings(c, Verdict{Trust: "public", ChainValid: true}, testNow))
	if !got["grandfathered_too_long"] || !got["exceeds_47_target"] {
		t.Fatalf("%v", got)
	}
	if got["violates_current_phase"] {
		t.Fatal("pre-2026 cert within 398 days must not violate the current phase")
	}
}

func TestViolatesCurrentPhase(t *testing.T) {
	c := certWithLifetime(time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), 300)
	got := types(Findings(c, Verdict{Trust: "public", ChainValid: true}, testNow))
	if !got["violates_current_phase"] {
		t.Fatalf("%v", got)
	}
}

func TestBoundaryCertBelongsToLaterPhase(t *testing.T) {
	// Issued exactly on the P1 boundary with 200 days: compliant.
	c := certWithLifetime(time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), 200)
	got := types(Findings(c, Verdict{Trust: "public", ChainValid: true}, testNow))
	if got["violates_current_phase"] || got["grandfathered_too_long"] {
		t.Fatalf("%v", got)
	}
	// 201 days on the same date violates.
	c2 := certWithLifetime(time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), 201)
	got2 := types(Findings(c2, Verdict{Trust: "public", ChainValid: true}, testNow))
	if !got2["violates_current_phase"] {
		t.Fatalf("%v", got2)
	}
}

func TestExpiryFindings(t *testing.T) {
	soon := Cert{NotBefore: testNow.Add(-100 * 24 * time.Hour), NotAfter: testNow.Add(10 * 24 * time.Hour), LifetimeDays: 110}
	if got := types(Findings(soon, Verdict{Trust: "public", ChainValid: true}, testNow)); !got["expires_soon"] {
		t.Fatalf("%v", got)
	}
	expired := Cert{NotBefore: testNow.Add(-200 * 24 * time.Hour), NotAfter: testNow.Add(-time.Hour), LifetimeDays: 200}
	got := types(Findings(expired, Verdict{Trust: "public", ChainValid: true}, testNow))
	if !got["expired_served"] {
		t.Fatalf("%v", got)
	}
	if got["expires_soon"] {
		t.Fatal("expired certs are not merely expiring soon")
	}
}

func TestTrustFindings(t *testing.T) {
	c := certWithLifetime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), 90)
	if got := types(Findings(c, Verdict{Trust: "private"}, testNow)); !got["private_trust"] {
		t.Fatalf("%v", got)
	}
	if got := types(Findings(c, Verdict{Trust: "untrusted", Reason: "incomplete"}, testNow)); !got["untrusted_chain"] {
		t.Fatalf("%v", got)
	}
	if got := types(Findings(c, Verdict{Trust: "public", HostnameValid: false}, testNow)); !got["hostname_mismatch"] {
		t.Fatalf("%v", got)
	}
}

func TestBucketOrder(t *testing.T) {
	both := []Finding{{Type: "exceeds_47_target"}, {Type: "grandfathered_too_long"}}
	if got := Bucket(both); got != "grandfathered" {
		t.Fatalf("got %q", got)
	}
	all := []Finding{{Type: "exceeds_47_target"}, {Type: "expires_soon"}, {Type: "violates_current_phase"}}
	if got := Bucket(all); got != "violation" {
		t.Fatalf("got %q", got)
	}
	if got := Bucket(nil); got != "ok" {
		t.Fatalf("got %q", got)
	}
}

func TestSeverity(t *testing.T) {
	nb := testNow.Add(-100 * 24 * time.Hour)
	c := Cert{NotBefore: nb, NotAfter: testNow.Add(10 * 24 * time.Hour), LifetimeDays: 110}
	f := Finding{Type: "expires_soon", Detail: map[string]any{"days_left": 10}}
	if got := Severity(f, testNow); got != "high" {
		t.Fatalf("10 days: %q", got)
	}
	f.Detail["days_left"] = 25
	if got := Severity(f, testNow); got != "medium" {
		t.Fatalf("25 days: %q", got)
	}
	if got := Severity(Finding{Type: "violates_current_phase"}, testNow); got != "critical" {
		t.Fatalf("violation: %q", got)
	}
	if got := Severity(Finding{Type: "exceeds_47_target"}, testNow); got != "info" {
		t.Fatalf("target: %q", got)
	}
	_ = c
}
