package x509eval

import (
	"testing"
	"time"

	"github.com/bamit99/47certificates/internal/phase"
)

// The next phase is what a certificate has to be reissued at before it can
// keep its current lifetime.
func TestNextPhase(t *testing.T) {
	cases := []struct {
		at   time.Time
		want string
	}{
		{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), "P1"},
		{time.Date(2026, 3, 14, 23, 59, 59, 0, time.UTC), "P1"},
		{time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), "P2"},
		{time.Date(2027, 3, 15, 0, 0, 0, 0, time.UTC), "P3"},
	}
	for _, c := range cases {
		got := phase.Next(c.at)
		if got.Name != c.want {
			t.Errorf("Next(%s) = %q, want %q", c.at.Format("2006-01-02"), got.Name, c.want)
		}
	}
	// After the last phase there is no further step.
	if got := phase.Next(time.Date(2029, 3, 15, 0, 0, 0, 0, time.UTC)); got.Name != "" {
		t.Errorf("Next after the last phase = %q, want none", got.Name)
	}
}

// A certificate that is legal today but longer than the next phase allows
// must be reported: its renewal chain has to come down before that date.
func TestExceedsNextPhaseIsReported(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	// 150 days: legal under today's 200-day limit, too long for the 100-day
	// limit that arrives in 2027.
	cert := Cert{
		NotBefore:    now.AddDate(0, 0, -30),
		NotAfter:     now.AddDate(0, 0, 120),
		LifetimeDays: 150,
	}
	fm := Findings(cert, Verdict{Trust: "public", ChainValid: true, HostnameValid: true}, now)
	f := findType(t, fm, ExceedsNextPhase)
	if f.Detail["max_days"] != 100 {
		t.Errorf("max_days = %v, want 100", f.Detail["max_days"])
	}
	if f.Detail["phase"] != "P2" {
		t.Errorf("phase = %v, want P2", f.Detail["phase"])
	}
	if f.Detail["effective"] != "2027-03-15" {
		t.Errorf("effective = %v, want 2027-03-15", f.Detail["effective"])
	}
	// It is a medium-severity item: real work, but nothing broken today.
	if got := Severity(f, now); got != "medium" {
		t.Errorf("severity = %q, want medium", got)
	}
}

// A certificate already compliant with the next phase has nothing to report
// about it.
func TestNoExceedsNextPhaseWhenCompliant(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	cert := Cert{
		NotBefore:    now.AddDate(0, 0, -30),
		NotAfter:     now.AddDate(0, 0, 60),
		LifetimeDays: 90,
	}
	fm := Findings(cert, Verdict{Trust: "public", ChainValid: true, HostnameValid: true}, now)
	for _, f := range fm {
		if f.Type == ExceedsNextPhase {
			t.Fatal("a 90-day certificate is compliant with the 100-day next phase")
		}
	}
}

// The next-phase bucket ranks between grandfathered and expiring: a
// certificate that is legal today but too long tomorrow matters more than one
// that is merely too long for 2029.
func TestNextPhaseBucketRanking(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	cert := Cert{
		NotBefore:    now.AddDate(0, 0, -30),
		NotAfter:     now.AddDate(0, 0, 120),
		LifetimeDays: 150,
	}
	fm := Findings(cert, Verdict{Trust: "public", ChainValid: true, HostnameValid: true}, now)
	if got := Bucket(fm); got != "next_phase" {
		t.Errorf("bucket = %q, want next_phase", got)
	}
	// It outranks the pure 2029 target.
	targetOnly := []Finding{{Type: Exceeds47Target}}
	if Bucket(targetOnly) == Bucket(fm) {
		t.Error("the next-phase bucket must outrank the 2029 target")
	}
}
