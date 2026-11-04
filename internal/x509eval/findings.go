package x509eval

import (
	"time"

	"github.com/bamit99/47certificates/internal/phase"
)

// Finding is one reason a certificate needs attention. Findings overlap: a
// 486-day certificate from 2024 is both grandfathered and above the 47-day
// target.
type Finding struct {
	Type   string
	Detail map[string]any
}

// Finding type names. These strings are persisted and must not change.
const (
	ViolatesCurrentPhase = "violates_current_phase"
	GrandfatheredTooLong = "grandfathered_too_long"
	Exceeds47Target      = "exceeds_47_target"
	ExceedsNextPhase     = "exceeds_next_phase"
	ExpiresSoon          = "expires_soon"
	ExpiredServed        = "expired_served"
	HostnameMismatch     = "hostname_mismatch"
	UntrustedChain       = "untrusted_chain"
	PrivateTrust         = "private_trust"
)

// DaysLeft returns the whole days until t, rounded away from zero.
//
// Rounding up matters at the boundaries the schedule uses: a certificate with
// 30.9 days left is 31 days away, so it is not yet "expires soon" (the rule
// is not_after - now <= 30 days), and one with 14.9 days left is 15 days
// away, so it is not yet the high-severity case (which is <= 14 days).
func DaysLeft(t, now time.Time) int {
	d := t.Sub(now)
	day := 24 * time.Hour
	if d >= 0 {
		return int((d + day - 1) / day)
	}
	return -int((-d + day - 1) / day)
}

// Findings evaluates a certificate at now. c.LifetimeDays, when zero, is
// recomputed from the dates.
func Findings(c Cert, v Verdict, now time.Time) []Finding {
	lifetime := c.LifetimeDays
	if lifetime == 0 {
		lifetime = phase.LifetimeDays(c.NotBefore, c.NotAfter)
	}
	out := make([]Finding, 0, 4)

	// The CA/B Forum schedule governs publicly-trusted TLS certificates only.
	// An internal PKI sets its own lifetime policy, and a chain that does not
	// build to a public root is not evidence of one, so the four lifetime
	// findings are raised only for a confirmed public chain. A private or
	// untrusted certificate still gets its own finding and its expiry checks;
	// it simply is not measured against a rule that does not apply to it.
	if v.Trust == "public" {
		maxAtIssue := phase.For(c.NotBefore).MaxLifetimeDays
		current := phase.For(now)
		maxToday := current.MaxLifetimeDays

		if lifetime > maxAtIssue {
			out = append(out, Finding{Type: ViolatesCurrentPhase, Detail: map[string]any{
				"lifetime_days": lifetime, "max_days": maxAtIssue,
			}})
		}
		if lifetime > maxToday && c.NotBefore.Before(current.StartsAt) {
			out = append(out, Finding{Type: GrandfatheredTooLong, Detail: map[string]any{
				"lifetime_days": lifetime, "max_days": maxToday,
			}})
		}
		// The next phase forbids a shorter lifetime than today's. A
		// certificate above that limit is legal today but cannot be reissued
		// at its current length once the next phase begins, so its renewal
		// chain has to shorten before then.
		if next := phase.Next(now); next.Name != "" && lifetime > next.MaxLifetimeDays {
			out = append(out, Finding{Type: ExceedsNextPhase, Detail: map[string]any{
				"lifetime_days": lifetime, "max_days": next.MaxLifetimeDays,
				"phase": next.Name, "effective": next.StartsAt.UTC().Format("2006-01-02"),
			}})
		}
		if lifetime > 47 {
			out = append(out, Finding{Type: Exceeds47Target, Detail: map[string]any{
				"lifetime_days": lifetime, "target_days": 47,
			}})
		}
	}

	daysLeft := DaysLeft(c.NotAfter, now)
	switch {
	case c.NotAfter.Before(now):
		out = append(out, Finding{Type: ExpiredServed, Detail: map[string]any{"days_left": daysLeft}})
	case daysLeft <= 30:
		out = append(out, Finding{Type: ExpiresSoon, Detail: map[string]any{"days_left": daysLeft}})
	}

	switch v.Trust {
	case "private":
		out = append(out, Finding{Type: PrivateTrust, Detail: map[string]any{"reason": v.Reason}})
	case "untrusted":
		out = append(out, Finding{Type: UntrustedChain, Detail: map[string]any{"reason": v.Reason}})
	}
	if v.Trust != "" && !v.HostnameValid {
		out = append(out, Finding{Type: HostnameMismatch, Detail: map[string]any{}})
	}
	return out
}

// IsCertLevel reports whether a finding type is a property of the certificate
// alone, or of one endpoint that served it.
//
// Certificate-level findings (lifetime, expiry) belong to the certificate:
// one row per certificate, no matter how many endpoints serve it. Endpoint
// findings (hostname mismatch, chain trust) belong to the endpoint that
// produced them.
func IsCertLevel(t string) bool {
	switch t {
	case ViolatesCurrentPhase, GrandfatheredTooLong, Exceeds47Target, ExceedsNextPhase,
		ExpiresSoon, ExpiredServed:
		return true
	}
	return false
}

// SplitFindings separates certificate-level findings from endpoint-level ones.
func SplitFindings(fs []Finding) (certLevel, endpointLevel []Finding) {
	for _, f := range fs {
		if IsCertLevel(f.Type) {
			certLevel = append(certLevel, f)
			continue
		}
		endpointLevel = append(endpointLevel, f)
	}
	return certLevel, endpointLevel
}

// Bucket collapses overlapping findings into the one label the UI shows.
func Bucket(fs []Finding) string {
	best := "ok"
	for _, f := range fs {
		switch b := bucketOf(f.Type); {
		case b == "violation":
			return b
		case rank(b) > rank(best):
			best = b
		}
	}
	return best
}

func bucketOf(t string) string {
	switch t {
	case ViolatesCurrentPhase, ExpiredServed, HostnameMismatch, UntrustedChain:
		return "violation"
	case GrandfatheredTooLong:
		return "grandfathered"
	case ExceedsNextPhase:
		return "next_phase"
	case ExpiresSoon:
		return "expiring"
	case Exceeds47Target:
		return "target"
	case PrivateTrust:
		return "info"
	default:
		return "info"
	}
}

func rank(b string) int {
	switch b {
	case "violation":
		return 6
	case "grandfathered":
		return 5
	case "next_phase":
		return 4
	case "expiring":
		return 3
	case "target":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

// detailDays reads the days_left field of a finding detail map. The value
// arrives as an int when the finding was just computed and as a float64 when
// it was decoded from JSON, so both are accepted.
func detailDays(detail map[string]any) int {
	switch v := detail["days_left"].(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return 0
}

// Severity is derived at read time so a phase boundary does not require a
// migration.
func Severity(f Finding, now time.Time) string {
	switch f.Type {
	case ViolatesCurrentPhase, ExpiredServed:
		return "critical"
	case GrandfatheredTooLong, UntrustedChain:
		return "high"
	case ExceedsNextPhase:
		return "medium"
	case ExpiresSoon:
		if d := detailDays(f.Detail); d <= 14 {
			return "high"
		}
		return "medium"
	case HostnameMismatch:
		return "medium"
	default:
		return "info"
	}
}
