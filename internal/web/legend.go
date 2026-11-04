package web

// legendItem explains one status in the plain language an operator needs.
type legendItem struct {
	Label string
	What  string
}

// bucketLegend explains the impact buckets the dashboard counts.
var bucketLegend = []legendItem{
	{"Violation", "A rule is broken now: the lifetime is too long for the phase it was issued under, the certificate has expired and is still being served, the name does not match, or the chain does not anchor in a public root."},
	{"Grandfathered", "The certificate is longer than today's limit but was issued before the current phase began, so it was legal then. A renewal has to be shorter."},
	{"Too long for the next phase", "Legal today, but the next phase shortens the limit. The renewal chain has to come down before that date, and the sooner the automation is in place the less painful it is."},
	{"Expiring", "The certificate expires within 30 days and needs renewing."},
	{"Above 47-day target", "The certificate is longer than the 47 days the 2029 phase will allow. It is on the worklist for 2029, not broken today."},
	{"Informational", "A private certificate, which is out of scope for the 47-day analysis."},
	{"Compliant", "Nothing to do: the lifetime fits the phase and the chain is sound."},
}

// findingLegend explains the finding types.
var findingLegend = []legendItem{
	{"violates_current_phase", "The lifetime exceeds what the phase in force at issuance allows. This should not exist."},
	{"grandfathered_too_long", "Legal when issued, too long for today's limit. A renewal must be shorter."},
	{"exceeds_next_phase", "Legal today, too long for the phase that comes next. The renewal chain has to shorten before that date."},
	{"exceeds_47_target", "Longer than the 47 days the 2029 phase will allow."},
	{"expires_soon", "Expires within 30 days."},
	{"expired_served", "Expired, and still being served."},
	{"hostname_mismatch", "The certificate does not cover the name that was asked for."},
	{"untrusted_chain", "The chain does not build to a public root."},
	{"private_trust", "The chain anchors in a private root. Informational."},
}

// severityLegend explains the severities.
var severityLegend = []legendItem{
	{"critical", "Act now: a rule is broken."},
	{"high", "Act soon: it will break, or it was legal only because of a phase that has since changed."},
	{"medium", "Plan for it: renewal or a mismatch."},
	{"info", "For information only."},
}
