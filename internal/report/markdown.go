package report

import (
	"fmt"
	"strings"
	"time"
)

// renderMarkdown writes the report as Markdown.
//
// Markdown is the format that reads best in a ticket, a commit message or a
// chat: it needs no viewer and it keeps the tables readable.
func renderMarkdown(kind Kind, v reportView) []byte {
	var b strings.Builder
	title := map[Kind]string{
		Executive: "47-day TLS certificate impact — executive summary",
		Worklist:  "47-day TLS certificate worklist",
		Inventory: "Certificate inventory",
		Domain:    "Certificate inventory for " + v.Domain,
	}[kind]

	fmt.Fprintf(&b, "# %s\n\n", title)
	fmt.Fprintf(&b, "- Report #%d\n", v.ReportID)
	fmt.Fprintf(&b, "- Scan #%d (started %s)\n", v.ScanID, v.ScanTime.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "- Generated %s by 47c %s\n", v.GeneratedAt.UTC().Format(time.RFC3339), v.Version)
	fmt.Fprintf(&b, "- CA/B phase %s (max lifetime %d days)\n", v.Phase.Name, v.Phase.MaxLifetimeDays)
	if v.Scope != "" {
		fmt.Fprintf(&b, "- Scope: %s\n", v.Scope)
	}
	fmt.Fprintf(&b, "- Delta: %s\n", v.Delta.Sentence)
	fmt.Fprintf(&b, "\n> %s\n", v.Notice)

	switch kind {
	case Executive:
		fmt.Fprintf(&b, "\n## Counts\n\n")
		b.WriteString("| Bucket | Certificates |\n|---|---:|\n")
		for _, name := range []string{"violation", "grandfathered", "next_phase", "expiring", "target", "info", "ok"} {
			fmt.Fprintf(&b, "| %s | %d |\n", name, v.Counts[name])
		}
		fmt.Fprintf(&b, "| **total** | **%d** |\n", v.Total)

		fmt.Fprintf(&b, "\n## Phase exposure\n\n")
		b.WriteString("| Phase | Issued | Exceeding phase max |\n|---|---:|---:|\n")
		for _, g := range v.PhaseGroups {
			fmt.Fprintf(&b, "| %s | %d | %d |\n", g.Name, g.Count, g.Exceeding)
		}

		if len(v.Longest) > 0 {
			fmt.Fprintf(&b, "\n## Longest-lived certificates\n\n")
			b.WriteString("| Lifetime | Subject | Fingerprint | Bucket |\n|---:|---|---|---|\n")
			for _, o := range v.Longest {
				fmt.Fprintf(&b, "| %dd | %s | `%s` | %s |\n", o.LifetimeDays, mdEscape(o.Subject), o.ShortFP, o.Bucket)
			}
		}
		if len(v.Expiring) > 0 {
			fmt.Fprintf(&b, "\n## Expiring within 30 days\n\n")
			b.WriteString("| Expires | Subject | Endpoints | Bucket |\n|---|---|---|---|\n")
			for _, o := range v.Expiring {
				fmt.Fprintf(&b, "| %s | %s | %s | %s |\n",
					o.NotAfter.Format("2006-01-02"), mdEscape(o.Subject), mdEscape(endpointList(o)), o.Bucket)
			}
		}
	case Worklist, Inventory, Domain:
		fmt.Fprintf(&b, "\n## Certificates\n\n")
		b.WriteString("| Subject | Issuer | Expires | Lifetime | Trust | Bucket | Severity | Endpoints |\n")
		b.WriteString("|---|---|---|---:|---|---|---|---|\n")
		for _, o := range v.Public {
			fmt.Fprintf(&b, "| %s | %s | %s | %dd | %s | %s | %s | %s |\n",
				mdEscape(o.Subject), mdEscape(o.Issuer),
				o.NotAfter.Format("2006-01-02"), o.LifetimeDays,
				o.Trust, o.Bucket, o.Severity, mdEscape(endpointList(o)))
		}
	}

	if len(v.Private) > 0 {
		fmt.Fprintf(&b, "\n## Non-public observations (%d)\n\n", len(v.Private))
		b.WriteString("| Subject | Trust | Endpoints |\n|---|---|---|\n")
		for _, o := range v.Private {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", mdEscape(o.Subject), o.Trust, mdEscape(endpointList(o)))
		}
	}

	return []byte(b.String())
}

// mdEscape makes a value safe inside a Markdown table cell.
func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
