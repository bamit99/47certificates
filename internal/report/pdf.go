package report

import (
	"fmt"

	"github.com/amit/47certificates/internal/pdf"
)

// pdfMargins are the page margins in points.
const (
	pdfMargin    = 36.0
	pdfPageWidth = pdf.A4Width
	pdfPageHeight = pdf.A4Height
)

// renderPDF writes the report as a PDF.
//
// The PDF is the format for a report meant to be read and printed, so it
// carries the same content as the HTML: the counts, the phase exposure and
// the certificates.
func renderPDF(kind Kind, v reportView) ([]byte, error) {
	doc := pdf.New(pdfPageWidth, pdfPageHeight)
	head := pdf.Style{Size: 16, Bold: true}
	sub := pdf.Style{Size: 9, Color: "#555555"}
	bold := pdf.Style{Size: 10, Bold: true}

	title := map[Kind]string{
		Executive: "47-day TLS certificate impact",
		Worklist:  "47-day TLS certificate worklist",
		Inventory: "Certificate inventory",
		Domain:    "Certificate inventory for " + v.Domain,
	}[kind]

	y := pdfMargin + 20
	doc.Text(title, pdfMargin, y, head)
	y += 26
	doc.Text(fmt.Sprintf("Report #%d  ·  scan #%d  ·  generated %s  ·  47c %s",
		v.ReportID, v.ScanID, v.GeneratedAt.UTC().Format("2006-01-02 15:04 UTC"), v.Version),
		pdfMargin, y, sub)
	y += 14
	doc.Text(fmt.Sprintf("CA/B phase %s (max %d days)  ·  delta: %s",
		v.Phase.Name, v.Phase.MaxLifetimeDays, v.Delta.Sentence), pdfMargin, y, sub)
	y += 14
	if v.Scope != "" {
		doc.Text("Scope: "+v.Scope, pdfMargin, y, sub)
		y += 14
	}
	doc.Text(v.Notice, pdfMargin, y, sub)
	y += 24

	switch kind {
	case Executive:
		y = pdfSection(doc, "Counts", y, bold)
		counts := doc.NewTable([]pdf.Column{
			{Title: "Bucket", Width: 240},
			{Title: "Certificates", Width: 100, Align: pdf.AlignRight},
		}, pdfMargin, y)
		for _, name := range []string{"violation", "grandfathered", "expiring", "target", "info", "ok"} {
			counts.Row([]string{name, fmt.Sprint(v.Counts[name])})
		}
		counts.Row([]string{"total", fmt.Sprint(v.Total)})
		y = counts.Y() + 22

		y = pdfSection(doc, "Phase exposure", y, bold)
		phases := doc.NewTable([]pdf.Column{
			{Title: "Phase", Width: 80},
			{Title: "Issued", Width: 100, Align: pdf.AlignRight},
			{Title: "Exceeding phase max", Width: 140, Align: pdf.AlignRight},
		}, pdfMargin, y)
		for _, g := range v.PhaseGroups {
			phases.Row([]string{g.Name, fmt.Sprint(g.Count), fmt.Sprint(g.Exceeding)})
		}
		y = phases.Y() + 22

		if len(v.Expiring) > 0 {
			y = pdfSection(doc, "Expiring within 30 days", y, bold)
			exp := doc.NewTable([]pdf.Column{
				{Title: "Expires", Width: 80},
				{Title: "Subject", Width: 230},
				{Title: "Lifetime", Width: 60, Align: pdf.AlignRight},
				{Title: "Bucket", Width: 70},
			}, pdfMargin, y)
			for _, o := range v.Expiring {
				exp.Row([]string{
					o.NotAfter.Format("2006-01-02"),
					pdfTruncate(o.Subject, 42),
					fmt.Sprintf("%dd", o.LifetimeDays),
					o.Bucket,
				})
			}
			y = exp.Y() + 22
		}
	default:
		y = pdfSection(doc, "Certificates", y, bold)
		cols := []pdf.Column{
			{Title: "Subject", Width: 175},
			{Title: "Issuer", Width: 130},
			{Title: "Expires", Width: 70},
			{Title: "Life", Width: 38, Align: pdf.AlignRight},
			{Title: "Bucket", Width: 60},
		}
		tbl := doc.NewTable(cols, pdfMargin, y)
		for _, o := range v.Public {
			tbl.Row([]string{
				pdfTruncate(o.Subject, 34),
				pdfTruncate(o.Issuer, 26),
				o.NotAfter.Format("2006-01-02"),
				fmt.Sprintf("%dd", o.LifetimeDays),
				o.Bucket,
			})
		}
		y = tbl.Y() + 22
	}

	if len(v.Private) > 0 {
		y = pdfSection(doc, fmt.Sprintf("Non-public observations (%d)", len(v.Private)), y, bold)
		tbl := doc.NewTable([]pdf.Column{
			{Title: "Subject", Width: 230},
			{Title: "Trust", Width: 70},
			{Title: "Endpoints", Width: 200},
		}, pdfMargin, y)
		for _, o := range v.Private {
			tbl.Row([]string{pdfTruncate(o.Subject, 44), o.Trust, pdfTruncate(endpointList(o), 40)})
		}
		y = tbl.Y() + 22
	}

	// The footer of every page.
	footer := fmt.Sprintf("47c %s  ·  report #%d  ·  scan #%d  ·  %s",
		v.Version, v.ReportID, v.ScanID, v.GeneratedAt.UTC().Format("2006-01-02"))
	for p := 1; p <= doc.PageCount(); p++ {
		doc.Text(footer, pdfMargin, pdfPageHeight-pdfMargin+8, pdf.Style{Size: 8, Color: "#777777"})
	}

	return doc.Bytes()
}

// pdfSection draws a heading and returns the new y.
func pdfSection(doc *pdf.Doc, title string, y float64, st pdf.Style) float64 {
	doc.Text(title, pdfMargin, y, st)
	return y + 20
}

// pdfTruncate shortens a value to fit a table cell.
func pdfTruncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
