// Package pdf writes small PDF files with nothing but the Go standard
// library.
//
// The writer is deliberately minimal: it emits PDF 1.4 files that use the
// standard 14 fonts, so no font has to be embedded and no external asset is
// needed. It provides what a certificate inventory report needs - text in
// several sizes and weights, rules, filled rectangles and tables that flow
// across pages.
//
// Coordinates use a top-left origin with y growing downwards, the way report
// layouts are normally described; the flip into PDF's bottom-left user space
// happens when the page is written.
package pdf

import (
	"bytes"
	"fmt"
	"strings"
)

// Page sizes in points.
const (
	// A4Width is the width of an A4 page in points.
	A4Width = 595.28
	// A4Height is the height of an A4 page in points.
	A4Height = 841.89
	// LetterWidth is the width of a US Letter page in points.
	LetterWidth = 612.0
	// LetterHeight is the height of a US Letter page in points.
	LetterHeight = 792.0
)

const (
	// defaultFontSize is used when a style leaves Size at zero.
	defaultFontSize = 10.0
	// lineHeightFactor is the line box height as a multiple of the font size.
	lineHeightFactor = 1.2
	// pageMargin is the free space kept at the top and bottom of a page.
	pageMargin = 40.0
	// defaultRowHeight is the height of a table row in points.
	defaultRowHeight = 18.0
)

// Style describes how text is drawn.
type Style struct {
	// Size is the font size in points. Zero means 10.
	Size float64
	// Bold selects the bold weight of the base font.
	Bold bool
	// Italic selects the oblique face of the base font.
	Italic bool
	// Color is a hex colour like "#111111" or "#b91c1c". Empty means black.
	Color string
}

// page is one page of the document plus the content stream drawn on it.
type page struct {
	content bytes.Buffer
}

// Doc accumulates pages.
//
// A document always has at least one page: New creates the first one, so
// PageCount reports 1 before anything is drawn and the first call to NewPage
// returns 2.
type Doc struct {
	width    float64
	height   float64
	pages    []*page
	cur      *page
	cursorX  float64
	cursorY  float64
	fonts    map[string]string
	fontList []string
	compress bool
}

// New returns a document with the given page size (use A4Width/A4Height or
// LetterWidth/LetterHeight). The document starts with one empty page.
//
// A size of zero or less for either dimension falls back to A4.
func New(width, height float64) *Doc {
	if width <= 0 {
		width = A4Width
	}
	if height <= 0 {
		height = A4Height
	}
	d := &Doc{
		width:  width,
		height: height,
		fonts:  make(map[string]string),
	}
	d.NewPage()
	return d
}

// SetCompression turns zlib compression of the page content streams on or
// off.
//
// Compression is off by default so that the file stays plain text and can be
// read with a text editor. When it is on, the compressed stream is wrapped in
// ASCII85 so that the file itself still consists of 7-bit ASCII only.
func (d *Doc) SetCompression(on bool) {
	d.compress = on
}

// Cursor returns the position the text cursor has reached, which is the
// start of the next line after the last piece of text drawn.
func (d *Doc) Cursor() (float64, float64) {
	return d.cursorX, d.cursorY
}

// Text draws one line of text at the current position and advances the
// cursor by the line height. It returns the x,y where the text was drawn.
//
// The baseline of the text sits on y, and the base font is the Helvetica
// family in the weight and slant requested by st.
func (d *Doc) Text(s string, x, y float64, st Style) (float64, float64) {
	return d.TextFont(s, x, y, FontHelvetica, st)
}

// TextFont draws one line of text like Text but picks the base font family
// from family, which is FontHelvetica, FontTimes or FontCourier.
func (d *Doc) TextFont(s string, x, y float64, family string, st Style) (float64, float64) {
	if d.cur == nil {
		d.NewPage()
	}
	size := styleSize(st)
	base := resolveFont(family, st.Bold, st.Italic)
	res := d.fontResource(base)
	r, g, b := parseColor(st.Color)
	fmt.Fprintf(&d.cur.content,
		"q %s rg BT /%s %s Tf 1 0 0 1 %s %s Tm (%s) Tj ET Q\n",
		rgb(r, g, b), res, num(size), num(x), num(d.pdfY(y)), escapeString(s))
	d.cursorX = x + textWidthIn(s, base, size)
	d.cursorY = y + size*lineHeightFactor
	return x, y
}

// TextWidth returns the width in points that s would occupy at the given
// style.
//
// The measurement uses the AFM advance widths of the Helvetica family, the
// base font of the default style, so the result is the real width of the
// string rather than an estimate of a fixed pitch font.
func (d *Doc) TextWidth(s string, st Style) float64 {
	return textWidthIn(s, resolveFont(FontHelvetica, st.Bold, st.Italic), styleSize(st))
}

// Line draws a rule from (x1,y1) to (x2,y2) with the given thickness in
// points (0 means 0.5) and hex colour (empty means black).
func (d *Doc) Line(x1, y1, x2, y2, thickness float64, color string) {
	if d.cur == nil {
		d.NewPage()
	}
	if thickness <= 0 {
		thickness = 0.5
	}
	r, g, b := parseColor(color)
	fmt.Fprintf(&d.cur.content,
		"q %s RG %s w %s %s m %s %s l S Q\n",
		rgb(r, g, b), num(thickness),
		num(x1), num(d.pdfY(y1)), num(x2), num(d.pdfY(y2)))
}

// Rect draws a filled rectangle with the given hex fill colour.
//
// The rectangle starts at the top-left corner (x,y) and is w points wide and
// h points tall.
func (d *Doc) Rect(x, y, w, h float64, fill string) {
	if d.cur == nil {
		d.NewPage()
	}
	r, g, b := parseColor(fill)
	fmt.Fprintf(&d.cur.content, "q %s rg %s %s %s %s re f Q\n",
		rgb(r, g, b), num(x), num(d.pdfY(y+h)), num(w), num(h))
}

// NewPage starts a new page and returns the index of the page that was
// started (1-based).
func (d *Doc) NewPage() int {
	p := &page{}
	d.pages = append(d.pages, p)
	d.cur = p
	d.cursorX = 0
	d.cursorY = 0
	return len(d.pages)
}

// PageCount returns the number of pages.
func (d *Doc) PageCount() int {
	return len(d.pages)
}

// Bytes renders the document and returns the PDF bytes. It must start with
// the %PDF- header and end with the %%EOF trailer.
//
// The output is pure 7-bit ASCII and is byte for byte stable for the same
// document, so it can be hashed or compared.
func (d *Doc) Bytes() ([]byte, error) {
	if len(d.pages) == 0 {
		d.NewPage()
	}

	// Object layout: 1 is the catalogue, 2 the page tree, then one object per
	// font, then a page object and its content stream for every page.
	fonts := d.fontList
	fontObj := make(map[string]int, len(fonts))
	for i, base := range fonts {
		fontObj[base] = 3 + i
	}
	firstPageObj := 3 + len(fonts)
	total := 2 + len(fonts) + 2*len(d.pages)

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	buf.WriteString("% 47certificates report writer\n")

	offsets := make([]int, total+1)
	writeObj := func(num int, body string) {
		offsets[num] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", num, body)
	}

	// The catalogue points at the page tree.
	writeObj(1, "<< /Type /Catalog /Pages 2 0 R >>")

	// The page tree lists every page in order.
	kids := make([]string, 0, len(d.pages))
	for i := range d.pages {
		kids = append(kids, fmt.Sprintf("%d 0 R", firstPageObj+2*i))
	}
	writeObj(2, fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), len(d.pages)))

	// One font object per base font that was actually used.
	for _, base := range fonts {
		writeObj(fontObj[base], fmt.Sprintf(
			"<< /Type /Font /Subtype /Type1 /BaseFont /%s /Encoding /WinAnsiEncoding >>", base))
	}

	// The pages themselves.
	for i, p := range d.pages {
		pageObj := firstPageObj + 2*i
		contentObj := pageObj + 1

		resources := make([]string, 0, len(fonts))
		for _, base := range fonts {
			resources = append(resources, fmt.Sprintf("/%s %d 0 R", d.fonts[base], fontObj[base]))
		}
		writeObj(pageObj, fmt.Sprintf(
			"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %s %s] /Resources << /Font << %s >> >> /Contents %d 0 R >>",
			num(d.width), num(d.height), strings.Join(resources, " "), contentObj))

		body, err := encodeStream(p.content.Bytes(), d.compress)
		if err != nil {
			return nil, err
		}
		dict := fmt.Sprintf("<< /Length %d", len(body))
		if d.compress {
			dict += " /Filter [/ASCII85Decode /FlateDecode]"
		}
		dict += " >>"
		writeObj(contentObj, fmt.Sprintf("%s\nstream\n%s\nendstream", dict, body))
	}

	// The cross-reference table and the trailer.
	xref := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n", total+1)
	buf.WriteString("0000000000 65535 f \n")
	for i := 1; i <= total; i++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", total+1, xref)

	return buf.Bytes(), nil
}

// pdfY converts a y coordinate with a top-left origin into the bottom-left
// user space PDF works in.
func (d *Doc) pdfY(y float64) float64 {
	return d.height - y
}

// fontResource returns the resource name of a base font, adding the font to
// the document the first time it is used.
func (d *Doc) fontResource(base string) string {
	if res, ok := d.fonts[base]; ok {
		return res
	}
	res := fmt.Sprintf("F%d", len(d.fontList)+1)
	d.fonts[base] = res
	d.fontList = append(d.fontList, base)
	return res
}

// styleSize returns the font size of a style, substituting the default when
// the style does not set one.
func styleSize(st Style) float64 {
	if st.Size <= 0 {
		return defaultFontSize
	}
	return st.Size
}
