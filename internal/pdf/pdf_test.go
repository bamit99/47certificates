package pdf

import (
	"bytes"
	"compress/zlib"
	"encoding/ascii85"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
)

// A rendered document has to look like a PDF file to any reader: the header
// comes first and the trailer comes last.
func TestBytesHasHeaderAndTrailer(t *testing.T) {
	d := New(A4Width, A4Height)
	d.Text("Certificate inventory", 40, 40, Style{Size: 14, Bold: true})

	b, err := d.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if !bytes.HasPrefix(b, []byte("%PDF-")) {
		t.Fatalf("missing %%PDF- header: %q", firstBytes(b))
	}
	if !bytes.HasPrefix(b, []byte("%PDF-1.")) {
		t.Errorf("unexpected version line: %q", firstBytes(b))
	}
	if !bytes.HasSuffix(bytes.TrimRight(b, " \t\r\n"), []byte("%%EOF")) {
		t.Fatalf("missing %%%%EOF trailer")
	}
}

// The file has to carry the objects a reader looks for.
func TestBytesContainsObjectMarkers(t *testing.T) {
	d := New(A4Width, A4Height)
	d.Text("hello", 40, 40, Style{})

	b, err := d.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	for _, marker := range []string{"/Type /Catalog", "/Type /Pages", "/Type /Page", "xref", "trailer"} {
		if !bytes.Contains(b, []byte(marker)) {
			t.Errorf("output does not contain %q", marker)
		}
	}
}

// A document that was never drawn on still has to render as one valid page.
func TestEmptyDocumentHasOnePage(t *testing.T) {
	d := New(A4Width, A4Height)
	b, err := d.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if d.PageCount() != 1 {
		t.Fatalf("PageCount = %d, want 1", d.PageCount())
	}
	if !bytes.Contains(b, []byte("/Count 1")) {
		t.Errorf("page tree does not report one page")
	}
	if !bytes.Contains(b, []byte("%%EOF")) {
		t.Errorf("empty document is not a complete file")
	}
}

// New starts the first page, so every new page is one further down.
func TestPageCountAndNewPage(t *testing.T) {
	d := New(A4Width, A4Height)
	if got := d.PageCount(); got != 1 {
		t.Fatalf("PageCount after New = %d, want 1", got)
	}
	for want := 2; want <= 4; want++ {
		got := d.NewPage()
		if got != want {
			t.Errorf("NewPage = %d, want %d", got, want)
		}
		if got := d.PageCount(); got != want {
			t.Errorf("PageCount = %d, want %d", got, want)
		}
	}
}

// The page index a new page reports is the page it actually landed on.
func TestNewPageIndexMatchesPageCount(t *testing.T) {
	d := New(LetterWidth, LetterHeight)
	if got := d.NewPage(); got != d.PageCount() {
		t.Errorf("NewPage = %d, PageCount = %d", got, d.PageCount())
	}
}

// Parentheses and backslashes are part of certificate data, so they have to
// survive the trip into the file without breaking the structure.
func TestTextWithParenthesesAndBackslashes(t *testing.T) {
	d := New(A4Width, A4Height)
	d.Text(`CN=Weird (Name) \ Corp`, 40, 40, Style{})

	b, err := d.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if !bytes.Contains(b, []byte(`\(Name\)`)) {
		t.Errorf("parentheses are not escaped in the output")
	}
	if !bytes.Contains(b, []byte(`\\`)) {
		t.Errorf("backslash is not escaped in the output")
	}
	if !bytes.Contains(b, []byte("%PDF-")) || !bytes.HasSuffix(bytes.TrimRight(b, " \t\r\n"), []byte("%%EOF")) {
		t.Errorf("escaping broke the file structure")
	}
}

// The same document has to render to the same bytes every time, otherwise
// reports cannot be compared or cached.
func TestBytesAreStable(t *testing.T) {
	d := New(A4Width, A4Height)
	d.Text("CN=Weird (Name) \\ Corp", 40, 40, Style{Bold: true})
	d.Line(40, 60, 500, 60, 0.5, "#cccccc")
	d.Rect(40, 70, 200, 20, "#eaeef3")

	first, err := d.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	second, err := d.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if len(first) != len(second) {
		t.Fatalf("byte count changed between renders: %d then %d", len(first), len(second))
	}
	if !bytes.Equal(first, second) {
		t.Errorf("two renders of the same document differ")
	}
}

// A table with more rows than fit on a page continues on the next one.
func TestTableFlowsAcrossPages(t *testing.T) {
	d := New(A4Width, A4Height)
	tbl := d.NewTable([]Column{
		{Title: "Host", Width: 300},
		{Title: "Issuer", Width: 200},
	}, 40, 40)

	for i := 0; i < 200 && d.PageCount() < 2; i++ {
		tbl.Row([]string{"host.example.com", "Example CA"})
	}
	if got := d.PageCount(); got != 2 {
		t.Fatalf("PageCount = %d, want 2", got)
	}
	if tbl.Y() <= 40 {
		t.Errorf("table did not advance: y = %v", tbl.Y())
	}

	b, err := d.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if got := bytes.Count(b, []byte("(Host)")); got != 2 {
		t.Errorf("header drawn %d times, want 2 (once per page)", got)
	}
	if got := bytes.Count(b, []byte("/Type /Page ")); got != 2 {
		t.Errorf("file holds %d page objects, want 2", got)
	}
}

// The header of a table repeats on the page the rows continue on.
func TestTableHeaderRepeatsOnSecondPage(t *testing.T) {
	d := New(A4Width, A4Height)
	tbl := d.NewTable([]Column{{Title: "Serial", Width: 200}}, 40, 40)
	for i := 0; i < 200 && d.PageCount() < 2; i++ {
		tbl.Row([]string{"0123abcd"})
	}
	b, err := d.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if got := bytes.Count(b, []byte("(Serial)")); got != 2 {
		t.Errorf("header appears %d times, want 2", got)
	}
}

// Text is measured with the real widths of a proportional font, so a longer
// string is wider and two strings of the same length are about the same
// wide.
func TestTextWidthIsProportional(t *testing.T) {
	d := New(A4Width, A4Height)
	st := Style{Size: 10}

	short := d.TextWidth("Hello", st)
	long := d.TextWidth("Hello, wonderful world", st)
	if long <= short {
		t.Fatalf("longer string is not wider: %v vs %v", long, short)
	}
	if short <= 0 {
		t.Fatalf("TextWidth returned %v", short)
	}

	// Helvetica advance widths: H 722, e 556, l 222, l 222, o 556 per 1000 em.
	if want := 2278 * 10 / 1000.0; abs(short-want) > 0.01 {
		t.Errorf("TextWidth(\"Hello\") = %v, want %v", short, want)
	}
	// A proportional font is not a fixed pitch one.
	if d.TextWidth("iiiii", st) == d.TextWidth("MMMMM", st) {
		t.Errorf("widths do not depend on the characters")
	}
}

// The measured width has to match what is drawn, otherwise a table column
// that is right aligned would drift.
func TestTextWidthScalesWithSize(t *testing.T) {
	d := New(A4Width, A4Height)
	one := d.TextWidth("Report", Style{Size: 10})
	two := d.TextWidth("Report", Style{Size: 20})
	if abs(two-2*one) > 0.01 {
		t.Errorf("width at 20pt = %v, want %v", two, 2*one)
	}
	if got := d.TextWidth("Report", Style{}); abs(got-one) > 0.01 {
		t.Errorf("default size width = %v, want %v", got, one)
	}
}

// The whole file has to stay 7-bit ASCII, because the certificate data it
// carries is not always printable.
func TestOutputIsPureASCII(t *testing.T) {
	d := New(A4Width, A4Height)
	d.Text("Naïve CN=Ünïcode ✓", 40, 40, Style{})
	d.Text("naïve café", 40, 60, Style{Bold: true, Color: "#b91c1c"})
	d.Line(40, 70, 500, 70, 0.5, "#cccccc")
	d.Rect(40, 80, 100, 10, "#eaeef3")

	b, err := d.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	for i, c := range b {
		if c > 127 {
			t.Fatalf("byte %d is not ASCII: %#x", i, c)
		}
	}
}

// A compressed content stream still has to decode to the text that was
// drawn, and the file still has to be plain ASCII.
func TestCompressedStreamRoundTrips(t *testing.T) {
	d := New(A4Width, A4Height)
	d.SetCompression(true)
	d.Text("CN=Weird (Name)", 40, 40, Style{})

	b, err := d.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	for i, c := range b {
		if c > 127 {
			t.Fatalf("byte %d is not ASCII: %#x", i, c)
		}
	}
	if !bytes.Contains(b, []byte("/Filter [/ASCII85Decode /FlateDecode]")) {
		t.Fatalf("stream is not marked as compressed")
	}

	raw := extractStream(t, b)
	plain := inflate(t, raw)
	if !bytes.Contains(plain, []byte(`\(Name\)`)) {
		t.Errorf("decoded stream does not hold the escaped text: %q", plain)
	}
}

// Rules and filled rectangles have to reach the content stream.
func TestLineAndRectReachTheContentStream(t *testing.T) {
	d := New(A4Width, A4Height)
	d.Line(40, 100, 500, 100, 1.2, "#b91c1c")
	d.Rect(40, 120, 200, 18, "#eaeef3")

	b, err := d.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if !bytes.Contains(b, []byte(" l\nS")) && !bytes.Contains(b, []byte(" l S")) {
		t.Errorf("no stroked line in the content stream")
	}
	if !bytes.Contains(b, []byte(" re f")) {
		t.Errorf("no filled rectangle in the content stream")
	}
}

// The colour and the thickness of a rule are separate operands. If they are
// mixed up, the reader paints the line in the wrong colour.
func TestLineColourAndThicknessAreSeparateOperands(t *testing.T) {
	d := New(A4Width, A4Height)
	d.Line(40, 100, 500, 100, 0.8, "#808080")
	d.Rect(40, 120, 200, 18, "#eaeef3")

	b, err := d.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if want := "q 0.502 0.502 0.502 RG 0.8 w 40 741.89 m 500 741.89 l S Q"; !bytes.Contains(b, []byte(want)) {
		t.Errorf("rule is not written as %q", want)
	}
	if want := "q 0.918 0.933 0.953 rg 40 703.89 200 18 re f Q"; !bytes.Contains(b, []byte(want)) {
		t.Errorf("rectangle is not written as %q", want)
	}
}

// The cross-reference table has to point at the real objects, otherwise a
// reader rejects the file.
func TestCrossReferenceOffsetsAreCorrect(t *testing.T) {
	d := New(A4Width, A4Height)
	d.Text("offset check", 40, 40, Style{})
	d.NewPage()
	d.Text("second page", 40, 40, Style{})

	b, err := d.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	idx := bytes.Index(b, []byte("\nxref\n"))
	if idx < 0 {
		t.Fatalf("no xref table")
	}
	rest := b[idx+len("\nxref\n"):]
	// The subsection header names the first object and the number of
	// entries, the entries themselves are 20 bytes each.
	nl := bytes.Index(rest, []byte("\n"))
	if nl < 0 {
		t.Fatalf("truncated xref table")
	}
	var first, count int
	if _, err := fmt.Sscanf(string(rest[:nl]), "%d %d", &first, &count); err != nil {
		t.Fatalf("malformed xref header %q", rest[:nl])
	}
	if first != 0 || count < 2 {
		t.Fatalf("xref header = %d %d", first, count)
	}
	entries := rest[nl+1:]
	for i := 1; i < count; i++ {
		// The first record belongs to the free object 0, so the record of
		// object i is the i-th one.
		entry := entries[i*20 : i*20+20]
		if len(entry) != 20 {
			t.Fatalf("entry %d is %d bytes long, want 20", i, len(entry))
		}
		offset, err := strconv.Atoi(strings.TrimSpace(string(entry[:10])))
		if err != nil {
			t.Fatalf("entry %d is malformed: %q", i, entry)
		}
		want := []byte(fmt.Sprintf("%d 0 obj", i))
		if !bytes.HasPrefix(b[offset:], want) {
			t.Errorf("entry %d points at %q, want %q", i, b[offset:offset+10], want)
		}
	}
}

// extractStream returns the encoded body of the first content stream in a
// PDF file.
func extractStream(t *testing.T, b []byte) string {
	t.Helper()
	start := bytes.Index(b, []byte("stream\n"))
	if start < 0 {
		t.Fatalf("no stream in the file")
	}
	start += len("stream\n")
	end := bytes.Index(b[start:], []byte("\nendstream"))
	if end < 0 {
		t.Fatalf("unterminated stream")
	}
	return string(b[start : start+end])
}

// inflate decodes an ASCII85 wrapped zlib stream.
func inflate(t *testing.T, encoded string) []byte {
	t.Helper()
	// The Go decoder does not know the end of data marker of the PDF
	// filter, so it is stripped before decoding.
	encoded = strings.TrimPrefix(encoded, "<~")
	encoded = strings.TrimSuffix(encoded, "~>")
	r := ascii85.NewDecoder(strings.NewReader(encoded))
	zr, err := zlib.NewReader(r)
	if err != nil {
		t.Fatalf("zlib reader: %v", err)
	}
	defer zr.Close()
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return out
}

// abs returns the absolute difference of two numbers.
func abs(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

// firstBytes returns the head of a byte slice for a failure message.
func firstBytes(b []byte) []byte {
	if len(b) > 16 {
		return b[:16]
	}
	return b
}
