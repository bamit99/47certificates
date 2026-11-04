package pdf

import (
	"bytes"
	"compress/zlib"
	"encoding/ascii85"
	"fmt"
	"strconv"
	"strings"
)

// escapeString turns a Go string into the body of a PDF literal string.
//
// The three characters that end or escape a literal string are escaped, and
// every byte outside the printable ASCII range is written as a three digit
// octal escape, so the whole file stays 7-bit ASCII.
func escapeString(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r > 255 {
			// No WinAnsi code point exists for this rune.
			b.WriteByte('?')
			continue
		}
		c := byte(r)
		switch c {
		case '(':
			b.WriteString(`\(`)
		case ')':
			b.WriteString(`\)`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if c < 32 || c > 126 {
				fmt.Fprintf(&b, "\\%03o", c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	return b.String()
}

// parseColor turns a hex colour such as "#b91c1c" into the red, green and
// blue components PDF expects in the range 0 to 1.
//
// Three digit colours are accepted as well, and anything that cannot be
// parsed becomes black.
func parseColor(s string) (float64, float64, float64) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "#")
	if len(s) == 3 {
		s = string([]byte{s[0], s[0], s[1], s[1], s[2], s[2]})
	}
	if len(s) != 6 {
		return 0, 0, 0
	}
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return 0, 0, 0
	}
	return float64((v>>16)&0xff) / 255, float64((v>>8)&0xff) / 255, float64(v&0xff) / 255
}

// rgb formats a colour as the three operands of a PDF colour operator.
func rgb(r, g, b float64) string {
	return num(r) + " " + num(g) + " " + num(b)
}

// num formats a number for a PDF operand, dropping the noise digits that
// are not needed to place a coordinate on the page.
func num(v float64) string {
	s := strconv.FormatFloat(v, 'f', 3, 64)
	if strings.Contains(s, ".") {
		s = strings.TrimRight(s, "0")
		s = strings.TrimSuffix(s, ".")
	}
	if s == "" || s == "-" || s == "-0" {
		return "0"
	}
	return s
}

// encodeStream renders the body of a content stream.
//
// With compression off the stream is written as plain text. With compression
// on it is deflated and then ASCII85 encoded, which keeps the file free of
// binary bytes while still shrinking long reports.
func encodeStream(data []byte, compress bool) (string, error) {
	if !compress {
		return string(data), nil
	}
	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	if _, err := zw.Write(data); err != nil {
		return "", fmt.Errorf("compress content stream: %w", err)
	}
	if err := zw.Close(); err != nil {
		return "", fmt.Errorf("compress content stream: %w", err)
	}
	var abuf bytes.Buffer
	enc := ascii85.NewEncoder(&abuf)
	if _, err := enc.Write(zbuf.Bytes()); err != nil {
		return "", fmt.Errorf("encode content stream: %w", err)
	}
	if err := enc.Close(); err != nil {
		return "", fmt.Errorf("encode content stream: %w", err)
	}
	abuf.WriteString("~>")
	return abuf.String(), nil
}
