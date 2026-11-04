package pdf

import "strings"

// Font family names understood by TextFont.
const (
	// FontHelvetica is the sans-serif family (Helvetica, Arial).
	FontHelvetica = "Helvetica"
	// FontTimes is the serif family (Times, Times New Roman).
	FontTimes = "Times"
	// FontCourier is the monospace family (Courier).
	FontCourier = "Courier"
)

// resolveFont maps a family name plus a weight and a slant onto one of the
// PDF standard 14 fonts.
func resolveFont(family string, bold, italic bool) string {
	switch strings.ToLower(strings.TrimSpace(family)) {
	case "", "helvetica", "arial", "sans-serif", "sans":
		family = FontHelvetica
	case "times", "times-roman", "times new roman", "serif":
		family = FontTimes
	case "courier", "mono", "monospace":
		family = FontCourier
	}
	switch family {
	case FontTimes:
		switch {
		case bold && italic:
			return "Times-BoldItalic"
		case bold:
			return "Times-Bold"
		case italic:
			return "Times-Italic"
		default:
			return "Times-Roman"
		}
	case FontCourier:
		switch {
		case bold && italic:
			return "Courier-BoldOblique"
		case bold:
			return "Courier-Bold"
		case italic:
			return "Courier-Oblique"
		default:
			return "Courier"
		}
	default:
		switch {
		case bold && italic:
			return "Helvetica-BoldOblique"
		case bold:
			return "Helvetica-Bold"
		case italic:
			return "Helvetica-Oblique"
		default:
			return "Helvetica"
		}
	}
}

// The width tables below hold the Adobe AFM advance widths of the printable
// ASCII range, in 1/1000 of an em, for characters 32 to 126. The Helvetica
// family is used for the default text style, so its table is the one that
// has to be exact.
var (
	helveticaWidths = []int{
		278, 278, 355, 556, 556, 889, 667, 191, 333, 333,
		389, 584, 278, 333, 278, 278, 556, 556, 556, 556,
		556, 556, 556, 556, 556, 556, 278, 278, 584, 584,
		584, 556, 1015, 667, 667, 722, 722, 667, 611, 778,
		722, 278, 500, 667, 556, 833, 722, 778, 667, 778,
		722, 667, 611, 722, 667, 944, 667, 667, 611, 278,
		278, 278, 469, 556, 333, 556, 556, 500, 556, 556,
		278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
		556, 556, 333, 500, 278, 556, 500, 722, 500, 500,
		500, 334, 260, 334, 584,
	}

	helveticaBoldWidths = []int{
		278, 333, 474, 556, 556, 889, 722, 238, 333, 333,
		389, 584, 278, 333, 278, 278, 556, 556, 556, 556,
		556, 556, 556, 556, 556, 556, 333, 333, 584, 584,
		584, 611, 975, 722, 722, 722, 722, 667, 611, 778,
		722, 278, 556, 722, 611, 833, 722, 778, 667, 778,
		722, 667, 611, 722, 667, 944, 667, 667, 611, 333,
		278, 278, 333, 584, 556, 333, 556, 611, 556, 611,
		333, 611, 611, 278, 278, 556, 278, 889, 611, 611,
		611, 611, 389, 556, 333, 611, 556, 778, 556, 556,
		500, 389, 280, 389, 584,
	}

	timesRomanWidths = []int{
		250, 333, 408, 500, 500, 833, 778, 333, 333, 333,
		500, 564, 250, 333, 250, 278, 500, 500, 500, 500,
		500, 500, 500, 500, 500, 500, 278, 278, 564, 564,
		564, 444, 921, 722, 667, 667, 722, 611, 556, 722,
		722, 333, 389, 722, 611, 889, 722, 722, 556, 722,
		667, 556, 611, 722, 667, 944, 722, 722, 611, 333,
		278, 278, 469, 500, 333, 444, 500, 444, 500, 444,
		333, 500, 500, 278, 278, 500, 278, 778, 500, 500,
		500, 500, 333, 389, 278, 500, 500, 722, 500, 500,
		444, 480, 200, 480, 541,
	}

	timesBoldWidths = []int{
		250, 333, 555, 500, 500, 1000, 833, 333, 333, 333,
		500, 570, 250, 333, 250, 278, 500, 500, 500, 500,
		500, 500, 500, 500, 500, 500, 333, 333, 570, 570,
		570, 500, 930, 722, 667, 722, 722, 667, 611, 778,
		778, 389, 500, 778, 667, 944, 722, 778, 611, 778,
		722, 556, 667, 722, 667, 1000, 722, 722, 667, 333,
		278, 278, 581, 500, 333, 500, 556, 444, 556, 444,
		333, 500, 556, 278, 333, 556, 278, 833, 556, 500,
		556, 556, 444, 389, 333, 556, 500, 722, 500, 500,
		444, 394, 220, 394, 520,
	}
)

// courierWidth is the advance width of every character of the Courier
// family, which is monospaced.
const courierWidth = 600

// widthsFor returns the advance width table of a base font, or nil for the
// monospaced Courier family.
//
// The oblique faces of a family share the widths of the upright one, which is
// what the Adobe metrics do for Helvetica and a close enough approximation
// for Times.
func widthsFor(base string) []int {
	switch base {
	case "Helvetica-Bold", "Helvetica-BoldOblique":
		return helveticaBoldWidths
	case "Helvetica", "Helvetica-Oblique":
		return helveticaWidths
	case "Times-Roman", "Times-Italic":
		return timesRomanWidths
	case "Times-Bold", "Times-BoldItalic":
		return timesBoldWidths
	default:
		return nil
	}
}

// latin1Base maps the accented letters of Latin-1 onto the ASCII letter they
// are built from, so that they are measured with the width of that letter.
var latin1Base = map[rune]rune{
	'à': 'a', 'á': 'a', 'â': 'a', 'ã': 'a', 'ä': 'a', 'å': 'a', 'ā': 'a', 'ă': 'a', 'ą': 'a',
	'ç': 'c', 'ć': 'c', 'č': 'c',
	'ď': 'd', 'đ': 'd',
	'è': 'e', 'é': 'e', 'ê': 'e', 'ë': 'e', 'ē': 'e', 'ę': 'e', 'ě': 'e',
	'ğ': 'g',
	'ì': 'i', 'í': 'i', 'î': 'i', 'ï': 'i', 'ī': 'i', 'ı': 'i',
	'ł': 'l',
	'ñ': 'n', 'ń': 'n', 'ň': 'n',
	'ò': 'o', 'ó': 'o', 'ô': 'o', 'õ': 'o', 'ö': 'o', 'ø': 'o', 'ō': 'o', 'ő': 'o',
	'ř': 'r',
	'ś': 's', 'š': 's', 'ş': 's', 'ß': 's',
	'ť': 't', 'ţ': 't',
	'ù': 'u', 'ú': 'u', 'û': 'u', 'ü': 'u', 'ū': 'u', 'ů': 'u', 'ű': 'u',
	'ý': 'y', 'ÿ': 'y',
	'ź': 'z', 'ż': 'z', 'ž': 'z',
	'þ': 'p', 'ð': 'd', 'æ': 'a', 'œ': 'o', '×': 'x', '÷': 'x',
}

// textWidthIn returns the width of s in points when set in the given base
// font at the given size.
func textWidthIn(s string, base string, size float64) float64 {
	widths := widthsFor(base)
	total := 0
	for _, r := range s {
		total += charWidth(r, widths)
	}
	return float64(total) * size / 1000
}

// charWidth returns the advance width of a single character.
func charWidth(r rune, widths []int) int {
	if widths == nil {
		return courierWidth
	}
	if r >= 32 && r <= 126 {
		return widths[r-32]
	}
	if base, ok := latin1Base[r]; ok {
		return widths[base-32]
	}
	return widths['?'-32]
}
