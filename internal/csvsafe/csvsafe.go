// Package csvsafe neutralises values that spreadsheet software would treat
// as formulas.
package csvsafe

// Cell returns s with a leading apostrophe when it would be interpreted as a
// formula by a spreadsheet application.
//
// Certificate subjects, issuers and hostnames come from the network. A
// subject like "=cmd|'/c calc'!A1" is legal in a certificate, and opening
// the exported CSV in Excel or LibreOffice would otherwise execute it.
func Cell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// Row applies Cell to every field of a row.
func Row(fields []string) []string {
	out := make([]string, len(fields))
	for i, f := range fields {
		out[i] = Cell(f)
	}
	return out
}
