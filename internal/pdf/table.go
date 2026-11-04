package pdf

import "fmt"

// Align controls the horizontal alignment of a table cell.
type Align int

// Horizontal alignments available to table cells.
const (
	// AlignLeft places the cell text at the left edge of the column.
	AlignLeft Align = iota
	// AlignCenter centres the cell text in the column.
	AlignCenter
	// AlignRight places the cell text at the right edge of the column.
	AlignRight
)

// Column describes one column of a table.
type Column struct {
	// Title is the text of the header cell.
	Title string
	// Width is the width of the column in points.
	Width float64
	// Align controls the horizontal alignment of the cells.
	Align Align
}

// Table lays out rows of text in columns.
//
// Rows that no longer fit on the current page move to a new page, where the
// header is drawn again so that every page can be read on its own.
type Table struct {
	doc        *Doc
	columns    []Column
	offsets    []float64
	total      float64
	x          float64
	y          float64
	rowH       float64
	style      Style
	header     Style
	headerFill string
}

// NewTable starts a table with the given columns at (x, y).
//
// The header row is drawn straight away; the rows are added with Row.
func (d *Doc) NewTable(columns []Column, x, y float64) *Table {
	t := &Table{
		doc:        d,
		columns:    columns,
		x:          x,
		y:          y,
		rowH:       defaultRowHeight,
		style:      Style{Size: 9},
		header:     Style{Size: 9, Bold: true},
		headerFill: "#eaeef3",
	}
	t.layout()
	t.drawHeader()
	return t
}

// SetStyle sets the style used for the cells of the rows that follow.
func (t *Table) SetStyle(st Style) {
	t.style = st
}

// SetHeaderStyle sets the style used for the header row.
func (t *Table) SetHeaderStyle(st Style) {
	t.header = st
}

// SetHeaderFill sets the fill colour of the header row. An empty colour
// leaves the header unshaded.
func (t *Table) SetHeaderFill(color string) {
	t.headerFill = color
}

// SetRowHeight sets the height of a row in points.
func (t *Table) SetRowHeight(h float64) {
	if h > 0 {
		t.rowH = h
	}
}

// Y returns the vertical position just below the last row that was drawn.
func (t *Table) Y() float64 {
	return t.y
}

// Row draws one row of cells with the style of the table.
func (t *Table) Row(cells []string) {
	t.StyledRow(cells, t.style)
}

// StyledRow draws one row of cells with the given style.
//
// Cells that are missing from the row are left empty and cells beyond the
// last column are ignored.
func (t *Table) StyledRow(cells []string, st Style) {
	if t.y+t.rowH > t.doc.height-pageMargin {
		t.doc.NewPage()
		t.y = pageMargin
		t.drawHeader()
	}
	for i, col := range t.columns {
		text := ""
		if i < len(cells) {
			text = cells[i]
		}
		t.drawCellAt(i, col, text, st)
	}
	t.doc.Line(t.x, t.y+t.rowH, t.x+t.total, t.y+t.rowH, 0.3, "#dfe3e8")
	t.y += t.rowH
}

// layout computes the left edge of every column and the width of the table.
func (t *Table) layout() {
	t.offsets = make([]float64, len(t.columns))
	offset := t.x
	for i, col := range t.columns {
		t.offsets[i] = offset
		offset += col.Width
	}
	t.total = offset - t.x
}

// drawHeader draws the header row and moves the cursor below it.
func (t *Table) drawHeader() {
	if t.headerFill != "" {
		t.doc.Rect(t.x, t.y, t.total, t.rowH, t.headerFill)
	}
	for i, col := range t.columns {
		t.drawCellAt(i, col, col.Title, t.header)
	}
	t.doc.Line(t.x, t.y+t.rowH, t.x+t.total, t.y+t.rowH, 0.6, "#c7ced6")
	t.y += t.rowH
}

// drawCellAt draws one cell of the current row at the given column index.
func (t *Table) drawCellAt(i int, col Column, text string, st Style) {
	size := styleSize(st)
	width := textWidthIn(text, resolveFont(FontHelvetica, st.Bold, st.Italic), size)
	x := t.offsets[i]
	switch col.Align {
	case AlignCenter:
		x += (col.Width - width) / 2
	case AlignRight:
		x += col.Width - width
	}
	baseline := t.y + (t.rowH+size*0.72)/2
	t.doc.Text(text, x, baseline, st)
}

// String describes the table, which is handy in test failures.
func (t *Table) String() string {
	return fmt.Sprintf("pdf.Table{columns: %d, y: %.2f}", len(t.columns), t.y)
}
