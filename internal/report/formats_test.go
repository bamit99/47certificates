package report

import (
	"bytes"
	"context"
	"testing"
)

// Every report is generated in every format.
func TestEveryFormatIsGenerated(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	s1, err := st.BeginScan(ctx, "cli", nil)
	if err != nil {
		t.Fatal(err)
	}
	nb := testNow().AddDate(0, 0, -5)
	addCert(t, st, s1, "a.example.com", fp48, nb, 48, []string{"a.example.com"})
	if err := st.FinishScan(ctx, s1, "done", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	id, _ := st.CreateReport(ctx, s1, string(Inventory), nil, nil)
	a, err := Generate(ctx, st, id, s1, Inventory, "", testNow())
	if err != nil {
		t.Fatal(err)
	}
	if len(a.HTML) == 0 {
		t.Error("no HTML")
	}
	if len(a.CSV) == 0 {
		t.Error("no CSV")
	}
	if len(a.JSON) == 0 {
		t.Error("no JSON")
	}
	if len(a.Markdown) == 0 {
		t.Error("no Markdown")
	}
	if len(a.PDF) == 0 {
		t.Error("no PDF")
	}
	if !bytes.HasPrefix(a.PDF, []byte("%PDF-")) {
		t.Errorf("the PDF does not start with the header: %q", a.PDF[:min(8, len(a.PDF))])
	}
}

// The Markdown carries the counts, the certificates and the scope note.
func TestMarkdownCarriesTheContent(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	s1, _ := st.BeginScan(ctx, "cli", nil)
	nb := testNow().AddDate(0, 0, -5)
	addCert(t, st, s1, "a.example.com", fp48, nb, 48, []string{"a.example.com"})
	if err := st.FinishScan(ctx, s1, "done", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	id, _ := st.CreateReport(ctx, s1, string(Executive), nil, nil)
	a, err := Generate(ctx, st, id, s1, Executive, "", testNow())
	if err != nil {
		t.Fatal(err)
	}
	md := string(a.Markdown)
	for _, want := range []string{
		"# 47-day TLS certificate impact",
		"publicly-trusted certificates only",
		"a.example.com",
		"Phase exposure",
		"include: example.com",
	} {
		if !bytes.Contains(a.Markdown, []byte(want)) {
			t.Errorf("the Markdown is missing %q", want)
		}
	}
	_ = md
}

// The best format is chosen per report kind.
func TestDefaultFormatPerKind(t *testing.T) {
	cases := map[Kind]string{
		Executive: "pdf",
		Worklist:  "csv",
		Inventory: "csv",
		Domain:    "md",
	}
	for kind, want := range cases {
		if got := DefaultFormat(kind); got != want {
			t.Errorf("DefaultFormat(%s) = %q, want %q", kind, got, want)
		}
	}
}
