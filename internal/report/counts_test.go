package report

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/amit/47certificates/internal/scope"
	"github.com/amit/47certificates/internal/x509eval"
)

// A certificate served by several endpoints is one certificate: the report
// counts it once, not once per endpoint.
func TestReportCountsCertificatesNotEndpoints(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	s1, err := st.BeginScan(ctx, "cli", nil)
	if err != nil {
		t.Fatal(err)
	}
	nb := testNow().AddDate(0, 0, -5)
	certID := addCert(t, st, s1, "a.example.com", fpCompliant, nb, 90, []string{"a.example.com"})
	for _, host := range []string{"b.example.com", "c.example.com", "d.example.com"} {
		ep, err := st.UpsertEndpoint(ctx, testDomainID, host, 443, "192.0.2.9", s1)
		if err != nil {
			t.Fatal(err)
		}
		v := x509eval.Verdict{Trust: "public", ChainValid: true, HostnameValid: true}
		if err := st.RecordObservation(ctx, s1, testDomainID, ep, certID, v, 0x0304, 0x1301, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.FinishScan(ctx, s1, "done", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	id, _ := st.CreateReport(ctx, s1, string(Inventory), nil, nil)
	a, err := Generate(ctx, st, id, s1, Inventory, "", testNow())
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(a.JSON, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Total != 1 {
		t.Fatalf("total = %d, want 1", doc.Total)
	}
	// The endpoint sheet still lists every endpoint.
	epCount := bytes.Count(a.CSV, []byte("example.com"))
	if epCount < 4 {
		t.Fatalf("endpoint sheet lost endpoints: %d occurrences", epCount)
	}
}

// Every format embeds the provenance the spec requires.
func TestEveryFormatEmbedsProvenance(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	s1, err := st.BeginScan(ctx, "cli", nil)
	if err != nil {
		t.Fatal(err)
	}
	nb := testNow().AddDate(0, 0, -5)
	addCert(t, st, s1, "a.example.com", fpCompliant, nb, 47, []string{"a.example.com"})
	if err := st.FinishScan(ctx, s1, "done", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	id, _ := st.CreateReport(ctx, s1, string(Inventory), nil, nil)
	a, err := Generate(ctx, st, id, s1, Inventory, "", testNow())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"publicly-trusted certificates only",
		"generated_at=",
		"scan_id=",
		"scope=",
		"version=",
	} {
		if !bytes.Contains(a.CSV, []byte(want)) {
			t.Errorf("CSV missing %q", want)
		}
	}
	var doc map[string]any
	if err := json.Unmarshal(a.JSON, &doc); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"notice", "generated_at", "scan_id", "scan_time", "scope", "version"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("JSON missing %q", key)
		}
	}
	if notice, _ := doc["notice"].(string); !bytes.Contains([]byte(notice), []byte("publicly-trusted certificates only")) {
		t.Errorf("JSON notice = %q", notice)
	}
}

// The delta compares against the previous report of the same kind, using the
// snapshot stored with it. Pruning the observations does not change it.
func TestDeltaSurvivesPrunedObservations(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	nb := testNow().AddDate(0, 0, -5)

	scan1, err := st.BeginScan(ctx, "cli", nil)
	if err != nil {
		t.Fatal(err)
	}
	addCert(t, st, scan1, "a.example.com", fpCompliant, nb, 47, []string{"a.example.com"})
	if err := st.FinishScan(ctx, scan1, "done", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	id1, _ := st.CreateReport(ctx, scan1, string(Inventory), nil, nil)
	a1, err := Generate(ctx, st, id1, scan1, Inventory, "", testNow())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveReportSnapshot(ctx, id1, a1.Snapshot); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveReportFiles(ctx, id1, "/tmp/a.html", "/tmp/a.csv", "/tmp/a.json", "/tmp/a.md", "/tmp/a.pdf", 1, "sha"); err != nil {
		t.Fatal(err)
	}

	scan2, err := st.BeginScan(ctx, "cli", nil)
	if err != nil {
		t.Fatal(err)
	}
	addCert(t, st, scan2, "b.example.com", fpNew, nb, 47, []string{"b.example.com"})
	if err := st.FinishScan(ctx, scan2, "done", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}

	// Retention removes the observations the first report was built from.
	if err := st.PruneObservations(ctx, 1); err != nil {
		t.Fatal(err)
	}

	id2, _ := st.CreateReport(ctx, scan2, string(Inventory), nil, nil)
	a2, err := Generate(ctx, st, id2, scan2, Inventory, "", testNow())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(a2.HTML, []byte("1 new certificate, 1 retired")) {
		t.Fatalf("delta sentence missing or wrong; body:\n%s", a2.HTML)
	}
}

// The delta counts certificates, not endpoints.
func TestDeltaCountsCertificates(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	nb := testNow().AddDate(0, 0, -5)

	scan1, err := st.BeginScan(ctx, "cli", nil)
	if err != nil {
		t.Fatal(err)
	}
	certID := addCert(t, st, scan1, "a.example.com", fpCompliant, nb, 47, []string{"a.example.com"})
	for _, host := range []string{"b.example.com", "c.example.com"} {
		ep, err := st.UpsertEndpoint(ctx, testDomainID, host, 443, "192.0.2.9", scan1)
		if err != nil {
			t.Fatal(err)
		}
		v := x509eval.Verdict{Trust: "public", ChainValid: true, HostnameValid: true}
		if err := st.RecordObservation(ctx, scan1, testDomainID, ep, certID, v, 0x0304, 0x1301, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.FinishScan(ctx, scan1, "done", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	id1, _ := st.CreateReport(ctx, scan1, string(Inventory), nil, nil)
	a1, err := Generate(ctx, st, id1, scan1, Inventory, "", testNow())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveReportSnapshot(ctx, id1, a1.Snapshot); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveReportFiles(ctx, id1, "/tmp/a.html", "/tmp/a.csv", "/tmp/a.json", "/tmp/a.md", "/tmp/a.pdf", 1, "sha"); err != nil {
		t.Fatal(err)
	}

	scan2, err := st.BeginScan(ctx, "cli", nil)
	if err != nil {
		t.Fatal(err)
	}
	addCert(t, st, scan2, "a.example.com", fpCompliant, nb, 47, []string{"a.example.com"})
	if err := st.FinishScan(ctx, scan2, "done", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	id2, _ := st.CreateReport(ctx, scan2, string(Inventory), nil, nil)
	a2, err := Generate(ctx, st, id2, scan2, Inventory, "", testNow())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(a2.HTML, []byte("0 new certificates, 0 retired")) {
		t.Fatalf("delta sentence wrong; body:\n%s", a2.HTML)
	}
}

// The worklist is exactly the certificates above the 47-day target.
func TestWorklistIsExactlyAboveTarget(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	s1, err := st.BeginScan(ctx, "cli", nil)
	if err != nil {
		t.Fatal(err)
	}
	nb := testNow().AddDate(0, 0, -5)
	addCert(t, st, s1, "a.example.com", fpCompliant, nb, 47, []string{"a.example.com"})
	addCert(t, st, s1, "b.example.com", fp48, nb, 48, []string{"b.example.com"})
	if err := st.FinishScan(ctx, s1, "done", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	id, _ := st.CreateReport(ctx, s1, string(Worklist), nil, nil)
	a, err := Generate(ctx, st, id, s1, Worklist, "", testNow())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(a.HTML, []byte(fp48)) {
		t.Fatal("worklist must contain the 48-day cert")
	}
	if bytes.Contains(a.HTML, []byte(fpCompliant)) {
		t.Fatal("worklist must not contain the 47-day cert")
	}
}

// The scope in force is part of the report.
func TestReportEmbedsScope(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	if err := st.ReplaceScope(ctx, []scope.Entry{{Kind: scope.Include, Value: "example.com"}}, nil); err != nil {
		t.Fatal(err)
	}
	s1, err := st.BeginScan(ctx, "cli", nil)
	if err != nil {
		t.Fatal(err)
	}
	nb := testNow().AddDate(0, 0, -5)
	addCert(t, st, s1, "a.example.com", fpCompliant, nb, 47, []string{"a.example.com"})
	if err := st.FinishScan(ctx, s1, "done", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	id, _ := st.CreateReport(ctx, s1, string(Inventory), nil, nil)
	a, err := Generate(ctx, st, id, s1, Inventory, "", testNow())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(a.CSV, []byte("scope=include: example.com")) {
		t.Fatalf("CSV missing scope; got:\n%s", a.CSV)
	}
}
