package report

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/bamit99/47certificates/internal/scope"
	"github.com/bamit99/47certificates/internal/store"
	"github.com/bamit99/47certificates/internal/x509eval"
)

func testNow() time.Time { return time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC) }

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(); err != nil {
		t.Fatal(err)
	}
	domID, err := st.EnsureDomain(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	testDomainID = domID
	if err := st.ReplaceScope(context.Background(), []scope.Entry{{Kind: scope.Include, Value: "example.com"}}, nil); err != nil {
		t.Fatal(err)
	}
	return st
}

// testDomainID is the domain the report tests use.
var testDomainID int64

func addCert(t *testing.T, st *store.Store, scanID int64, host, fp string, nb time.Time, lifetime int, sans []string) int64 {
	t.Helper()
	cert := x509eval.Cert{
		Fingerprint:  fp,
		Subject:      "CN=" + sans[0],
		Issuer:       "CN=Test CA",
		NotBefore:    nb,
		NotAfter:     nb.Add(time.Duration(lifetime) * 24 * time.Hour),
		LifetimeDays: lifetime,
		KeyAlg:       "ECDSA", KeyBits: 256, SigAlg: "ECDSA-SHA256",
		SANs: sans,
		Raw:  []byte("raw" + fp),
	}
	certID, err := st.UpsertCert(context.Background(), cert)
	if err != nil {
		t.Fatal(err)
	}
	ep, err := st.UpsertEndpoint(context.Background(), testDomainID, host, 443, "192.0.2.1", scanID)
	if err != nil {
		t.Fatal(err)
	}
	v := x509eval.Verdict{Trust: "public", ChainValid: true, HostnameValid: true}
	if err := st.RecordObservation(context.Background(), scanID, testDomainID, ep, certID, v, 0x0304, 0x1301, nil); err != nil {
		t.Fatal(err)
	}
	return certID
}

func startScan(t *testing.T, st *store.Store, status string) int64 {
	t.Helper()
	id, err := st.BeginScan(context.Background(), "cli", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.FinishScan(context.Background(), id, status, []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	return id
}

const fpCompliant = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const fp48 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const fpNew = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

func TestWorklistExcludes47DayCerts(t *testing.T) {
	st := openStore(t)
	s1, err := st.BeginScan(context.Background(), "cli", nil)
	if err != nil {
		t.Fatal(err)
	}
	nb := testNow().AddDate(0, 0, -5)
	addCert(t, st, s1, "a.example.com", fpCompliant, nb, 47, []string{"a.example.com"})
	addCert(t, st, s1, "b.example.com", fp48, nb, 48, []string{"b.example.com"})
	if err := st.FinishScan(context.Background(), s1, "done", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	id, _ := st.CreateReport(context.Background(), s1, string(Worklist), nil, nil)
	a, err := Generate(context.Background(), st, id, s1, Worklist, "", testNow())
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

func TestReportRefusesNonDoneScan(t *testing.T) {
	st := openStore(t)
	s := startScan(t, st, "cancelled")
	if _, err := Generate(context.Background(), st, 1, s, Inventory, "", testNow()); err != ErrScanNotDone {
		t.Fatalf("err = %v", err)
	}
}

func TestReportEmbedsProvenance(t *testing.T) {
	st := openStore(t)
	s, err := st.BeginScan(context.Background(), "cli", nil)
	if err != nil {
		t.Fatal(err)
	}
	nb := testNow().AddDate(0, 0, -5)
	addCert(t, st, s, "a.example.com", fpCompliant, nb, 47, []string{"a.example.com"})
	if err := st.FinishScan(context.Background(), s, "done", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	id, _ := st.CreateReport(context.Background(), s, string(Inventory), nil, nil)
	a, err := Generate(context.Background(), st, id, s, Inventory, "", testNow())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"scan #" + fmt.Sprint(s),
		"example.com",
		"dev",
		"publicly-trusted certificates only",
	} {
		if !bytes.Contains(a.HTML, []byte(want)) {
			t.Fatalf("HTML missing %q", want)
		}
	}
	if !bytes.Contains(a.JSON, []byte(`"schema_version": 1`)) {
		t.Fatal("JSON missing schema_version")
	}
	if !bytes.Contains(a.CSV, []byte("fingerprint_sha256")) {
		t.Fatal("CSV missing header")
	}
}

func TestDeltaAgainstPreviousReport(t *testing.T) {
	st := openStore(t)
	nb := testNow().AddDate(0, 0, -5)

	scan1, err := st.BeginScan(context.Background(), "cli", nil)
	if err != nil {
		t.Fatal(err)
	}
	addCert(t, st, scan1, "a.example.com", fpCompliant, nb, 47, []string{"a.example.com"})
	if err := st.FinishScan(context.Background(), scan1, "done", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	id1, _ := st.CreateReport(context.Background(), scan1, string(Inventory), nil, nil)
	if err := st.SaveReportFiles(context.Background(), id1, "/nonexistent/a.html", "/nonexistent/a.csv", "/nonexistent/a.json", "/nonexistent/a.md", "/nonexistent/a.pdf", 1, "sha"); err != nil {
		t.Fatal(err)
	}

	scan2, err := st.BeginScan(context.Background(), "cli", nil)
	if err != nil {
		t.Fatal(err)
	}
	addCert(t, st, scan2, "b.example.com", fpNew, nb, 47, []string{"b.example.com"})
	if err := st.FinishScan(context.Background(), scan2, "done", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}

	id2, _ := st.CreateReport(context.Background(), scan2, string(Inventory), nil, nil)
	a, err := Generate(context.Background(), st, id2, scan2, Inventory, "", testNow())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(a.HTML, []byte("1 new certificate, 1 retired")) {
		t.Fatalf("delta sentence missing; body:\n%s", a.HTML)
	}
}
