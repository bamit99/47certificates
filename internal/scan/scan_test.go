package scan

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bamit99/47certificates/internal/scope"
	"github.com/bamit99/47certificates/internal/store"
	"github.com/bamit99/47certificates/internal/testutil"
)

type fakeSource struct{ names []string }

func (f fakeSource) Names(context.Context, string) ([]string, error) { return f.names, nil }

type fakeResolver struct{ ips map[string][]string }

func (f fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	return f.ips[host], nil
}

func (f fakeResolver) LookupCNAME(context.Context, string) (string, error) { return "", nil }

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
	return st
}

// startServer serves a leaf and its root on loopback and returns the port.
func startServer(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, name string) int {
	t.Helper()
	der, key := testutil.NewLeaf(t, ca, caKey, testutil.LeafOpts{DNSNames: []string{name}})
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key}}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func testEngine(st *store.Store, pool *x509.CertPool) *Engine {
	return &Engine{
		Store:       st,
		Source:      fakeSource{names: []string{"a.example.com"}},
		Resolver:    fakeResolver{ips: map[string][]string{"a.example.com": {"127.0.0.1"}}},
		Roots:       pool,
		Now:         func() time.Time { return time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC) },
		Concurrency: 4,
		QPS:         1000,
		Timeout:     time.Second,
	}
}

func TestRunEndToEnd(t *testing.T) {
	ca, caKey := testutil.NewCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	port := startServer(t, ca, caKey, "a.example.com")

	st := openStore(t)
	set, _ := scope.New([]scope.Entry{{Kind: scope.Include, Value: "example.com"}})
	id, err := st.BeginScan(context.Background(), "cli", nil)
	if err != nil {
		t.Fatal(err)
	}
	var events []Progress
	stats, err := testEngine(st, pool).Run(context.Background(), id, set, []int{port}, func(p Progress) {
		events = append(events, p)
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Hosts != 2 || stats.Endpoints != 1 || stats.Observed != 1 || stats.Public != 1 {
		t.Fatalf("%+v", stats)
	}
	sc, err := st.ScanByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Status != "done" {
		t.Fatalf("status = %s", sc.Status)
	}
	if len(events) == 0 {
		t.Fatal("expected progress events")
	}
	rows, err := st.ScanObservationRows(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Fingerprint == "" || rows[0].Host != "a.example.com" {
		t.Fatalf("%+v", rows)
	}
}

func TestCancelledScanDoesNotRetire(t *testing.T) {
	ca, caKey := testutil.NewCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	port := startServer(t, ca, caKey, "a.example.com")

	st := openStore(t)
	ctx := context.Background()
	set, _ := scope.New([]scope.Entry{{Kind: scope.Include, Value: "example.com"}})
	first, _ := st.BeginScan(ctx, "cli", nil)
	if _, err := testEngine(st, pool).Run(ctx, first, set, []int{port}, nil); err != nil {
		t.Fatal(err)
	}

	var certID int64
	var retired *int64
	if err := st.DB().QueryRow(`SELECT id, retired_at FROM certs LIMIT 1`).Scan(&certID, &retired); err != nil {
		t.Fatal(err)
	}
	if retired != nil {
		t.Fatal("cert from a done scan must not be retired")
	}

	second, _ := st.BeginScan(ctx, "cli", nil)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := testEngine(st, pool).Run(cancelled, second, set, []int{port}, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	sc, _ := st.ScanByID(ctx, second)
	if sc.Status != "cancelled" {
		t.Fatalf("status = %s", sc.Status)
	}
	if err := st.DB().QueryRow(`SELECT retired_at FROM certs WHERE id = ?`, certID).Scan(&retired); err != nil {
		t.Fatal(err)
	}
	if retired != nil {
		t.Fatal("cancelled scan must not retire certs")
	}
}

func TestEngineRefusesWhenLockHeld(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	lock, err := st.AcquireScanLock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()

	set, _ := scope.New([]scope.Entry{{Kind: scope.Include, Value: "example.com"}})
	id, _ := st.BeginScan(ctx, "cli", nil)
	if _, err := (&Engine{Store: st, Roots: x509.NewCertPool()}).Run(ctx, id, set, nil, nil); !errors.Is(err, store.ErrScanInProgress) {
		t.Fatalf("err = %v", err)
	}
}

func TestExportCSVAndJSON(t *testing.T) {
	ca, caKey := testutil.NewCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	port := startServer(t, ca, caKey, "a.example.com")

	st := openStore(t)
	ctx := context.Background()
	set, _ := scope.New([]scope.Entry{{Kind: scope.Include, Value: "example.com"}})
	id, _ := st.BeginScan(ctx, "cli", nil)
	if _, err := testEngine(st, pool).Run(ctx, id, set, []int{port}, nil); err != nil {
		t.Fatal(err)
	}

	var csvBuf bytes.Buffer
	if err := ExportCSV(ctx, st, id, &csvBuf); err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(strings.NewReader(csvBuf.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[1][0] != "a.example.com" {
		t.Fatalf("csv = %v", records)
	}

	var jsonBuf bytes.Buffer
	if err := ExportJSON(ctx, st, id, &jsonBuf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		ScanID int64            `json:"scan_id"`
		Rows   []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal(jsonBuf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.ScanID != id || len(doc.Rows) != 1 {
		t.Fatalf("%+v", doc)
	}
}
