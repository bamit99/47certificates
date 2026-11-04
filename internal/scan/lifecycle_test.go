package scan

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"testing"
	"time"

	"github.com/amit/47certificates/internal/scope"
	"github.com/amit/47certificates/internal/testutil"
)

// mustJSON encodes v as JSON.
func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A cancelled scan leaves the lifecycle untouched: last_seen does not move
// and a retired certificate stays retired.
func TestCancelledScanLeavesLifecycleAlone(t *testing.T) {
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
	var lastSeen, retired *int64
	if err := st.DB().QueryRow(`SELECT id, last_seen, retired_at FROM certs LIMIT 1`).Scan(&certID, &lastSeen, &retired); err != nil {
		t.Fatal(err)
	}
	if lastSeen == nil {
		t.Fatal("a done scan must set last_seen")
	}
	firstSeen := *lastSeen

	// The certificate is retired by a later done scan that stops observing it.
	empty, _ := st.BeginScan(ctx, "cli", nil)
	if err := st.FinishScan(ctx, empty, "done", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	if err := st.RetireUnseen(ctx, empty); err != nil {
		t.Fatal(err)
	}

	// A cancelled scan observes it again. Nothing may change.
	second, _ := st.BeginScan(ctx, "cli", nil)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := testEngine(st, pool).Run(cancelled, second, set, []int{port}, nil); err == nil {
		t.Fatal("expected the cancelled scan to fail")
	}
	if err := st.DB().QueryRow(`SELECT last_seen, retired_at FROM certs WHERE id = ?`, certID).Scan(&lastSeen, &retired); err != nil {
		t.Fatal(err)
	}
	if lastSeen == nil || *lastSeen != firstSeen {
		t.Fatalf("a cancelled scan moved last_seen: %v -> %v", firstSeen, lastSeen)
	}
	if retired == nil {
		t.Fatal("a cancelled scan resurrected a retired certificate")
	}
}

// The CT cache replays the names it saw, so a rescan inside the cache window
// still probes the hosts CT revealed.
func TestCTCacheReplaysNames(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()

	cached, remember := ctCache(st)
	if _, ok := cached("example.com"); ok {
		t.Fatal("an empty cache must not report a hit")
	}
	remember("example.com", []string{"a.example.com", "b.example.com"})

	names, ok := cached("example.com")
	if !ok {
		t.Fatal("the cache must report a hit after a successful query")
	}
	if len(names) != 2 || names[0] != "a.example.com" {
		t.Fatalf("cached names = %v", names)
	}

	// An expired cache is a miss.
	old := ctCacheEntry{At: time.Now().Add(-7 * time.Hour).Unix(), Names: names}
	if err := st.SetSetting(ctx, ctCacheKey("example.com"), mustJSON(t, old)); err != nil {
		t.Fatal(err)
	}
	if _, ok := cached("example.com"); ok {
		t.Fatal("an expired cache must be a miss")
	}
}
