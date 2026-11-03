package jobs

import (
	"context"
	"crypto/x509"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/amit/47certificates/internal/scan"
	"github.com/amit/47certificates/internal/scope"
	"github.com/amit/47certificates/internal/store"
)

type blockingSource struct {
	started chan struct{}
}

func (b blockingSource) Names(ctx context.Context, domain string) ([]string, error) {
	select {
	case b.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

type fakeResolver struct{}

func (fakeResolver) LookupHost(context.Context, string) ([]string, error) { return nil, nil }
func (fakeResolver) LookupCNAME(context.Context, string) (string, error)  { return "", nil }

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
	if err := st.ReplaceScope(context.Background(), []scope.Entry{{Kind: scope.Include, Value: "example.com"}}, nil); err != nil {
		t.Fatal(err)
	}
	return st
}

func waitForStatus(t *testing.T, st *store.Store, id int64, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		sc, err := st.ScanByID(context.Background(), id)
		if err == nil && sc.Status == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("scan %d did not reach %q", id, want)
}

func TestTriggerIsSingleFlight(t *testing.T) {
	st := openStore(t)
	started := make(chan struct{}, 1)
	eng := &scan.Engine{
		Store:       st,
		Source:      blockingSource{started: started},
		Resolver:    fakeResolver{},
		Roots:       x509.NewCertPool(),
		Now:         time.Now,
		Concurrency: 1,
		QPS:         1000,
		Timeout:     time.Second,
	}

	r := New(st, eng, time.Now)
	first, err := r.TriggerScan(context.Background(), "manual", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Wait until discovery starts (job is alive).
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("scan did not start discovery")
	}

	if _, err := r.TriggerScan(context.Background(), "manual", nil); !errors.Is(err, ErrBusy) {
		t.Fatalf("second trigger err = %v", err)
	}
	if err := r.Cancel(first); err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, st, first, "cancelled")
}
