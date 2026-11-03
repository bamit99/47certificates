package schedule

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/amit/47certificates/internal/store"
)

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

func TestScheduledReportUsesLatestDoneScan(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()

	doneID, err := st.BeginScan(ctx, "cli", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.FinishScan(ctx, doneID, "done", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}

	// A newer cancelled scan exists; the scheduler must not use it.
	cancelledID, err := st.BeginScan(ctx, "schedule", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.FinishScan(ctx, cancelledID, "cancelled", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	warnings, err := ScheduledReport(ctx, st, dir, nil, time.Date(2026, 11, 3, 4, 7, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "cancelled") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a warning mentioning the cancelled scan, got %v", warnings)
	}

	reports, err := st.ListReports(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, r := range reports {
		if r.ScanID != doneID {
			t.Fatalf("report %d used scan %d, want %d", r.ID, r.ScanID, doneID)
		}
		kinds[r.Kind] = true
	}
	for _, want := range []string{"executive", "worklist"} {
		if !kinds[want] {
			t.Fatalf("missing %q report: %v", want, kinds)
		}
	}
}
