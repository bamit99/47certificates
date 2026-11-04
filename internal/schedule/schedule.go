// Package schedule wires periodic scans, reports, and retention.
package schedule

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/amit/47certificates/internal/notify"
	"github.com/amit/47certificates/internal/report"
	"github.com/amit/47certificates/internal/store"
)

// New parses spec as a standard 5-field cron expression and returns a new,
// unstarted Cron in loc.
func New(spec string, loc *time.Location) (*cron.Cron, error) {
	if spec == "" {
		return nil, fmt.Errorf("schedule: spec is empty")
	}
	if _, err := cron.ParseStandard(spec); err != nil {
		return nil, fmt.Errorf("schedule: invalid cron %q: %w", spec, err)
	}
	if loc == nil {
		loc = time.Local
	}
	return cron.New(cron.WithLocation(loc)), nil
}

// Jitter returns a stable-per-run offset in [-10, +10] minutes applied to a
// scheduled entry so many instances do not fire at the same moment.
func Jitter() time.Duration {
	return time.Duration(rand.Intn(20)-10) * time.Minute
}

// ParseRetention reads the retention setting (the number of newest scans
// whose observations are kept).
func ParseRetention(v string, def int) int {
	var n int
	if v == "" {
		return def
	}
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil || n < 0 {
		return def
	}
	return n
}

// ScheduledReport generates the executive and worklist reports for the newest
// done scan and delivers them via the webhook when configured. Warnings are
// returned for skipped scans instead of aborting.
func ScheduledReport(ctx context.Context, st *store.Store, reportsDir string, wh *notify.Webhook, now time.Time) ([]string, error) {
	var warnings []string

	latestID, latestStatus, err := st.LatestScan(ctx)
	if err != nil && err != store.ErrNotFound {
		return warnings, err
	}
	doneID, err := st.LatestDoneScan(ctx)
	if err != nil {
		if err == store.ErrNotFound {
			return warnings, fmt.Errorf("schedule: no done scan to report on")
		}
		return warnings, err
	}
	if latestID != 0 && latestID != doneID {
		warnings = append(warnings, fmt.Sprintf("latest scan #%d is %s; reports use done scan #%d", latestID, latestStatus, doneID))
	}

	for _, kind := range []report.Kind{report.Executive, report.Worklist} {
		rp, err := report.GenerateAndStore(ctx, st, reportsDir, kind, doneID, "", nil, now)
		if err != nil {
			return warnings, fmt.Errorf("schedule: %s report: %w", kind, err)
		}
		if wh == nil {
			continue
		}
		if err := deliver(ctx, st, wh, rp); err != nil {
			// Delivery failures are logged but never abort the scheduler.
			warnings = append(warnings, fmt.Sprintf("webhook for report #%d failed: %v", rp.ID, err))
			log.Printf("schedule: webhook for report #%d: %v", rp.ID, err)
		}
	}
	return warnings, nil
}

func deliver(ctx context.Context, st *store.Store, wh *notify.Webhook, rp store.Report) error {
	body, err := json.Marshal(map[string]any{
		"report_id": rp.ID,
		"kind":      rp.Kind,
		"scan_id":   rp.ScanID,
		"status":    rp.Status,
		"sha256":    rp.SHA256,
	})
	if err != nil {
		return err
	}
	deliveryID, err := st.CreateDelivery(ctx, rp.ID, "webhook", wh.URL)
	if err != nil {
		return err
	}

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		if err := wh.Send(ctx, rp.ID, body); err == nil {
			return st.FinishDelivery(ctx, deliveryID, "delivered", attempt, "")
		} else {
			lastErr = err
		}
		if attempt < 3 {
			time.Sleep(time.Duration(1<<(attempt-1)) * time.Second)
		}
	}
	_ = st.FinishDelivery(ctx, deliveryID, "failed", 3, lastErr.Error())
	return lastErr
}
