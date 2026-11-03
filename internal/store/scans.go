package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Scan is one row of the scans table.
type Scan struct {
	ID          int64
	StartedAt   time.Time
	FinishedAt  *time.Time
	Status      string
	Trigger     string
	TriggeredBy *int64
	Stats       string
	Error       string
}

// BeginScan inserts a queued scan and returns its id.
func (s *Store) BeginScan(ctx context.Context, trigger string, userID *int64) (int64, error) {
	now := time.Now()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO scans (started_at, status, trigger, triggered_by) VALUES (?, 'queued', ?, ?)`,
		toUnix(now), trigger, userID)
	if err != nil {
		return 0, fmt.Errorf("store: begin scan: %w", err)
	}
	return res.LastInsertId()
}

// MarkRunning flips a queued scan to running.
func (s *Store) MarkRunning(ctx context.Context, scanID int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE scans SET status = 'running' WHERE id = ? AND status = 'queued'`, scanID)
	return err
}

// FinishScan records a terminal status, stats, and error.
func (s *Store) FinishScan(ctx context.Context, scanID int64, status string, stats []byte, scanErr string) error {
	var errVal any
	if scanErr != "" {
		errVal = scanErr
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE scans SET status = ?, finished_at = ?, stats_json = ?, error = ? WHERE id = ?`,
		status, toUnix(time.Now()), string(stats), errVal, scanID)
	if err != nil {
		return fmt.Errorf("store: finish scan: %w", err)
	}
	return nil
}

// ScanByID loads one scan.
func (s *Store) ScanByID(ctx context.Context, id int64) (Scan, error) {
	var (
		sc      Scan
		started int64
		fin     sql.NullInt64
		by      sql.NullInt64
		stats   sql.NullString
		scanErr sql.NullString
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, started_at, finished_at, status, trigger, triggered_by, stats_json, error FROM scans WHERE id = ?`, id).
		Scan(&sc.ID, &started, &fin, &sc.Status, &sc.Trigger, &by, &stats, &scanErr)
	if err != nil {
		return Scan{}, err
	}
	sc.StartedAt = fromUnix(started)
	if fin.Valid {
		t := fromUnix(fin.Int64)
		sc.FinishedAt = &t
	}
	if by.Valid {
		v := by.Int64
		sc.TriggeredBy = &v
	}
	sc.Stats = stats.String
	sc.Error = scanErr.String
	return sc, nil
}

// RetireUnseen marks certs not observed by a scan as retired. It does nothing
// unless the scan ended done: a cancelled or failed scan must not look like
// mass retirement.
func (s *Store) RetireUnseen(ctx context.Context, scanID int64) error {
	var status string
	if err := s.db.QueryRowContext(ctx, `SELECT status FROM scans WHERE id = ?`, scanID).Scan(&status); err != nil {
		return err
	}
	if status != "done" {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE certs SET retired_at = ?
		 WHERE retired_at IS NULL
		   AND id NOT IN (SELECT cert_id FROM observations WHERE scan_id = ?)`,
		toUnix(time.Now()), scanID)
	return err
}
