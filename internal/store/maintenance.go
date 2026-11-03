package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// PruneObservations deletes observations of all but the newest keep scans and
// then sweeps report deliveries for reports whose scans no longer exist.
// Certificates and findings are kept: they are the accumulated knowledge.
func (s *Store) PruneObservations(ctx context.Context, keep int) error {
	if keep < 0 {
		keep = 0
	}
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM observations
		 WHERE scan_id NOT IN (SELECT id FROM scans ORDER BY id DESC LIMIT ?)`, keep)
	if err != nil {
		return fmt.Errorf("store: prune observations: %w", err)
	}
	return nil
}

// LatestDoneScan returns the id of the newest scan with status done.
func (s *Store) LatestDoneScan(ctx context.Context) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM scans WHERE status = 'done' ORDER BY id DESC LIMIT 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return id, err
}

// LatestScan returns the id and status of the newest scan of any status.
func (s *Store) LatestScan(ctx context.Context) (int64, string, error) {
	var (
		id     int64
		status string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, status FROM scans ORDER BY id DESC LIMIT 1`).Scan(&id, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", ErrNotFound
	}
	return id, status, err
}

// CreateDelivery records one delivery attempt row with status pending.
func (s *Store) CreateDelivery(ctx context.Context, reportID int64, kind, target string) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO report_deliveries (report_id, kind, target, status, attempts, created_at)
		 VALUES (?, ?, ?, 'pending', 0, ?)`,
		reportID, kind, target, toUnix(time.Now()))
	if err != nil {
		return 0, fmt.Errorf("store: create delivery: %w", err)
	}
	return res.LastInsertId()
}

// FinishDelivery records the terminal outcome of one delivery.
func (s *Store) FinishDelivery(ctx context.Context, deliveryID int64, status string, attempts int, lastErr string) error {
	var errVal any
	if lastErr != "" {
		errVal = lastErr
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE report_deliveries SET status = ?, attempts = ?, last_error = ? WHERE id = ?`,
		status, attempts, errVal, deliveryID)
	return err
}
