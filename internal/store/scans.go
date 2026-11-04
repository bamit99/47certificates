package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Scan is one row of the scans table.
type Scan struct {
	ID          int64      `json:"id"`
	StartedAt   time.Time  `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	Status      string     `json:"status"`
	Trigger     string     `json:"trigger"`
	TriggeredBy *int64     `json:"triggered_by,omitempty"`
	DomainID    *int64     `json:"domain_id,omitempty"`
	Domain      string     `json:"domain,omitempty"`
	Stats       string     `json:"stats,omitempty"`
	Error       string     `json:"error,omitempty"`
}

// BeginScan inserts a queued scan for a domain and returns its id.
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

// BeginDomainScan inserts a queued scan for one domain and returns its id.
func (s *Store) BeginDomainScan(ctx context.Context, trigger string, userID *int64, domainID int64) (int64, error) {
	now := time.Now()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO scans (started_at, status, trigger, triggered_by, domain_id) VALUES (?, 'queued', ?, ?, ?)`,
		toUnix(now), trigger, userID, domainID)
	if err != nil {
		return 0, fmt.Errorf("store: begin domain scan: %w", err)
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

// UpdateScanStats writes the live progress counters of a running scan.
//
// The counters are written while the scan runs, not only when it ends, so
// the UI can show movement. The status is left alone.
func (s *Store) UpdateScanStats(ctx context.Context, scanID int64, stats []byte) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE scans SET stats_json = ? WHERE id = ? AND status IN ('queued', 'running')`,
		string(stats), scanID)
	if err != nil {
		return fmt.Errorf("store: update scan stats: %w", err)
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
		dom     sql.NullInt64
		stats   sql.NullString
		scanErr sql.NullString
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT s.id, s.started_at, s.finished_at, s.status, s.trigger, s.triggered_by,
		        s.domain_id, s.stats_json, s.error, COALESCE(d.name, '')
		 FROM scans s LEFT JOIN domains d ON d.id = s.domain_id
		 WHERE s.id = ?`, id).
		Scan(&sc.ID, &started, &fin, &sc.Status, &sc.Trigger, &by, &dom, &stats, &scanErr, &sc.Domain)
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
	if dom.Valid {
		v := dom.Int64
		sc.DomainID = &v
	}
	sc.Stats = stats.String
	sc.Error = scanErr.String
	return sc, nil
}

// OwnerDomainID returns the domain the scan covers, or zero when the scan is
// not tied to one.
func (s Scan) OwnerDomainID() int64 {
	if s.DomainID == nil {
		return 0
	}
	return *s.DomainID
}

// RetireUnseen marks the certificates a domain stopped serving as retired.
//
// It does nothing unless the scan ended done: a cancelled or failed scan
// must not look like mass retirement. The retirement is per domain: a
// certificate colt.net stopped serving is retired there and stays live at
// iana.org.
func (s *Store) RetireUnseen(ctx context.Context, scanID, domainID int64) error {
	var status string
	if err := s.db.QueryRowContext(ctx, `SELECT status FROM scans WHERE id = ?`, scanID).Scan(&status); err != nil {
		return err
	}
	if status != "done" {
		return nil
	}
	now := toUnix(time.Now())
	// The certificates the domain served before and does not serve now.
	_, err := s.db.ExecContext(ctx,
		`UPDATE domain_certs SET retired_at = ?
		 WHERE domain_id = ? AND retired_at IS NULL
		   AND cert_id NOT IN (SELECT cert_id FROM observations WHERE scan_id = ?)`,
		now, domainID, scanID)
	if err != nil {
		return err
	}
	// The findings of a retired certificate no longer hold: nothing serves
	// it, so there is nothing to report about it.
	_, err = s.db.ExecContext(ctx,
		`UPDATE findings SET status = 'resolved'
		 WHERE status IN ('open', 'snoozed') AND domain_id IS ?
		   AND cert_id IN (SELECT cert_id FROM domain_certs
		                   WHERE domain_id = ? AND retired_at IS NOT NULL)`,
		domainID, domainID)
	return err
}
