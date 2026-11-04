package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Report is one immutable report row.
type Report struct {
	ID         int64      `json:"id"`
	ScanID     int64      `json:"scan_id"`
	Kind       string     `json:"kind"`
	Status     string     `json:"status"`
	HTMLPath   string     `json:"html_path"`
	CSVPath    string     `json:"csv_path"`
	JSONPath   string     `json:"json_path"`
	SizeBytes  int64      `json:"size_bytes"`
	SHA256     string     `json:"sha256"`
	CreatedBy  *int64     `json:"created_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Error      string     `json:"error,omitempty"`
	Params     string     `json:"params_json,omitempty"`
}

// CreateReport inserts a generating report row and returns its id.
func (s *Store) CreateReport(ctx context.Context, scanID int64, kind string, userID *int64, params []byte) (int64, error) {
	now := toUnix(time.Now())
	paramsVal := []byte("{}")
	if len(params) > 0 {
		paramsVal = params
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO reports (scan_id, kind, status, params_json, created_by, created_at)
		 VALUES (?, ?, 'generating', ?, ?, ?)`,
		scanID, kind, string(paramsVal), userID, now)
	if err != nil {
		return 0, fmt.Errorf("store: create report: %w", err)
	}
	return res.LastInsertId()
}

// ReportByID loads one report.
func (s *Store) ReportByID(ctx context.Context, id int64) (Report, error) {
	var (
		r       Report
		fin     sql.NullInt64
		by      sql.NullInt64
		hp      sql.NullString
		cp      sql.NullString
		jp      sql.NullString
		sha     sql.NullString
		size    sql.NullInt64
		params  sql.NullString
		errMsg  sql.NullString
		started int64
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT id, scan_id, kind, status, html_path, csv_path, json_path, size_bytes,
		       sha256, created_by, created_at, finished_at, error, params_json
		FROM reports WHERE id = ?`, id).
		Scan(&r.ID, &r.ScanID, &r.Kind, &r.Status, &hp, &cp, &jp, &size, &sha, &by, &started, &fin, &errMsg, &params)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Report{}, ErrNotFound
		}
		return Report{}, err
	}
	r.HTMLPath = hp.String
	r.CSVPath = cp.String
	r.JSONPath = jp.String
	r.SizeBytes = size.Int64
	r.SHA256 = sha.String
	r.Error = errMsg.String
	r.Params = params.String
	r.CreatedAt = fromUnix(started)
	if fin.Valid {
		t := fromUnix(fin.Int64)
		r.FinishedAt = &t
	}
	if by.Valid {
		v := by.Int64
		r.CreatedBy = &v
	}
	return r, nil
}

// SaveReportFiles records the artifact paths and marks the report done.
func (s *Store) SaveReportFiles(ctx context.Context, id int64, htmlPath, csvPath, jsonPath string, sizeBytes int64, sha256 string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE reports
		SET status='done', html_path=?, csv_path=?, json_path=?, size_bytes=?, sha256=?, finished_at=?
		WHERE id=?`, htmlPath, csvPath, jsonPath, sizeBytes, sha256, toUnix(time.Now()), id)
	return err
}

// FailReport marks a report failed.
func (s *Store) FailReport(ctx context.Context, id int64, reportErr string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE reports SET status='failed', error=?, finished_at=? WHERE id=?`,
		reportErr, toUnix(time.Now()), id)
	return err
}

// LatestDoneReport returns the most recent done report of a kind whose scan is
// not scanID; earlier scans only.
func (s *Store) LatestDoneReport(ctx context.Context, kind string, scanID int64) (*Report, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, scan_id FROM reports
		WHERE kind = ? AND status = 'done' AND scan_id < ?
		ORDER BY scan_id DESC, id DESC LIMIT 1`, kind, scanID)
	var r Report
	if err := row.Scan(&r.ID, &r.ScanID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &r, nil
}

// LatestDoneReportOfKind returns the most recent done report of a kind,
// regardless of which scan it covers. It is the delta baseline: a report
// compares against the previous report of the same kind, not against a scan
// that retention may have pruned.
func (s *Store) LatestDoneReportOfKind(ctx context.Context, kind string, beforeID int64) (*Report, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, scan_id FROM reports
		WHERE kind = ? AND status = 'done' AND id < ?
		ORDER BY id DESC LIMIT 1`, kind, beforeID)
	var r Report
	if err := row.Scan(&r.ID, &r.ScanID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &r, nil
}

// SnapshotRow is one certificate as a report saw it. It is stored with the
// report so a later report can diff against it without reading observations
// that retention may have deleted.
type SnapshotRow struct {
	Fingerprint  string `json:"fingerprint_sha256"`
	LifetimeDays int    `json:"lifetime_days"`
	Violation    bool   `json:"violation"`
}

// SaveReportSnapshot records the certificate set a report was built from.
func (s *Store) SaveReportSnapshot(ctx context.Context, reportID int64, rows []SnapshotRow) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM report_snapshots WHERE report_id = ?`, reportID); err != nil {
		return err
	}
	for _, r := range rows {
		violation := 0
		if r.Violation {
			violation = 1
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT OR REPLACE INTO report_snapshots (report_id, fingerprint, lifetime_days, violation)
			 VALUES (?, ?, ?, ?)`,
			reportID, r.Fingerprint, r.LifetimeDays, violation); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ReportSnapshot loads the certificate set a report was built from.
func (s *Store) ReportSnapshot(ctx context.Context, reportID int64) ([]SnapshotRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT fingerprint, lifetime_days, violation FROM report_snapshots WHERE report_id = ?`, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SnapshotRow
	for rows.Next() {
		var (
			r        SnapshotRow
			violation int
		)
		if err := rows.Scan(&r.Fingerprint, &r.LifetimeDays, &violation); err != nil {
			return nil, err
		}
		r.Violation = violation != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListReports returns reports newest first.
func (s *Store) ListReports(ctx context.Context, limit int) ([]Report, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, scan_id, kind, status, created_by, created_at, finished_at
		FROM reports ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Report
	for rows.Next() {
		var (
			r   Report
			at  int64
			fin sql.NullInt64
			by  sql.NullInt64
		)
		if err := rows.Scan(&r.ID, &r.ScanID, &r.Kind, &r.Status, &by, &at, &fin); err != nil {
			return nil, err
		}
		r.CreatedAt = fromUnix(at)
		if fin.Valid {
			t := fromUnix(fin.Int64)
			r.FinishedAt = &t
		}
		if by.Valid {
			v := by.Int64
			r.CreatedBy = &v
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteReport removes the row; the caller removes the files.
func (s *Store) DeleteReport(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM reports WHERE id = ?`, id)
	if err != nil {
		return err
	}
	return affectedOne(res)
}
