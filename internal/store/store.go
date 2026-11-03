// Package store is the SQLite persistence layer. It is the only package that
// talks SQL.
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// ErrScanInProgress is returned when another process holds the scan lock.
var ErrScanInProgress = errors.New("store: scan already in progress")

//go:embed migrations/0001_init.sql
var migration1 string

// lockStaleAfter lets a crashed holder be reclaimed.
const lockStaleAfter = 30 * time.Minute

// Store wraps the database.
type Store struct {
	db   *sql.DB
	path string
}

// Open opens (but does not migrate) the database at path.
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &Store{db: db, path: path}, nil
}

// Migrate applies embedded migrations. It is idempotent.
func (s *Store) Migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("store: migrations table: %w", err)
	}
	var applied int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 1`).Scan(&applied); err != nil {
		return err
	}
	if applied == 0 {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migration1); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: migration 1: %w", err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (1, ?)`, time.Now().Unix()); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// DB exposes the handle for tests and read-only helpers in this package.
func (s *Store) DB() *sql.DB { return s.db }

// AcquireScanLock takes the store-level single-flight lock. The returned
// function releases it and must always be called.
func (s *Store) AcquireScanLock(ctx context.Context) (func(), error) {
	now := time.Now()
	res, err := s.db.ExecContext(ctx,
		`UPDATE scan_lock SET acquired_at = ?
		 WHERE id = 1 AND (acquired_at IS NULL OR acquired_at < ?)`,
		now.Unix(), now.Add(-lockStaleAfter).Unix())
	if err != nil {
		return nil, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, ErrScanInProgress
	}
	return func() {
		_, _ = s.db.Exec(`UPDATE scan_lock SET acquired_at = NULL WHERE id = 1`)
	}, nil
}

func toUnix(t time.Time) int64 { return t.UTC().Unix() }

func fromUnix(v int64) time.Time { return time.Unix(v, 0).UTC() }

func nullTime(v *int64) *time.Time {
	if v == nil {
		return nil
	}
	t := fromUnix(*v)
	return &t
}
