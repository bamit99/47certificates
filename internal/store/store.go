// Package store is the SQLite persistence layer. It is the only package that
// talks SQL.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	_ "modernc.org/sqlite"
)

// ErrScanInProgress is returned when another process holds the scan lock.
var ErrScanInProgress = errors.New("store: scan already in progress")

//go:embed migrations/0001_init.sql migrations/0002_cert_raw.sql migrations/0003_findings_null.sql migrations/0004_scanlock_holder.sql migrations/0005_findings_scan_id.sql migrations/0006_report_snapshots.sql migrations/0007_dns_cache.sql migrations/0008_domains.sql migrations/0009_report_formats.sql
var migrationFS embed.FS

var migrations = []struct {
	version int
	file    string
}{
	{1, "migrations/0001_init.sql"},
	{2, "migrations/0002_cert_raw.sql"},
	{3, "migrations/0003_findings_null.sql"},
	{4, "migrations/0004_scanlock_holder.sql"},
	{5, "migrations/0005_findings_scan_id.sql"},
	{6, "migrations/0006_report_snapshots.sql"},
	{7, "migrations/0007_dns_cache.sql"},
	{8, "migrations/0008_domains.sql"},
	{9, "migrations/0009_report_formats.sql"},
}

// LatestSchemaVersion returns the highest migration version the binary knows.
func LatestSchemaVersion() int {
	latest := 0
	for _, m := range migrations {
		if m.version > latest {
			latest = m.version
		}
	}
	return latest
}

// lockStaleAfter lets a crashed holder be reclaimed.
const lockStaleAfter = 30 * time.Minute

// Store wraps the database.
type Store struct {
	db   *sql.DB
	path string
}

// Open opens (but does not migrate) the database at path.
//
// The database holds password hashes, session ids and the CSRF and webhook
// secrets, so the file is created with owner-only permissions.
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
	if err := restrictPermissions(path); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, path: path}, nil
}

// restrictPermissions makes the database file readable by its owner only.
func restrictPermissions(path string) error {
	if _, err := os.Stat(path); err != nil {
		// The file does not exist yet; SQLite creates it on first write.
		return nil
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("store: restrict permissions on %s: %w", path, err)
	}
	return nil
}

// Migrate applies embedded migrations. It is idempotent.
func (s *Store) Migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("store: migrations table: %w", err)
	}
	for _, m := range migrations {
		script, err := migrationFS.ReadFile(m.file)
		if err != nil {
			return fmt.Errorf("store: read migration %d: %w", m.version, err)
		}
		var applied int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, m.version).Scan(&applied); err != nil {
			return err
		}
		if applied > 0 {
			continue
		}
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(script)); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: migration %d: %w", m.version, err)
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, ?)`, m.version, time.Now().Unix()); err != nil {
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

// Path returns the file path the store was opened with.
func (s *Store) Path() string { return s.path }

// DB exposes the handle for tests and read-only helpers in this package.
func (s *Store) DB() *sql.DB { return s.db }

// ScanLock is a held single-flight lock. It refreshes itself while a long
// scan runs, so a scan that takes more than lockStaleAfter is not mistaken
// for a crashed one.
type ScanLock struct {
	s      *Store
	holder string
}

// Release drops the lock. It is safe to call more than once, and it never
// clears a lock that another holder has taken over.
func (l *ScanLock) Release() {
	if l == nil || l.s == nil {
		return
	}
	_, _ = l.s.db.Exec(`UPDATE scan_lock SET acquired_at = NULL, holder = NULL WHERE id = 1 AND holder = ?`, l.holder)
}

// Refresh extends the lock's lease. It reports false when the lock was
// reclaimed by another holder.
func (l *ScanLock) Refresh(ctx context.Context) (bool, error) {
	if l == nil || l.s == nil {
		return false, nil
	}
	res, err := l.s.db.ExecContext(ctx,
		`UPDATE scan_lock SET acquired_at = ? WHERE id = 1 AND holder = ?`,
		toUnix(time.Now()), l.holder)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// AcquireScanLock takes the store-level single-flight lock. The returned lock
// must always be released.
func (s *Store) AcquireScanLock(ctx context.Context) (*ScanLock, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	holder := hex.EncodeToString(nonce)
	now := time.Now()
	res, err := s.db.ExecContext(ctx,
		`UPDATE scan_lock SET acquired_at = ?, holder = ?
		 WHERE id = 1 AND (acquired_at IS NULL OR acquired_at < ?)`,
		now.Unix(), holder, now.Add(-lockStaleAfter).Unix())
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
	return &ScanLock{s: s, holder: holder}, nil
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
