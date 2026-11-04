package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrUserExists is returned when a username is already taken.
var ErrUserExists = errors.New("store: user already exists")

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("store: not found")

// User is one account.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	CreatedAt    time.Time
	Disabled     bool
}

// CreateUser inserts a user. Duplicate usernames return ErrUserExists.
func (s *Store) CreateUser(ctx context.Context, username, hash string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("store: empty username")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)`,
		username, hash, toUnix(time.Now()))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return ErrUserExists
		}
		return fmt.Errorf("store: create user: %w", err)
	}
	return nil
}

// UserByUsername loads one user by name.
func (s *Store) UserByUsername(ctx context.Context, username string) (User, error) {
	return s.scanUser(s.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, created_at, disabled FROM users WHERE username = ?`, username))
}

// UserByID loads one user by id.
func (s *Store) UserByID(ctx context.Context, id int64) (User, error) {
	return s.scanUser(s.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, created_at, disabled FROM users WHERE id = ?`, id))
}

// ListUsers returns every user ordered by name.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, username, password_hash, created_at, disabled FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var (
			u   User
			at  int64
			dis int
		)
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &at, &dis); err != nil {
			return nil, err
		}
		u.CreatedAt = fromUnix(at)
		u.Disabled = dis != 0
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) scanUser(row *sql.Row) (User, error) {
	var (
		u   User
		at  int64
		dis int
	)
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &at, &dis); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, err
	}
	u.CreatedAt = fromUnix(at)
	u.Disabled = dis != 0
	return u, nil
}

// CreateSession stores a session id for a user.
func (s *Store) CreateSession(ctx context.Context, id string, userID int64, expires time.Time, ip, userAgent string) error {
	now := toUnix(time.Now())
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, created_at, expires_at, last_seen, ip, user_agent)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, userID, now, toUnix(expires), now, ip, userAgent)
	if err != nil {
		return fmt.Errorf("store: create session: %w", err)
	}
	return nil
}

// sessionTTL is the absolute session lifetime.
const sessionTTL = 30 * 24 * time.Hour

// sessionIdle is how long a session may be inactive before it dies.
const sessionIdle = 7 * 24 * time.Hour

// SessionUser resolves a session id to an enabled user and refreshes last_seen.
// Sessions older than 30 days or idle for more than 7 are treated as absent.
func (s *Store) SessionUser(ctx context.Context, id string, now time.Time) (User, error) {
	var userID int64
	var (
		expires  int64
		lastSeen int64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT user_id, expires_at, last_seen FROM sessions WHERE id = ?`, id).Scan(&userID, &expires, &lastSeen)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, err
	}
	if fromUnix(expires).Before(now) || fromUnix(lastSeen).Before(now.Add(-sessionIdle)) {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
		return User{}, ErrNotFound
	}
	u, err := s.UserByID(ctx, userID)
	if err != nil {
		return User{}, err
	}
	if u.Disabled {
		return User{}, ErrNotFound
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE sessions SET last_seen = ? WHERE id = ?`, toUnix(now), id)
	return u, nil
}

// DeleteSession removes a session.
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	return err
}

// GetSetting reads a settings row.
func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return value, err
}

// SetSetting writes a settings row.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}
