package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/amit/47certificates/internal/scope"
)

// AuditEntry is one row of audit_log.
type AuditEntry struct {
	ID     int64     `json:"id"`
	UserID *int64    `json:"user_id,omitempty"`
	Action string    `json:"action"`
	Target string    `json:"target,omitempty"`
	Detail string    `json:"detail,omitempty"`
	IP     string    `json:"ip,omitempty"`
	At     time.Time `json:"at"`
}

// ReplaceScope swaps the whole allowlist in one transaction.
func (s *Store) ReplaceScope(ctx context.Context, entries []scope.Entry, userID *int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM scope_entries`); err != nil {
		return fmt.Errorf("store: clear scope: %w", err)
	}
	for _, e := range entries {
		kind, err := kindString(e.Kind)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO scope_entries (kind, value, note, created_by, created_at) VALUES (?, ?, NULL, ?, ?)`,
			kind, e.Value, userID, toUnix(time.Now())); err != nil {
			return fmt.Errorf("store: insert scope entry: %w", err)
		}
	}
	return tx.Commit()
}

func kindString(k scope.Kind) (string, error) {
	switch k {
	case scope.Include:
		return "include", nil
	case scope.Exclude:
		return "exclude", nil
	case scope.Seed:
		return "seed", nil
	default:
		return "", fmt.Errorf("store: unknown scope kind %d", k)
	}
}

// Audit records one mutating action.
func (s *Store) Audit(ctx context.Context, userID *int64, action, target string, detail []byte, ip string) error {
	var detailVal any
	if len(detail) > 0 {
		var v any
		if err := json.Unmarshal(detail, &v); err == nil {
			detailVal = string(detail)
		} else {
			b, _ := json.Marshal(string(detail))
			detailVal = string(b)
		}
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_log (user_id, action, target, detail_json, at, ip)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		userID, action, target, detailVal, toUnix(time.Now()), ip)
	if err != nil {
		return fmt.Errorf("store: audit: %w", err)
	}
	return nil
}

// ListAudit returns recent audit entries, newest first.
func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, action, COALESCE(target, ''), COALESCE(detail_json, ''), COALESCE(ip, ''), at
		FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var (
			e   AuditEntry
			uid sql.NullInt64
			at  int64
		)
		if err := rows.Scan(&e.ID, &uid, &e.Action, &e.Target, &e.Detail, &e.IP, &at); err != nil {
			return nil, err
		}
		if uid.Valid {
			v := uid.Int64
			e.UserID = &v
		}
		e.At = fromUnix(at)
		out = append(out, e)
	}
	return out, rows.Err()
}
