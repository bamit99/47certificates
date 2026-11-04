package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// AckFinding acknowledges one finding; it stops appearing as open.
func (s *Store) AckFinding(ctx context.Context, findingID, userID int64, note string) error {
	now := toUnix(time.Now())
	res, err := s.db.ExecContext(ctx,
		`UPDATE findings
		 SET status='ack', ack_by=?, ack_at=?, snooze_until=NULL, note=?
		 WHERE id=? AND status <> 'resolved'`,
		userID, now, nullableString(note), findingID)
	if err != nil {
		return fmt.Errorf("store: ack finding: %w", err)
	}
	return affectedOne(res)
}

// SnoozeFinding hides one finding until until.
//
// The caller passes the reference time it is working with: the web layer uses
// its injected clock, so a snooze is judged against the same "now" the user
// was shown rather than the wall clock.
func (s *Store) SnoozeFinding(ctx context.Context, findingID, userID int64, until, now time.Time, note string) error {
	if until.IsZero() || !until.After(now) {
		return fmt.Errorf("store: snooze requires a future time")
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE findings
		 SET status='snoozed', snooze_until=?, note=?, ack_by=NULL, ack_at=NULL
		 WHERE id=? AND status <> 'resolved'`,
		toUnix(until), nullableString(note), findingID)
	if err != nil {
		return fmt.Errorf("store: snooze finding: %w", err)
	}
	return affectedOne(res)
}

// ReopenFinding returns one acknowledged or snoozed finding to open.
func (s *Store) ReopenFinding(ctx context.Context, findingID int64) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE findings
		 SET status='open', ack_by=NULL, ack_at=NULL, snooze_until=NULL, note=NULL
		 WHERE id=? AND status <> 'resolved'`,
		findingID)
	if err != nil {
		return fmt.Errorf("store: reopen finding: %w", err)
	}
	return affectedOne(res)
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func affectedOne(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
