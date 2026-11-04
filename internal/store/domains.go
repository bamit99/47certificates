package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Domain is one audited estate.
type Domain struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	// Certs is the number of certificates the domain currently serves.
	Certs int `json:"certs"`
	// Endpoints is the number of endpoints observed for the domain.
	Endpoints int `json:"endpoints"`
	// Open is the number of certificates with an open finding.
	Open int `json:"open"`
	// Retired is the number of certificates the domain stopped serving.
	Retired int `json:"retired"`
}

// ErrDomainNotFound is returned when a domain does not exist.
var ErrDomainNotFound = errors.New("store: domain not found")

// EnsureDomain returns the id of the domain named name, creating it when it
// does not exist. The name is matched case-insensitively.
func (s *Store) EnsureDomain(ctx context.Context, name string) (int64, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return 0, errors.New("store: empty domain name")
	}
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM domains WHERE name = ?`, name).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO domains (name, created_at) VALUES (?, ?)`, name, toUnix(time.Now()))
	if err != nil {
		// Another writer may have created it in the meantime.
		if e2 := s.db.QueryRowContext(ctx, `SELECT id FROM domains WHERE name = ?`, name).Scan(&id); e2 == nil {
			return id, nil
		}
		return 0, fmt.Errorf("store: ensure domain %s: %w", name, err)
	}
	return res.LastInsertId()
}

// DomainByName returns the domain named name.
func (s *Store) DomainByName(ctx context.Context, name string) (Domain, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	var (
		d       Domain
		created int64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, created_at FROM domains WHERE name = ?`, name).Scan(&d.ID, &d.Name, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return Domain{}, ErrDomainNotFound
	}
	if err != nil {
		return Domain{}, err
	}
	d.CreatedAt = fromUnix(created)
	return d, nil
}

// DomainByID returns the domain with the given id.
func (s *Store) DomainByID(ctx context.Context, id int64) (Domain, error) {
	var (
		d       Domain
		created int64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, created_at FROM domains WHERE id = ?`, id).Scan(&d.ID, &d.Name, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return Domain{}, ErrDomainNotFound
	}
	if err != nil {
		return Domain{}, err
	}
	d.CreatedAt = fromUnix(created)
	return d, nil
}

// ListDomains returns every domain with its counts, ordered by name.
func (s *Store) ListDomains(ctx context.Context) ([]Domain, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT d.id, d.name, d.created_at,
		       COALESCE(dc.certs, 0),
		       COALESCE(dc.retired, 0),
		       COALESCE(dc.open, 0),
		       (SELECT COUNT(*) FROM endpoints e WHERE e.domain_id = d.id)
		FROM domains d
		LEFT JOIN (
		    SELECT dc.domain_id,
		           COUNT(*) AS certs,
		           SUM(CASE WHEN dc.retired_at IS NOT NULL THEN 1 ELSE 0 END) AS retired,
		           (SELECT COUNT(*) FROM findings f
		             WHERE f.domain_id = dc.domain_id AND f.status IN ('open','snoozed')) AS open
		    FROM domain_certs dc GROUP BY dc.domain_id
		) dc ON dc.domain_id = d.id
		ORDER BY d.name`)
	if err != nil {
		return nil, fmt.Errorf("store: list domains: %w", err)
	}
	defer rows.Close()
	var out []Domain
	for rows.Next() {
		var (
			d       Domain
			created int64
		)
		if err := rows.Scan(&d.ID, &d.Name, &created, &d.Certs, &d.Retired, &d.Open, &d.Endpoints); err != nil {
			return nil, err
		}
		d.CreatedAt = fromUnix(created)
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeleteDomain removes a domain and everything recorded for it.
func (s *Store) DeleteDomain(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM domains WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete domain: %w", err)
	}
	return affectedOne(res)
}
