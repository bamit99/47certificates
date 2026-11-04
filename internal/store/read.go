package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Finding is one persisted finding row, without interpretation.
type Finding struct {
	ID          int64
	Type        string
	Detail      string
	Status      string
	SnoozeUntil *time.Time
}

// CertSummary is a certificate with its findings, for read paths.
type CertSummary struct {
	ID           int64
	Fingerprint  string
	Subject      string
	Issuer       string
	NotBefore    time.Time
	NotAfter     time.Time
	LifetimeDays int
	KeyAlg       string
	KeyBits      int
	SigAlg       string
	SANs         []string
	FirstSeen    time.Time
	LastSeen     *time.Time
	RetiredAt    *time.Time
	HasRaw       bool
	Findings     []Finding
	// Endpoints are the endpoints of the domain that served the certificate.
	Endpoints []CertEndpoint
}

// CertEndpoint is one endpoint that served a certificate.
type CertEndpoint struct {
	Host          string
	Port          int
	IP            string
	Trust         string
	ChainValid    bool
	HostnameValid bool
}

// ScopeEntry is one row of the allowlist.
type ScopeEntry struct {
	ID        int64
	Kind      string
	Value     string
	Note      string
	CreatedAt time.Time
}

func nullI64(v sql.NullInt64) *int64 {
	if !v.Valid {
		return nil
	}
	x := v.Int64
	return &x
}

// ListCerts returns the certificates of one domain with their findings,
// ordered by expiry.
//
// The certificate's own metadata is global, but which certificates a domain
// serves, and the lifecycle within it, are per domain: a certificate
// colt.net stopped serving is retired there and still live at iana.org.
func (s *Store) ListCerts(ctx context.Context, domainID int64) ([]CertSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT c.id, c.fingerprint_sha256, COALESCE(c.subject, ''), COALESCE(c.issuer_dn, ''),
		       c.not_before, c.not_after, c.lifetime_days, COALESCE(c.key_alg, ''), c.key_bits,
		       COALESCE(c.sig_alg, ''), COALESCE(c.san_json, '[]'), c.first_seen,
		       dc.last_seen, dc.retired_at,
		       c.raw_der IS NOT NULL AND length(c.raw_der) > 0
		FROM certs c
		LEFT JOIN domain_certs dc ON dc.cert_id = c.id AND dc.domain_id = ?
		WHERE dc.cert_id IS NOT NULL
		   OR EXISTS (SELECT 1 FROM observations o
		               WHERE o.cert_id = c.id AND o.domain_id = ?)
		   OR EXISTS (SELECT 1 FROM findings f
		               WHERE f.cert_id = c.id AND f.domain_id = ?)
		ORDER BY c.not_after ASC, c.id ASC`, domainID, domainID, domainID)
	if err != nil {
		return nil, fmt.Errorf("store: list certs: %w", err)
	}
	defer rows.Close()

	byID := map[int64]int{}
	var out []CertSummary
	for rows.Next() {
		var (
			c       CertSummary
			nb, na  int64
			first   int64
			last    sql.NullInt64
			retired sql.NullInt64
			sans    string
		)
		if err := rows.Scan(&c.ID, &c.Fingerprint, &c.Subject, &c.Issuer, &nb, &na,
			&c.LifetimeDays, &c.KeyAlg, &c.KeyBits, &c.SigAlg, &sans, &first, &last,
			&retired, &c.HasRaw); err != nil {
			return nil, err
		}
		c.NotBefore = fromUnix(nb)
		c.NotAfter = fromUnix(na)
		c.FirstSeen = fromUnix(first)
		c.LastSeen = nullTime(nullI64(last))
		c.RetiredAt = nullTime(nullI64(retired))
		if err := json.Unmarshal([]byte(sans), &c.SANs); err != nil {
			c.SANs = nil
		}
		byID[c.ID] = len(out)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// The endpoints of the domain that served each certificate.
	eps, err := s.db.QueryContext(ctx, `
		SELECT o.cert_id, e.hostname, e.port, e.ip, COALESCE(o.trust, ''),
		       o.chain_valid, o.hostname_valid
		FROM observations o
		JOIN endpoints e ON e.id = o.endpoint_id
		WHERE o.domain_id IS ?
		ORDER BY e.hostname, e.port`, domainID)
	if err != nil {
		return nil, err
	}
	defer eps.Close()
	for eps.Next() {
		var (
			certID int64
			e      CertEndpoint
		)
		if err := eps.Scan(&certID, &e.Host, &e.Port, &e.IP, &e.Trust, &e.ChainValid, &e.HostnameValid); err != nil {
			return nil, err
		}
		if i, ok := byID[certID]; ok {
			out[i].Endpoints = append(out[i].Endpoints, e)
		}
	}
	if err := eps.Err(); err != nil {
		return nil, err
	}

	fs, err := s.db.QueryContext(ctx, `SELECT cert_id, id, type, COALESCE(detail_json, '{}'), status, snooze_until FROM findings WHERE domain_id IS ?`, domainID)
	if err != nil {
		return nil, err
	}
	defer fs.Close()
	for fs.Next() {
		var (
			certID int64
			f      Finding
			sz     sql.NullInt64
		)
		if err := fs.Scan(&certID, &f.ID, &f.Type, &f.Detail, &f.Status, &sz); err != nil {
			return nil, err
		}
		if sz.Valid {
			t := fromUnix(sz.Int64)
			f.SnoozeUntil = &t
		}
		if i, ok := byID[certID]; ok {
			out[i].Findings = append(out[i].Findings, f)
		}
	}
	return out, fs.Err()
}

// CertByFingerprint loads one certificate of a domain with its findings.
func (s *Store) CertByFingerprint(ctx context.Context, domainID int64, fp string) (CertSummary, error) {
	all, err := s.ListCerts(ctx, domainID)
	if err != nil {
		return CertSummary{}, err
	}
	for _, c := range all {
		if c.Fingerprint == fp {
			return c, nil
		}
	}
	return CertSummary{}, ErrNotFound
}

// CertEndpoints returns the latest observation of this certificate per
// endpoint.
func (s *Store) CertEndpoints(ctx context.Context, domainID, certID int64) ([]CertEndpoint, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT e.hostname, e.port, e.ip, COALESCE(o.trust, ''), o.chain_valid, o.hostname_valid
		FROM observations o
		JOIN endpoints e ON e.id = o.endpoint_id
		WHERE o.cert_id = ? AND o.domain_id IS ?
		  AND o.scan_id = (
		    SELECT MAX(o2.scan_id) FROM observations o2
		    WHERE o2.endpoint_id = o.endpoint_id AND o2.cert_id = o.cert_id
		  )
		ORDER BY e.hostname, e.port`, certID, domainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CertEndpoint
	for rows.Next() {
		var e CertEndpoint
		if err := rows.Scan(&e.Host, &e.Port, &e.IP, &e.Trust, &e.ChainValid, &e.HostnameValid); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CertPEM returns the stored leaf certificate as PEM.
func (s *Store) CertPEM(ctx context.Context, fp string) ([]byte, error) {
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT raw_der FROM certs WHERE fingerprint_sha256 = ?`, fp).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("store: certificate %s has no stored DER", fp)
	}
	return raw, nil
}

// ListScans returns the scans of one domain, newest first. A domain id of
// zero returns the scans of every domain.
func (s *Store) ListScans(ctx context.Context, domainID int64, limit int) ([]Scan, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `
		SELECT s.id, s.started_at, s.finished_at, s.status, s.trigger, s.triggered_by,
		       s.domain_id, s.stats_json, s.error, COALESCE(d.name, '')
		FROM scans s LEFT JOIN domains d ON d.id = s.domain_id`
	args := []any{}
	if domainID > 0 {
		query += ` WHERE s.domain_id = ?`
		args = append(args, domainID)
	}
	query += ` ORDER BY s.id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Scan
	for rows.Next() {
		var (
			sc      Scan
			started int64
			fin     sql.NullInt64
			by      sql.NullInt64
			dom     sql.NullInt64
			stats   sql.NullString
			scanErr sql.NullString
		)
		if err := rows.Scan(&sc.ID, &started, &fin, &sc.Status, &sc.Trigger, &by, &dom, &stats, &scanErr, &sc.Domain); err != nil {
			return nil, err
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
		out = append(out, sc)
	}
	return out, rows.Err()
}

// ListScope returns every allowlist row.
func (s *Store) ListScope(ctx context.Context) ([]ScopeEntry, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, kind, value, COALESCE(note, ''), created_at FROM scope_entries
		ORDER BY kind, value`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScopeEntry
	for rows.Next() {
		var (
			e  ScopeEntry
			at int64
		)
		if err := rows.Scan(&e.ID, &e.Kind, &e.Value, &e.Note, &at); err != nil {
			return nil, err
		}
		e.CreatedAt = fromUnix(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// DomainHosts returns hostnames in the endpoint inventory under domain.
func (s *Store) DomainHosts(ctx context.Context, domain string) ([]string, error) {
	// The LIKE pattern is built from the domain, so the wildcards in it are
	// escaped: a domain of "%" must not match every hostname.
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT hostname FROM endpoints
		WHERE hostname = ? OR hostname LIKE ? ESCAPE '\'
		ORDER BY hostname`, domain, "%."+escapeLike(domain)+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// escapeLike escapes the wildcards of a LIKE pattern.
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}
