package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/amit/47certificates/internal/phase"
	"github.com/amit/47certificates/internal/x509eval"
)

// UpsertEndpoint records an observed host/port/ip for a domain and returns
// its id.
func (s *Store) UpsertEndpoint(ctx context.Context, domainID int64, host string, port int, ip string, scanID int64) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO endpoints (hostname, port, ip, domain_id, first_seen_scan, last_seen_scan)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT (hostname, port, ip) DO UPDATE SET last_seen_scan = excluded.last_seen_scan
		 RETURNING id`,
		host, port, ip, domainID, scanID, scanID).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store: upsert endpoint: %w", err)
	}
	return id, nil
}

// UpsertCert records a certificate and returns its id.
//
// It writes metadata only. The lifecycle columns (last_seen, retired_at) are
// owned by MarkSeen and RetireUnseen, which run only for scans that end
// "done": a cancelled or failed scan must not move last_seen or resurrect a
// retired certificate.
func (s *Store) UpsertCert(ctx context.Context, c x509eval.Cert) (int64, error) {
	sans, err := json.Marshal(c.SANs)
	if err != nil {
		return 0, err
	}
	chain, err := json.Marshal(c.Chain)
	if err != nil {
		return 0, err
	}
	now := toUnix(time.Now())
	var id int64
	err = s.db.QueryRowContext(ctx,
		`INSERT INTO certs (fingerprint_sha256, subject, issuer_dn, not_before, not_after,
		                    lifetime_days, key_alg, key_bits, sig_alg, san_json, chain_json,
		                    ari_url, ocsp_url, crl_url, first_seen, raw_der)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (fingerprint_sha256) DO UPDATE SET
		   subject = excluded.subject, issuer_dn = excluded.issuer_dn,
		   not_before = excluded.not_before, not_after = excluded.not_after,
		   lifetime_days = excluded.lifetime_days, key_alg = excluded.key_alg,
		   key_bits = excluded.key_bits, sig_alg = excluded.sig_alg,
		   san_json = excluded.san_json, chain_json = excluded.chain_json,
		   ari_url = excluded.ari_url, ocsp_url = excluded.ocsp_url,
		   crl_url = excluded.crl_url, raw_der = excluded.raw_der
		 RETURNING id`,
		c.Fingerprint, c.Subject, c.Issuer, toUnix(c.NotBefore), toUnix(c.NotAfter),
		c.LifetimeDays, c.KeyAlg, c.KeyBits, c.SigAlg, string(sans), string(chain),
		c.ARIURL, c.OCSPURL, c.CRLURL, now, c.Raw).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store: upsert cert: %w", err)
	}
	return id, nil
}

// MarkSeen updates the lifecycle of every certificate a domain observed in a
// scan that ended "done": last_seen becomes now and retired_at is cleared,
// because the certificate is being served right now. It does nothing for
// scans that did not finish.
//
// The lifecycle is per domain: a certificate colt.net stopped serving is
// retired there and still live at iana.org.
func (s *Store) MarkSeen(ctx context.Context, scanID, domainID int64) error {
	var status string
	if err := s.db.QueryRowContext(ctx, `SELECT status FROM scans WHERE id = ?`, scanID).Scan(&status); err != nil {
		return err
	}
	if status != "done" {
		return nil
	}
	now := toUnix(time.Now())
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO domain_certs (domain_id, cert_id, first_seen, last_seen, retired_at)
		SELECT ?, cert_id, ?, ?, NULL FROM observations WHERE scan_id = ?
		ON CONFLICT (domain_id, cert_id) DO UPDATE SET
		    last_seen = excluded.last_seen, retired_at = NULL`,
		domainID, now, now, scanID)
	if err != nil {
		return fmt.Errorf("store: mark seen: %w", err)
	}
	return nil
}

// RecordObservation links a scan, endpoint, and certificate.
func (s *Store) RecordObservation(ctx context.Context, scanID, domainID, endpointID, certID int64, v x509eval.Verdict, tlsVersion, cipher uint16, caa []string) error {
	caaJSON, err := json.Marshal(caa)
	if err != nil {
		return err
	}
	now := toUnix(time.Now())
	_, err = s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO observations
		 (scan_id, endpoint_id, cert_id, domain_id, trust, chain_valid, hostname_valid, expired, tls_version, cipher, caa_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?,
		         (SELECT CASE WHEN not_after IS NOT NULL AND not_after < ? THEN 1 ELSE 0 END FROM certs WHERE id = ?),
		         ?, ?, ?)`,
		scanID, endpointID, certID, domainID, v.Trust, boolInt(v.ChainValid), boolInt(v.HostnameValid),
		now, certID,
		int(tlsVersion), int(cipher), string(caaJSON))
	return err
}

// SyncFindings upserts the findings for one cert/endpoint pair, preserving
// first_seen and any acknowledgement.
//
// endpointID is nil for certificate-level findings (one row per certificate)
// and points at the endpoint for endpoint-level findings. Rows in the same
// scope whose type is not in fs are resolved: the condition no longer holds.
func (s *Store) SyncFindings(ctx context.Context, scanID, domainID, certID int64, endpointID *int64, fs []x509eval.Finding, now time.Time) error {
	var ep any
	if endpointID != nil {
		ep = *endpointID
	}
	phaseName := phase.For(now).Name
	present := make([]string, 0, len(fs))
	for _, f := range fs {
		present = append(present, f.Type)
		detail, err := json.Marshal(f.Detail)
		if err != nil {
			return err
		}
		var findingID int64
		row := s.db.QueryRowContext(ctx,
			`SELECT id FROM findings
			 WHERE domain_id IS ? AND cert_id = ? AND COALESCE(endpoint_id, 0) = COALESCE(?, 0) AND type = ?`,
			domainID, certID, ep, f.Type)
		if err := row.Scan(&findingID); err == sql.ErrNoRows {
			if _, err := s.db.ExecContext(ctx,
				`INSERT INTO findings (domain_id, cert_id, endpoint_id, type, phase, detail_json, first_seen, last_seen, scan_id)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				domainID, certID, ep, f.Type, phaseName, string(detail), toUnix(now), toUnix(now), scanID); err != nil {
				return fmt.Errorf("store: sync finding %s: %w", f.Type, err)
			}
			continue
		} else if err != nil {
			return err
		}
		// A finding that was resolved and is true again is open again. An
		// acknowledgement survives a scan that still finds the condition.
		if _, err := s.db.ExecContext(ctx,
			`UPDATE findings
			 SET detail_json = ?, last_seen = ?, scan_id = ?,
			     status = CASE WHEN status = 'resolved' THEN 'open' ELSE status END
			 WHERE id = ?`,
			string(detail), toUnix(now), scanID, findingID); err != nil {
			return fmt.Errorf("store: sync finding %s: %w", f.Type, err)
		}
	}
	return s.resolveMissing(ctx, domainID, certID, ep, present)
}

// resolveMissing closes the findings in one scope whose type is not in
// present. Acknowledged rows are left alone: they record a decision the
// operator made, not a live condition.
func (s *Store) resolveMissing(ctx context.Context, domainID, certID int64, ep any, present []string) error {
	args := []any{domainID, certID, ep}
	query := `UPDATE findings SET status = 'resolved'
	          WHERE domain_id IS ? AND cert_id = ? AND COALESCE(endpoint_id, 0) = COALESCE(?, 0)
	            AND status IN ('open', 'snoozed')`
	if len(present) > 0 {
		query += ` AND type NOT IN (` + placeholders(len(present)) + `)`
		for _, t := range present {
			args = append(args, t)
		}
	}
	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("store: resolve findings: %w", err)
	}
	return nil
}

// ResolveStaleFindings closes the findings of certificates this scan observed
// but did not confirm. It runs only for a scan that ended "done": a cancelled
// scan must not close anything.
//
// A finding row records the scan that last confirmed it. Anything still
// carrying an older scan id was not confirmed by this run.
func (s *Store) ResolveStaleFindings(ctx context.Context, scanID, domainID int64) error {
	var status string
	if err := s.db.QueryRowContext(ctx, `SELECT status FROM scans WHERE id = ?`, scanID).Scan(&status); err != nil {
		return err
	}
	if status != "done" {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE findings SET status = 'resolved'
		 WHERE status IN ('open', 'snoozed')
		   AND domain_id IS ?
		   AND cert_id IN (SELECT cert_id FROM observations WHERE scan_id = ?)
		   AND (scan_id IS NULL OR scan_id <> ?)`,
		domainID, scanID, scanID)
	return err
}

// RetireFindings closes the open findings of a retired certificate: the
// conditions they describe no longer hold because nothing serves it.
func (s *Store) RetireFindings(ctx context.Context, certIDs []int64) error {
	if len(certIDs) == 0 {
		return nil
	}
	args := make([]any, 0, len(certIDs))
	query := `UPDATE findings SET status = 'resolved'
	          WHERE status IN ('open', 'snoozed') AND cert_id IN (`
	for i, id := range certIDs {
		if i > 0 {
			query += ","
		}
		query += "?"
		args = append(args, id)
	}
	query += ")"
	_, err := s.db.ExecContext(ctx, query, args...)
	return err
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
