package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/amit/47certificates/internal/phase"
	"github.com/amit/47certificates/internal/x509eval"
)

// UpsertEndpoint records an observed host/port/ip and returns its id.
func (s *Store) UpsertEndpoint(ctx context.Context, host string, port int, ip string, scanID int64) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO endpoints (hostname, port, ip, first_seen_scan, last_seen_scan)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT (hostname, port, ip) DO UPDATE SET last_seen_scan = excluded.last_seen_scan
		 RETURNING id`,
		host, port, ip, scanID, scanID).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store: upsert endpoint: %w", err)
	}
	return id, nil
}

// UpsertCert records a certificate and returns its id. Re-observing a retired
// certificate clears retired_at.
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
		                    ari_url, ocsp_url, crl_url, first_seen, last_seen, raw_der)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (fingerprint_sha256) DO UPDATE SET
		   subject = excluded.subject, issuer_dn = excluded.issuer_dn,
		   not_before = excluded.not_before, not_after = excluded.not_after,
		   lifetime_days = excluded.lifetime_days, key_alg = excluded.key_alg,
		   key_bits = excluded.key_bits, sig_alg = excluded.sig_alg,
		   san_json = excluded.san_json, chain_json = excluded.chain_json,
		   ari_url = excluded.ari_url, ocsp_url = excluded.ocsp_url,
		   crl_url = excluded.crl_url, last_seen = excluded.last_seen,
		   raw_der = excluded.raw_der, retired_at = NULL
		 RETURNING id`,
		c.Fingerprint, c.Subject, c.Issuer, toUnix(c.NotBefore), toUnix(c.NotAfter),
		c.LifetimeDays, c.KeyAlg, c.KeyBits, c.SigAlg, string(sans), string(chain),
		c.ARIURL, c.OCSPURL, c.CRLURL, now, now, c.Raw).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store: upsert cert: %w", err)
	}
	return id, nil
}

// RecordObservation links a scan, endpoint, and certificate.
func (s *Store) RecordObservation(ctx context.Context, scanID, endpointID, certID int64, v x509eval.Verdict, tlsVersion, cipher uint16, caa []string) error {
	caaJSON, err := json.Marshal(caa)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO observations
		 (scan_id, endpoint_id, cert_id, trust, chain_valid, hostname_valid, expired, tls_version, cipher, caa_json)
		 VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)`,
		scanID, endpointID, certID, v.Trust, boolInt(v.ChainValid), boolInt(v.HostnameValid),
		int(tlsVersion), int(cipher), string(caaJSON))
	return err
}

// SyncFindings upserts the findings for one cert/endpoint pair, preserving
// first_seen and any acknowledgement.
func (s *Store) SyncFindings(ctx context.Context, scanID, certID int64, endpointID *int64, fs []x509eval.Finding, now time.Time) error {
	ep := int64(0)
	if endpointID != nil {
		ep = *endpointID
	}
	phaseName := phase.For(now).Name
	for _, f := range fs {
		detail, err := json.Marshal(f.Detail)
		if err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO findings (cert_id, endpoint_id, type, phase, detail_json, first_seen, last_seen)
			 VALUES (?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT (cert_id, endpoint_id, type) DO UPDATE SET
			   detail_json = excluded.detail_json, last_seen = excluded.last_seen`,
			certID, ep, f.Type, phaseName, string(detail), toUnix(now), toUnix(now)); err != nil {
			return fmt.Errorf("store: sync finding %s: %w", f.Type, err)
		}
	}
	return nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
