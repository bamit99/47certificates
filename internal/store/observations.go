package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// ObservationRow is one endpoint/certificate pair seen by a scan, flattened
// for export and reporting.
type ObservationRow struct {
	Host          string    `json:"host"`
	Port          int       `json:"port"`
	IP            string    `json:"ip"`
	Fingerprint   string    `json:"fingerprint_sha256"`
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	LifetimeDays  int       `json:"lifetime_days"`
	KeyAlg        string    `json:"key_alg"`
	KeyBits       int       `json:"key_bits"`
	SigAlg        string    `json:"sig_alg"`
	Trust         string    `json:"trust"`
	ChainValid    bool      `json:"chain_valid"`
	HostnameValid bool      `json:"hostname_valid"`
	TLSVersion    uint16    `json:"tls_version"`
	Cipher        uint16    `json:"cipher"`
}

// ScanObservationRows returns every observation of one scan, ordered for
// reading. It is the data source for CSV, JSON, and report rendering.
func (s *Store) ScanObservationRows(ctx context.Context, scanID int64) ([]ObservationRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT e.hostname, e.port, e.ip,
		       c.fingerprint_sha256, COALESCE(c.subject, ''), COALESCE(c.issuer_dn, ''),
		       c.not_before, c.not_after, c.lifetime_days,
		       COALESCE(c.key_alg, ''), c.key_bits, COALESCE(c.sig_alg, ''),
		       COALESCE(o.trust, ''), o.chain_valid, o.hostname_valid,
		       o.tls_version, o.cipher
		FROM observations o
		JOIN endpoints e ON e.id = o.endpoint_id
		JOIN certs c ON c.id = o.cert_id
		WHERE o.scan_id = ?
		ORDER BY e.hostname, e.port, c.not_after`, scanID)
	if err != nil {
		return nil, fmt.Errorf("store: scan rows: %w", err)
	}
	defer rows.Close()

	var out []ObservationRow
	for rows.Next() {
		var (
			r        ObservationRow
			nb, na   int64
			tlsv, cs sql.NullInt64
		)
		if err := rows.Scan(&r.Host, &r.Port, &r.IP, &r.Fingerprint, &r.Subject, &r.Issuer,
			&nb, &na, &r.LifetimeDays, &r.KeyAlg, &r.KeyBits, &r.SigAlg,
			&r.Trust, &r.ChainValid, &r.HostnameValid, &tlsv, &cs); err != nil {
			return nil, err
		}
		r.NotBefore = fromUnix(nb)
		r.NotAfter = fromUnix(na)
		r.TLSVersion = uint16(tlsv.Int64)
		r.Cipher = uint16(cs.Int64)
		out = append(out, r)
	}
	return out, rows.Err()
}
