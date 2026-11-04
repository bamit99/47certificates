package scan

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/amit/47certificates/internal/csvsafe"
	"github.com/amit/47certificates/internal/store"
)

var csvHeader = []string{
	"hostname", "port", "ip", "fingerprint_sha256", "subject", "issuer",
	"not_before", "not_after", "lifetime_days", "key_alg", "key_bits",
	"sig_alg", "trust", "chain_valid", "hostname_valid", "tls_version", "cipher",
}

// ExportCSV writes one scan's observations as CSV.
func ExportCSV(ctx context.Context, st *store.Store, scanID int64, w io.Writer) error {
	rows, err := st.ScanObservationRows(ctx, scanID)
	if err != nil {
		return err
	}
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	for _, r := range rows {
		rec := []string{
			r.Host, strconv.Itoa(r.Port), r.IP, r.Fingerprint, r.Subject, r.Issuer,
			r.NotBefore.Format(time.RFC3339), r.NotAfter.Format(time.RFC3339),
			strconv.Itoa(r.LifetimeDays), r.KeyAlg, strconv.Itoa(r.KeyBits), r.SigAlg,
			r.Trust, strconv.FormatBool(r.ChainValid), strconv.FormatBool(r.HostnameValid),
			strconv.Itoa(int(r.TLSVersion)), strconv.Itoa(int(r.Cipher)),
		}
		if err := cw.Write(csvsafe.Row(rec)); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// ExportJSON writes one scan's observations as a JSON document.
func ExportJSON(ctx context.Context, st *store.Store, scanID int64, w io.Writer) error {
	rows, err := st.ScanObservationRows(ctx, scanID)
	if err != nil {
		return err
	}
	doc := struct {
		ScanID      int64                  `json:"scan_id"`
		GeneratedAt time.Time              `json:"generated_at"`
		Rows        []store.ObservationRow `json:"rows"`
	}{
		ScanID:      scanID,
		GeneratedAt: time.Now().UTC(),
		Rows:        rows,
	}
	if doc.Rows == nil {
		doc.Rows = []store.ObservationRow{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func jsonStats(s Stats) ([]byte, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("scan: encode stats: %w", err)
	}
	return b, nil
}
