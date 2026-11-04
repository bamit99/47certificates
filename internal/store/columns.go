package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// CertColumn is one column of the certificate list.
type CertColumn struct {
	// Key identifies the column in the preference and in the template.
	Key string `json:"key"`
	// Label is the heading.
	Label string `json:"label"`
	// Title explains the column.
	Title string `json:"title"`
}

// CertColumns are the columns the certificate list can show.
var CertColumns = []CertColumn{
	{Key: "fingerprint", Label: "Fingerprint", Title: "SHA-256 of the certificate"},
	{Key: "subject", Label: "Subject", Title: "The certificate's subject"},
	{Key: "issuer", Label: "Issuer", Title: "The certificate authority that issued it"},
	{Key: "sans", Label: "SANs", Title: "The names the certificate covers"},
	{Key: "not_before", Label: "Not before", Title: "When the certificate became valid"},
	{Key: "not_after", Label: "Expires", Title: "When the certificate expires"},
	{Key: "lifetime", Label: "Lifetime", Title: "How many days the certificate is valid for"},
	{Key: "key", Label: "Key", Title: "The public key algorithm and size"},
	{Key: "signature", Label: "Signature", Title: "The signature algorithm"},
	{Key: "trust", Label: "Trust", Title: "Whether the chain anchors in a public root"},
	{Key: "chain", Label: "Chain", Title: "Whether the chain is valid"},
	{Key: "hostname", Label: "Hostname", Title: "Whether the certificate covers the served name"},
	{Key: "bucket", Label: "Bucket", Title: "The impact bucket the certificate falls in"},
	{Key: "severity", Label: "Severity", Title: "The severity of the worst finding"},
	{Key: "days_left", Label: "Days left", Title: "Days until the certificate expires"},
	{Key: "endpoints", Label: "Endpoints", Title: "The endpoints serving the certificate"},
	{Key: "first_seen", Label: "First seen", Title: "When the certificate was first observed"},
	{Key: "last_seen", Label: "Last seen", Title: "When the certificate was last observed"},
	{Key: "retired", Label: "Retired", Title: "Whether the domain stopped serving the certificate"},
}

// DefaultCertColumns are shown until the operator chooses otherwise.
var DefaultCertColumns = []string{
	"fingerprint", "subject", "issuer", "sans", "not_after",
	"lifetime", "trust", "bucket", "severity", "days_left", "endpoints",
}

// certColumnKey is the settings key holding one user's column choice.
func certColumnKey(userID int64) string {
	return fmt.Sprintf("ui.cert_columns.%d", userID)
}

// CertColumnPreference is the column set a user chose.
type CertColumnPreference struct {
	Columns []string `json:"columns"`
}

// GetCertColumns returns the columns a user chose, and the defaults when
// they have chosen none.
func (s *Store) GetCertColumns(ctx context.Context, userID int64) ([]string, error) {
	v, err := s.GetSetting(ctx, certColumnKey(userID))
	if err != nil {
		return append([]string{}, DefaultCertColumns...), nil
	}
	var pref CertColumnPreference
	if err := json.Unmarshal([]byte(v), &pref); err != nil {
		return append([]string{}, DefaultCertColumns...), nil
	}
	cols := sanitizeColumns(pref.Columns)
	if len(cols) == 0 {
		return append([]string{}, DefaultCertColumns...), nil
	}
	return cols, nil
}

// SetCertColumns records the columns a user chose.
func (s *Store) SetCertColumns(ctx context.Context, userID int64, columns []string) error {
	cols := sanitizeColumns(columns)
	if len(cols) == 0 {
		return fmt.Errorf("store: no columns chosen")
	}
	b, err := json.Marshal(CertColumnPreference{Columns: cols})
	if err != nil {
		return err
	}
	return s.SetSetting(ctx, certColumnKey(userID), string(b))
}

// sanitizeColumns keeps the known columns, in the order given, without
// repeats.
func sanitizeColumns(in []string) []string {
	known := map[string]bool{}
	for _, c := range CertColumns {
		known[c.Key] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range in {
		c = strings.TrimSpace(strings.ToLower(c))
		if c == "" || !known[c] || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}
