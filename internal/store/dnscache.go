package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// DNSCache stores the answer the resolver gave for a hostname, so a later
// scan does not ask again.
//
// A scan resolves every name a certificate transparency log mentions. Most
// of those names are retired and do not exist, so most of the queries are
// answered "no such host". Asking again every scan is what makes a scan
// look like a flood to the resolver, and it changes nothing: a name that did
// not exist a moment ago still does not.
//
// The cache holds the negative answers too. That is the point.
type DNSCache struct {
	s *Store
}

// DNSCache returns the cache of DNS answers.
func (s *Store) DNSCache() *DNSCache { return &DNSCache{s: s} }

// DNSAnswer is one cached resolution.
type DNSAnswer struct {
	IPs   []string
	CNAME string
	// NXDomain is true when the name does not exist.
	NXDomain bool
}

// Lookup returns the cached answer for host.
//
// The second return value reports whether the cache holds an answer at all.
// An answer that is older than maxAge is treated as missing.
func (c *DNSCache) Lookup(ctx context.Context, host string, maxAge time.Duration) (DNSAnswer, bool) {
	var (
		ipsJSON  string
		cname    string
		nxdomain int
		at       int64
	)
	err := c.s.db.QueryRowContext(ctx,
		`SELECT ips, cname, nxdomain, at FROM dns_cache WHERE hostname = ?`, host).
		Scan(&ipsJSON, &cname, &nxdomain, &at)
	if err != nil {
		if err == sql.ErrNoRows {
			return DNSAnswer{}, false
		}
		return DNSAnswer{}, false
	}
	if maxAge > 0 && time.Since(fromUnix(at)) > maxAge {
		return DNSAnswer{}, false
	}
	var ips []string
	if ipsJSON != "" {
		_ = json.Unmarshal([]byte(ipsJSON), &ips)
	}
	return DNSAnswer{IPs: ips, CNAME: cname, NXDomain: nxdomain != 0}, true
}

// Store records the answer for host.
func (c *DNSCache) Store(ctx context.Context, host string, a DNSAnswer) error {
	ips, err := json.Marshal(a.IPs)
	if err != nil {
		return err
	}
	nx := 0
	if a.NXDomain {
		nx = 1
	}
	_, err = c.s.db.ExecContext(ctx,
		`INSERT INTO dns_cache (hostname, ips, cname, nxdomain, at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT (hostname) DO UPDATE SET
		   ips = excluded.ips, cname = excluded.cname,
		   nxdomain = excluded.nxdomain, at = excluded.at`,
		host, string(ips), a.CNAME, nx, toUnix(time.Now()))
	if err != nil {
		return fmt.Errorf("store: cache dns %s: %w", host, err)
	}
	return nil
}

// PruneDNSCache removes entries older than maxAge and returns how many rows
// were deleted.
func (c *DNSCache) PruneDNSCache(ctx context.Context, maxAge time.Duration) (int64, error) {
	if maxAge <= 0 {
		return 0, nil
	}
	res, err := c.s.db.ExecContext(ctx,
		`DELETE FROM dns_cache WHERE at < ?`, toUnix(time.Now().Add(-maxAge)))
	if err != nil {
		return 0, fmt.Errorf("store: prune dns cache: %w", err)
	}
	return res.RowsAffected()
}

// ForgetDNS removes one entry.
func (c *DNSCache) ForgetDNS(ctx context.Context, host string) error {
	_, err := c.s.db.ExecContext(ctx, `DELETE FROM dns_cache WHERE hostname = ?`, strings.ToLower(host))
	return err
}
