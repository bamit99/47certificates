package discover

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/amit/47certificates/internal/roots"
)

const maxCTBody = 8 << 20

// CRTSource queries the crt.sh JSON endpoint.
type CRTSource struct {
	client *http.Client
	base   string
}

// NewCRTSource returns a crt.sh source. A nil client gets a bounded default.
// base defaults to https://crt.sh/ and is injectable for tests.
func NewCRTSource(client *http.Client, base ...string) *CRTSource {
	b := "https://crt.sh/"
	if len(base) > 0 && base[0] != "" {
		b = base[0]
	}
	return &CRTSource{client: clientOr(client), base: strings.TrimSuffix(b, "/")}
}

// Names returns every hostname crt.sh knows for domain and its subdomains.
func (c *CRTSource) Names(ctx context.Context, domain string) ([]string, error) {
	u := c.base + "/?q=" + url.QueryEscape("%."+domain) + "&output=json"
	body, err := getJSON(ctx, c.client, u)
	if err != nil {
		return nil, fmt.Errorf("crt.sh: %w", err)
	}
	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("crt.sh: decode: %w", err)
	}
	var out []string
	for _, r := range rows {
		for _, line := range strings.Split(r.NameValue, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				out = append(out, line)
			}
		}
	}
	return dedupePreserve(out), nil
}

// CertSpotterSource queries the Cert Spotter issuances API.
type CertSpotterSource struct {
	client *http.Client
	base   string
}

// NewCertSpotterSource returns a Cert Spotter source. A nil client gets a
// bounded default. base defaults to https://api.certspotter.com and is
// injectable for tests.
func NewCertSpotterSource(client *http.Client, base ...string) *CertSpotterSource {
	b := "https://api.certspotter.com"
	if len(base) > 0 && base[0] != "" {
		b = base[0]
	}
	return &CertSpotterSource{client: clientOr(client), base: strings.TrimSuffix(b, "/")}
}

// Names returns every hostname Cert Spotter has issued for domain.
func (c *CertSpotterSource) Names(ctx context.Context, domain string) ([]string, error) {
	u := c.base + "/v1/issuances?domain=" + url.QueryEscape(domain) + "&include_subdomains=true"
	body, err := getJSON(ctx, c.client, u)
	if err != nil {
		return nil, fmt.Errorf("certspotter: %w", err)
	}
	var rows []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("certspotter: decode: %w", err)
	}
	var out []string
	for _, r := range rows {
		for _, n := range r.DNSNames {
			if n = strings.TrimSpace(n); n != "" {
				out = append(out, n)
			}
		}
	}
	return dedupePreserve(out), nil
}

func clientOr(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return roots.HTTPClient(20 * time.Second)
}

func getJSON(ctx context.Context, client *http.Client, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "47c/1 certificate inventory")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxCTBody))
}

// dedupePreserve removes duplicates without reordering: the sources return
// names in a stable, human-friendly order and tests pin it.
func dedupePreserve(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, v := range in {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
