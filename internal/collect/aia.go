package collect

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxAIAURLs bounds how many caIssuers URLs one certificate may supply.
const maxAIAURLs = 3

// AIAFetcher downloads CA certificates from caIssuers URLs under a strict
// policy: http(s) only, no IP literals in private or special ranges, no
// redirects, a short timeout, and a hard size cap.
type AIAFetcher struct {
	client   *http.Client
	maxBytes int64
}

// NewAIAFetcher returns a fetcher. A nil client is replaced by a default one.
// maxBytes <= 0 means 1 MiB.
func NewAIAFetcher(client *http.Client, maxBytes int64) *AIAFetcher {
	if client == nil {
		client = &http.Client{}
	}
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	return &AIAFetcher{client: client, maxBytes: maxBytes}
}

// Fetch returns the DER certificates found at urls. It stops at the first URL
// that yields a certificate.
func (f *AIAFetcher) Fetch(ctx context.Context, urls []string) ([][]byte, error) {
	if len(urls) == 0 {
		return nil, fmt.Errorf("aia: no URLs")
	}
	if len(urls) > maxAIAURLs {
		return nil, fmt.Errorf("aia: %d URLs exceeds limit of %d", len(urls), maxAIAURLs)
	}
	var errs []string
	for _, u := range urls {
		ders, err := f.fetchOne(ctx, u)
		if err == nil {
			return ders, nil
		}
		errs = append(errs, fmt.Sprintf("%s: %v", u, err))
	}
	return nil, fmt.Errorf("aia: %s", strings.Join(errs, "; "))
}

func (f *AIAFetcher) fetchOne(ctx context.Context, raw string) ([][]byte, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("scheme %q is not allowed", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing host")
	}
	if ip := net.ParseIP(host); ip != nil && unsafeIP(ip) {
		return nil, fmt.Errorf("address %s is not routable", host)
	}
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return nil, fmt.Errorf("address %s is not routable", host)
	}

	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "47c/1 certificate inventory")

	client := *f.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > f.maxBytes {
		return nil, fmt.Errorf("body exceeds %d bytes", f.maxBytes)
	}
	ders := parseCerts(body)
	if len(ders) == 0 {
		return nil, fmt.Errorf("no certificate found")
	}
	return ders, nil
}

// parseCerts accepts a PEM bundle or concatenated DER certificates.
func parseCerts(body []byte) [][]byte {
	var out [][]byte
	rest := body
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			out = append(out, append([]byte{}, block.Bytes...))
		}
	}
	if len(out) > 0 {
		return out
	}
	if parsed, err := x509.ParseCertificates(body); err == nil {
		for _, c := range parsed {
			out = append(out, c.Raw)
		}
	}
	return out
}

func unsafeIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}
