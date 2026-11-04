// Package notify delivers report notifications.
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/amit/47certificates/internal/roots"
)

// Webhook posts report notifications to an HTTPS endpoint with an HMAC
// signature in the X-47C-Signature header.
type Webhook struct {
	// URL is the endpoint to POST to.
	URL string
	// Secret signs the body as "sha256=<hex HMAC-SHA256(secret, body)>".
	Secret string
	// Client, when nil, is replaced by a client with a 10s timeout.
	Client *http.Client
}

// ErrUnsafeURL is returned when a webhook URL points at an address that must
// not be contacted from the server.
var ErrUnsafeURL = errors.New("notify: webhook URL is not allowed")

// ValidateWebhookURL rejects a webhook URL that must not be contacted.
//
// Link-local addresses are refused: the cloud metadata endpoint
// (169.254.169.254) lives there and a report webhook has no business
// reaching it. Private and loopback addresses are allowed: a report receiver
// on the operator's own LAN is a normal deployment.
func ValidateWebhookURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnsafeURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: scheme %q", ErrUnsafeURL, u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: missing host", ErrUnsafeURL)
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLinkLocalUnicast() {
		return fmt.Errorf("%w: address %s is link-local", ErrUnsafeURL, host)
	}
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return fmt.Errorf("%w: address %s is loopback", ErrUnsafeURL, host)
	}
	return nil
}

// Send posts body and verifies the 2xx response.
func (w Webhook) Send(ctx context.Context, reportID int64, body []byte) error {
	if w.URL == "" {
		return fmt.Errorf("notify: webhook URL is empty")
	}
	if err := ValidateWebhookURL(w.URL); err != nil {
		return err
	}
	mac := hmac.New(sha256.New, []byte(w.Secret))
	mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	client := w.Client
	if client == nil {
		client = roots.HTTPClient(10 * time.Second)
	}
	// A redirect could point the delivery at a different host than the one
	// the operator configured. Webhook endpoints do not redirect.
	client = refuseRedirects(client)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notify: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "47c/1 report delivery")
	req.Header.Set("X-47C-Signature", sig)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("notify: post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("notify: webhook returned status %d", resp.StatusCode)
	}
	return nil
}

// refuseRedirects returns a copy of the client that does not follow
// redirects.
func refuseRedirects(c *http.Client) *http.Client {
	clone := *c
	clone.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &clone
}
