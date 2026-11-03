// Package notify delivers report notifications.
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"
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

// Send posts body and verifies the 2xx response.
func (w Webhook) Send(ctx context.Context, reportID int64, body []byte) error {
	if w.URL == "" {
		return fmt.Errorf("notify: webhook URL is empty")
	}
	mac := hmac.New(sha256.New, []byte(w.Secret))
	mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	client := w.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
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
