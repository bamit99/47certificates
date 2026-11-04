package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bamit99/47certificates/internal/notify"
)

// A webhook URL must not point at a link-local metadata endpoint.
func TestWebhookURLValidation(t *testing.T) {
	bad := []string{
		"http://169.254.169.254/latest/meta-data",
		"https://169.254.169.254/",
		"http://[fe80::1]/",
		"file:///etc/passwd",
		"ftp://example.com/",
		"",
	}
	for _, u := range bad {
		if err := notify.ValidateWebhookURL(u); err == nil {
			t.Errorf("%q should be refused", u)
		}
	}
	good := []string{
		"https://hooks.example.com/47c",
		"http://192.168.1.10:8080/hook",
		"http://127.0.0.1:9000/hook",
	}
	for _, u := range good {
		if err := notify.ValidateWebhookURL(u); err != nil {
			t.Errorf("%q should be accepted: %v", u, err)
		}
	}
}

// The settings form refuses an unsafe webhook URL.
func TestSettingsRejectUnsafeWebhookURL(t *testing.T) {
	s, _, cookie := newReadTestServer(t)
	rec := post(s, "/settings", url.Values{
		"report.webhook_url": {"http://169.254.169.254/latest/meta-data"},
	}, cookie, s.csrfToken(cookie.Value))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	v, err := s.deps.Store.GetSetting(context.Background(), "report.webhook_url")
	if err == nil && v != "" {
		t.Fatalf("unsafe webhook URL was stored: %q", v)
	}
}

// The login response does not disclose whether a username exists.
func TestLoginDoesNotDiscloseUnknownUser(t *testing.T) {
	s := newTestServer(t)
	rec := post(s, "/login", url.Values{"username": {"nobody"}, "password": {"x"}}, nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("failed login must not set a cookie")
	}
	// The same message as a wrong password for a known user.
	known := post(s, "/login", url.Values{"username": {"admin"}, "password": {"x"}}, nil, "")
	if known.Body.String() != rec.Body.String() {
		t.Fatalf("responses differ: %q vs %q", rec.Body.String(), known.Body.String())
	}
}

// A redirect target must stay on this site.
func TestSafeNextRefusesExternalRedirect(t *testing.T) {
	bad := []string{
		"//evil.example.com/",
		"/\\evil.example.com/",
		"https://evil.example.com/",
		"",
	}
	for _, s := range bad {
		if got := safeNext(s); got != "/certs" {
			t.Errorf("safeNext(%q) = %q, want /certs", s, got)
		}
	}
	if got := safeNext("/certs"); got != "/certs" {
		t.Errorf("safeNext(/certs) = %q", got)
	}
}

// Responses carry the headers that stop a browser from misusing the UI.
func TestSecurityHeaders(t *testing.T) {
	s := newTestServer(t)
	rec := post(s, "/login", url.Values{"username": {"admin"}, "password": {"s3cret"}}, nil, "")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", rec.Code)
	}
	h := rec.Header()
	for _, key := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Content-Security-Policy"} {
		if h.Get(key) == "" {
			t.Errorf("missing header %s", key)
		}
	}
}

// The health endpoint reports the database state.
func TestHealthzChecksDatabase(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "ok") {
		t.Fatalf("body = %q", rec.Body.String())
	}

	s.deps.Store.Close()
	req = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status with a closed database = %d, want 503", rec.Code)
	}
}
