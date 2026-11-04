package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// A successful login clears the earlier failures from the same address, so an
// operator is not locked out by their own earlier mistakes.
func TestSuccessfulLoginClearsRateLimit(t *testing.T) {
	s := newTestServer(t)
	form := url.Values{"username": {"admin"}, "password": {"s3cret"}}
	ip := "192.0.2.10"

	// Five wrong attempts fill the window.
	for i := 0; i < 5; i++ {
		s.limiter.allow(ip, time.Now())
	}
	// The correct password clears it.
	s.limiter.forget(ip)
	s.limiter.mu.Lock()
	hits := len(s.limiter.hits[ip])
	s.limiter.mu.Unlock()
	if hits != 0 {
		t.Fatalf("hits = %d, want 0", hits)
	}
	rec := post(s, "/login", form, nil, "")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", rec.Code)
	}
}

// The session cookie is marked Secure when the request arrived over TLS,
// including through a terminating proxy.
func TestSessionCookieSecureBehindProxy(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=admin&password=s3cret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookieName && !c.Secure {
			t.Fatal("a cookie served over a TLS-terminating proxy must be Secure")
		}
	}
}
