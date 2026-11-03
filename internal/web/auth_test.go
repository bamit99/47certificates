package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/amit/47certificates/internal/auth"
	"github.com/amit/47certificates/internal/store"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(); err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser(context.Background(), "admin", hash); err != nil {
		t.Fatal(err)
	}
	s := New(Deps{Store: st, Now: time.Now}).(*Server)
	return s
}

func post(h http.Handler, path string, form url.Values, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func login(t *testing.T, s *Server) *http.Cookie {
	t.Helper()
	rec := post(s, "/login", url.Values{"username": {"admin"}, "password": {"s3cret"}}, nil, "")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login status = %d: %s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookieName {
			return c
		}
	}
	t.Fatal("no session cookie")
	return nil
}

func TestMutatingRouteRequiresSessionAndCSRF(t *testing.T) {
	s := newTestServer(t)
	rec := post(s, "/scope", url.Values{"value": {"x"}}, nil, "")
	if rec.Code != http.StatusSeeOther && rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/login") {
		t.Fatalf("Location = %q", loc)
	}
}

func TestLoginSetsCookieAndAuthenticates(t *testing.T) {
	s := newTestServer(t)
	cookie := login(t, s)
	if !cookie.HttpOnly {
		t.Fatal("session cookie must be HttpOnly")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("SameSite = %v", cookie.SameSite)
	}
	if cookie.Secure {
		t.Fatal("plain HTTP must not set Secure")
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "admin") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestCSRFRequiredForMutations(t *testing.T) {
	s := newTestServer(t)
	cookie := login(t, s)

	rec := post(s, "/scope", url.Values{"value": {"x"}}, cookie, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing token status = %d", rec.Code)
	}
	rec = post(s, "/scope", url.Values{"value": {"x"}}, cookie, "wrong")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("wrong token status = %d", rec.Code)
	}
	rec = post(s, "/scope", url.Values{"value": {"x"}}, cookie, s.csrfToken(cookie.Value))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("valid token status = %d", rec.Code)
	}
}

func TestLogoutClearsSession(t *testing.T) {
	s := newTestServer(t)
	cookie := login(t, s)
	rec := post(s, "/logout", url.Values{}, cookie, s.csrfToken(cookie.Value))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("logout status = %d", rec.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("session should be gone, status = %d", rr.Code)
	}
}

func TestLoginRejectsBadPassword(t *testing.T) {
	s := newTestServer(t)
	rec := post(s, "/login", url.Values{"username": {"admin"}, "password": {"nope"}}, nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("failed login must not set a cookie")
	}
}

func TestLoginRateLimit(t *testing.T) {
	s := newTestServer(t)
	var last *httptest.ResponseRecorder
	for i := 0; i < 6; i++ {
		last = post(s, "/login", url.Values{"username": {"admin"}, "password": {"nope"}}, nil, "")
	}
	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("6th attempt status = %d", last.Code)
	}
}

func TestLoginUnavailableWhenStoreDown(t *testing.T) {
	s := newTestServer(t)
	s.deps.Store.Close()
	rec := post(s, "/login", url.Values{"username": {"admin"}, "password": {"s3cret"}}, nil, "")
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
}
