package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/amit/47certificates/internal/auth"
	"github.com/amit/47certificates/internal/store"
)

const (
	cookieName   = "47c_session"
	sessionTTL   = 30 * 24 * time.Hour
	loginPerMin  = 5
	secretKey    = "csrf_secret"
	secretLength = 32
)

// loadSecret reads the CSRF key, creating it on first use. CSRF tokens are
// HMACs of the session id, so the key must survive restarts.
func loadSecret(st *store.Store) []byte {
	if st != nil {
		if v, err := st.GetSetting(context.Background(), secretKey); err == nil {
			if b, err := base64.RawStdEncoding.DecodeString(v); err == nil && len(b) == secretLength {
				return b
			}
		}
	}
	b := make([]byte, secretLength)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("web: csrf secret: %v", err))
	}
	if st != nil {
		_ = st.SetSetting(context.Background(), secretKey, base64.RawStdEncoding.EncodeToString(b))
	}
	return b
}

func (s *Server) csrfToken(sessionID string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(sessionID))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) csrfValid(r *http.Request, sessionID string) bool {
	token := r.Header.Get("X-CSRF-Token")
	if token == "" {
		_ = r.ParseForm()
		token = r.PostFormValue("csrf")
	}
	if token == "" {
		return false
	}
	return hmac.Equal([]byte(token), []byte(s.csrfToken(sessionID)))
}

// dummyHash is a valid argon2id hash of an unguessable value. It is used to
// spend the same CPU time on an unknown username as on a known one, so the
// response time does not reveal which usernames exist.
var dummyHash = func() string {
	h, err := auth.HashPassword("47c-dummy-password-for-constant-time-login")
	if err != nil {
		panic("web: dummy hash: " + err.Error())
	}
	return h
}()

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.renderLogin(w, http.StatusOK, "")
	case http.MethodPost:
		if !s.limiter.allow(clientIP(r), s.now()) {
			http.Error(w, "too many attempts", http.StatusTooManyRequests)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		username := r.PostFormValue("username")
		password := r.PostFormValue("password")
		user, err := s.deps.Store.UserByUsername(r.Context(), username)
		if errors.Is(err, store.ErrNotFound) {
			// Spend the password-hashing time anyway so an unknown
			// username is not distinguishable by response time.
			auth.CheckPassword(dummyHash, password)
			s.renderLogin(w, http.StatusUnauthorized, "Invalid username or password.")
			return
		}
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if user.Disabled {
			auth.CheckPassword(dummyHash, password)
			s.renderLogin(w, http.StatusUnauthorized, "Invalid username or password.")
			return
		}
		if !auth.CheckPassword(user.PasswordHash, password) {
			s.renderLogin(w, http.StatusUnauthorized, "Invalid username or password.")
			return
		}
		if err := s.startSession(w, r, user); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// A correct password clears the earlier failures from this address.
		s.limiter.forget(clientIP(r))
		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// secureRequest reports whether the request reached the server over TLS,
// either directly or through a terminating proxy that set
// X-Forwarded-Proto.
func secureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, user store.User) error {
	idBytes := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		return err
	}
	id := hex.EncodeToString(idBytes)
	expires := s.now().Add(sessionTTL)
	if err := s.deps.Store.CreateSession(r.Context(), id, user.ID, expires, clientIP(r), r.UserAgent()); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secureRequest(r),
		Expires:  expires,
	})
	return nil
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		_ = s.deps.Store.DeleteSession(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secureRequest(r),
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) renderLogin(w http.ResponseWriter, status int, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = s.loginTmpl.Execute(w, map[string]string{"Error": errMsg})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// loginLimiter is a per-IP sliding window of login attempts.
type loginLimiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{hits: map[string][]time.Time{}}
}

// allow reports whether another attempt from ip is permitted. It records the
// attempt whether or not the credentials turn out to be right: the limiter
// exists to slow guessing, and counting successes too keeps a valid
// credential from being a free way to probe the limit.
func (l *loginLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-time.Minute)
	old := l.hits[ip]
	kept := old[:0]
	for _, t := range old {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= loginPerMin {
		l.hits[ip] = kept
		return false
	}
	l.hits[ip] = append(kept, now)
	return true
}

// forget drops the recorded attempts of an ip. It is called after a
// successful login so a legitimate operator is not locked out by their own
// earlier mistakes.
func (l *loginLimiter) forget(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.hits, ip)
}
