// Package web serves the 47c UI and its authenticated API.
package web

import (
	"context"
	"embed"
	"html/template"
	"net/http"
	"time"

	"github.com/amit/47certificates/internal/scan"
	"github.com/amit/47certificates/internal/store"
)

//go:embed templates/*.html static/app.css
var assets embed.FS

var viewTemplates = map[string]*template.Template{}

func init() {
	for _, p := range []string{"dashboard", "certs", "cert", "domains", "domain", "scans", "scan", "scope", "settings", "audit", "reports", "report"} {
		t := template.Must(template.New("layout.html").
			Funcs(template.FuncMap(funcMap)).
			ParseFS(assets, "templates/layout.html", "templates/"+p+".html"))
		viewTemplates[p] = t
	}
}

// JobTrigger is the scan runner surface the UI needs. It is defined here so
// the web package does not depend on the jobs implementation.
type JobTrigger interface {
	TriggerScan(ctx context.Context, trigger string, userID *int64) (int64, error)
	Cancel(scanID int64) error
	Subscribe(scanID int64) (<-chan scan.Progress, func())
}

// Deps are the collaborators the server needs.
type Deps struct {
	Store *store.Store
	Jobs  JobTrigger
	Now   func() time.Time
	// DataDir overrides store-derived report storage when set.
	DataDir string
}

// Server implements http.Handler.
type Server struct {
	deps      Deps
	mux       *http.ServeMux
	secret    []byte
	limiter   *loginLimiter
	loginTmpl *template.Template
}

type ctxKey int

const (
	userKey ctxKey = iota
	sessionKey
	csrfKey
)

// New builds the web handler.
const loginPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Sign in - 47c</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
</head><body>
<h1>47c</h1>
{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}
<form method="post" action="/login">
<label>Username <input name="username" autocomplete="username" required></label>
<label>Password <input type="password" name="password" autocomplete="current-password" required></label>
<button type="submit">Sign in</button>
</form>
</body></html>`

func New(d Deps) http.Handler {
	if d.Now == nil {
		d.Now = time.Now
	}
	s := &Server{deps: d, limiter: newLoginLimiter()}
	s.secret = loadSecret(d.Store)
	s.loginTmpl = template.Must(template.New("login").Parse(loginPage))
	s.mux = http.NewServeMux()
	s.mux.Handle("GET /static/", staticHandler())
	s.mux.HandleFunc("GET /{$}", s.handleDashboard)
	s.mux.HandleFunc("GET /certs", s.handleCerts)
	s.mux.HandleFunc("GET /certs/{fp}", s.handleCertDetail)
	s.mux.HandleFunc("GET /certs/{fp}/pem", s.handleCertPEM)
	s.mux.HandleFunc("GET /domains", s.handleDomains)
	s.mux.HandleFunc("GET /domains/{d}", s.handleDomainDetail)
	s.mux.HandleFunc("GET /scans", s.handleScans)
	s.mux.HandleFunc("GET /scans/{id}", s.handleScanDetail)
	s.mux.HandleFunc("GET /scans/{id}/events", s.handleScanEvents)
	s.mux.HandleFunc("GET /api/certs", s.handleAPICerts)
	s.mux.HandleFunc("GET /api/scans", s.handleAPIScans)
	s.mux.HandleFunc("GET /scope", s.handleScopeGet)
	s.mux.HandleFunc("POST /scope", s.handleScopePost)
	s.mux.HandleFunc("GET /settings", s.handleSettingsGet)
	s.mux.HandleFunc("POST /settings", s.handleSettingsPost)
	s.mux.HandleFunc("GET /audit", s.handleAudit)
	s.mux.HandleFunc("POST /scans", s.handleScanTrigger)
	s.mux.HandleFunc("POST /scans/{id}/cancel", s.handleScanCancel)
	s.mux.HandleFunc("GET /reports", s.handleReports)
	s.mux.HandleFunc("POST /reports", s.handleReportCreate)
	s.mux.HandleFunc("GET /reports/{id}", s.handleReportDetail)
	s.mux.HandleFunc("POST /reports/{id}/delete", s.handleReportDelete)
	s.mux.HandleFunc("GET /reports/{id}/download", s.handleReportDownload)
	s.mux.HandleFunc("POST /findings/{id}/ack", s.handleFindingAck)
	s.mux.HandleFunc("POST /findings/{id}/snooze", s.handleFindingSnooze)
	s.mux.HandleFunc("POST /findings/{id}/reopen", s.handleFindingReopen)
	s.mux.HandleFunc("POST /logout", s.handleLogout)
	return s
}

func (s *Server) now() time.Time { return s.deps.Now() }

// ServeHTTP applies authentication and CSRF checks, then dispatches.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if r.URL.Path == "/login" {
		s.handleLogin(w, r)
		return
	}
	if r.URL.Path == "/healthz" {
		s.handleHealth(w, r)
		return
	}

	cookie, err := r.Cookie(cookieName)
	if err != nil {
		s.redirectLogin(w, r)
		return
	}
	user, err := s.deps.Store.SessionUser(r.Context(), cookie.Value, s.now())
	if err != nil {
		s.redirectLogin(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
		if !s.csrfValid(r, cookie.Value) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
	}

	ctx := context.WithValue(r.Context(), userKey, user)
	ctx = context.WithValue(ctx, sessionKey, cookie.Value)
	ctx = context.WithValue(ctx, csrfKey, s.csrfToken(cookie.Value))
	s.mux.ServeHTTP(w, r.WithContext(ctx))
}

func (s *Server) redirectLogin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// handleHealth reports liveness: the database must answer.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if s.deps.Store == nil {
		http.Error(w, "no store", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.deps.Store.DB().PingContext(ctx); err != nil {
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// securityHeaders sets the response headers that keep a browser from
// sniffing, framing or leaking the UI's URLs.
func securityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
}

// UserFrom returns the authenticated user from a request context.
func UserFrom(ctx context.Context) (store.User, bool) {
	u, ok := ctx.Value(userKey).(store.User)
	return u, ok
}

func CSRFFrom(ctx context.Context) string {
	t, _ := ctx.Value(csrfKey).(string)
	return t
}
