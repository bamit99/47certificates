package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bamit99/47certificates/internal/store"
)

// safeNext returns a path the server is willing to redirect to. Only local
// absolute paths are allowed, and a backslash is refused because browsers
// normalise "/\host" into "//host", which would leave the site.
func safeNext(s string) string {
	if s == "" || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") {
		return "/certs"
	}
	if strings.ContainsAny(s, "\\") {
		return "/certs"
	}
	if !strings.HasPrefix(s, "/certs") && !strings.HasPrefix(s, "/scans") && !strings.HasPrefix(s, "/") {
		return "/certs"
	}
	return s
}

func (s *Server) handleFindingAck(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_ = r.ParseForm()
	ctx := r.Context()
	u, _ := UserFrom(ctx)
	if err := s.deps.Store.AckFinding(ctx, id, u.ID, strings.TrimSpace(r.PostFormValue("note"))); err != nil {
		s.findingError(w, r, err)
		return
	}
	_ = s.deps.Store.Audit(ctx, &u.ID, "finding.ack", strconv.FormatInt(id, 10),
		[]byte(fmt.Sprintf(`{"note":%q}`, r.PostFormValue("note"))), clientIP(r))
	http.Redirect(w, r, safeNext(r.PostFormValue("next")), http.StatusSeeOther)
}

func (s *Server) handleFindingSnooze(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_ = r.ParseForm()
	ctx := r.Context()
	u, _ := UserFrom(ctx)
	days, err := strconv.Atoi(r.PostFormValue("snooze_days"))
	if err != nil || days < 1 || days > 365 {
		http.Error(w, "snooze_days must be between 1 and 365", http.StatusBadRequest)
		return
	}
	until := s.now().Add(time.Duration(days) * 24 * time.Hour)
	if err := s.deps.Store.SnoozeFinding(ctx, id, u.ID, until, s.now(), strings.TrimSpace(r.PostFormValue("note"))); err != nil {
		s.findingError(w, r, err)
		return
	}
	_ = s.deps.Store.Audit(ctx, &u.ID, "finding.snooze", strconv.FormatInt(id, 10),
		[]byte(fmt.Sprintf(`{"snooze_days":%d}`, days)), clientIP(r))
	http.Redirect(w, r, safeNext(r.PostFormValue("next")), http.StatusSeeOther)
}

func (s *Server) handleFindingReopen(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_ = r.ParseForm()
	ctx := r.Context()
	u, _ := UserFrom(ctx)
	if err := s.deps.Store.ReopenFinding(ctx, id); err != nil {
		s.findingError(w, r, err)
		return
	}
	_ = s.deps.Store.Audit(ctx, &u.ID, "finding.reopen", strconv.FormatInt(id, 10), nil, clientIP(r))
	http.Redirect(w, r, safeNext(r.PostFormValue("next")), http.StatusSeeOther)
}

func (s *Server) findingError(w http.ResponseWriter, r *http.Request, err error) {
	if err == store.ErrNotFound {
		http.NotFound(w, r)
		return
	}
	http.Error(w, err.Error(), http.StatusBadRequest)
}
