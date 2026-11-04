package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/amit/47certificates/internal/jobs"
	"github.com/amit/47certificates/internal/notify"
	"github.com/amit/47certificates/internal/scope"
	"github.com/amit/47certificates/internal/store"
)

// settingsSpec documents the keys the UI accepts. Unknown keys are ignored.
var settingsSpec = []struct {
	Key   string
	Label string
}{
	{"ports", "Ports (comma-separated)"},
	{"concurrency", "Concurrency (probes)"},
	{"qps", "QPS (probes/second)"},
	{"timeout", "Timeout (e.g. 10s)"},
	{"schedule", "Scan schedule (cron)"},
	{"retention", "Retention (scans kept)"},
	{"report.schedule", "Report schedule (cron)"},
	{"report.webhook_url", "Report webhook URL"},
}

func (s *Server) handleScopeGet(w http.ResponseWriter, r *http.Request) {
	s.renderScope(w, r, http.StatusOK, "")
}

func (s *Server) handleScopePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	u, _ := UserFrom(ctx)
	entries, err := parseScopeLines(r.PostFormValue("entries"))
	if err != nil {
		s.renderScope(w, r, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.deps.Store.ReplaceScope(ctx, entries, &u.ID); err != nil {
		s.renderScope(w, r, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.deps.Store.Audit(ctx, &u.ID, "scope.replace", "scope",
		[]byte(fmt.Sprintf(`{"entries":%d}`, len(entries))), clientIP(r))
	http.Redirect(w, r, "/scope?saved=1", http.StatusSeeOther)
}

func (s *Server) renderScope(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	entries, err := s.deps.Store.ListScope(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var lines []string
	for _, e := range entries {
		lines = append(lines, e.Kind+":"+e.Value)
	}
	data := struct {
		pageData
		ScopeLines string
		Saved      bool
		Error      string
	}{
		pageData:   s.base(r, "Scope"),
		ScopeLines: strings.Join(lines, "\n") + "\n",
		Saved:      r.URL.Query().Get("saved") == "1",
		Error:      errMsg,
	}
	s.renderStatus(w, "scope", status, data)
}

func parseScopeLines(text string) ([]scope.Entry, error) {
	var entries []scope.Entry
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kind, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("line %d: expected kind:value", i+1)
		}
		var k scope.Kind
		switch strings.ToLower(strings.TrimSpace(kind)) {
		case "include":
			k = scope.Include
		case "exclude":
			k = scope.Exclude
		case "seed":
			k = scope.Seed
		default:
			return nil, fmt.Errorf("line %d: unknown kind %q", i+1, kind)
		}
		entries = append(entries, scope.Entry{Kind: k, Value: strings.TrimSpace(value)})
	}
	set, err := scope.New(entries)
	if err != nil {
		return nil, err
	}
	var out []scope.Entry
	for _, v := range set.Includes() {
		out = append(out, scope.Entry{Kind: scope.Include, Value: v})
	}
	for _, v := range set.Excludes() {
		out = append(out, scope.Entry{Kind: scope.Exclude, Value: v})
	}
	for _, v := range set.Seeds() {
		out = append(out, scope.Entry{Kind: scope.Seed, Value: v})
	}
	return out, nil
}

func (s *Server) handleSettingsGet(w http.ResponseWriter, r *http.Request) {
	s.renderSettings(w, r, http.StatusOK, nil)
}

func (s *Server) handleSettingsPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	u, _ := UserFrom(ctx)
	values, errs := validateSettings(r.PostForm)
	if len(errs) > 0 {
		s.renderSettings(w, r, http.StatusBadRequest, errs)
		return
	}
	var saved []string
	for k, v := range values {
		if err := s.deps.Store.SetSetting(ctx, k, v); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		saved = append(saved, k)
	}
	detail := []byte(fmt.Sprintf(`{"keys":[%s]}`, quotedJoin(saved)))
	_ = s.deps.Store.Audit(ctx, &u.ID, "settings.update", "settings", detail, clientIP(r))
	http.Redirect(w, r, "/settings?saved=1", http.StatusSeeOther)
}

func validateSettings(form url.Values) (map[string]string, []string) {
	values := map[string]string{}
	var errs []string
	for _, spec := range settingsSpec {
		if !form.Has(spec.Key) {
			continue
		}
		v := strings.TrimSpace(form.Get(spec.Key))
		switch spec.Key {
		case "ports":
			parts := strings.Split(v, ",")
			ok := len(parts) > 0 && parts[0] != ""
			for _, p := range parts {
				p = strings.TrimSpace(p)
				n, err := strconv.Atoi(p)
				if err != nil || n < 1 || n > 65535 {
					ok = false
				}
			}
			if !ok {
				errs = append(errs, "ports: comma-separated ports 1-65535")
				continue
			}
			values[spec.Key] = v
		case "concurrency", "qps":
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 10000 {
				errs = append(errs, spec.Key+": integer 1-10000")
				continue
			}
			values[spec.Key] = strconv.Itoa(n)
		case "retention":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				errs = append(errs, "retention: non-negative number of scans to keep")
				continue
			}
			values[spec.Key] = strconv.Itoa(n)
		case "timeout":
			d, err := time.ParseDuration(v)
			if err != nil || d <= 0 {
				errs = append(errs, "timeout: duration, e.g. 10s")
				continue
			}
			values[spec.Key] = v
		case "schedule", "report.schedule":
			if v == "" {
				errs = append(errs, spec.Key+": must not be empty")
				continue
			}
			values[spec.Key] = v
		case "report.webhook_url":
			if v == "" {
				values[spec.Key] = ""
				continue
			}
			if err := notify.ValidateWebhookURL(v); err != nil {
				errs = append(errs, "report.webhook_url: "+err.Error())
				continue
			}
			values[spec.Key] = v
		default:
			values[spec.Key] = v
		}
	}
	return values, errs
}

func (s *Server) renderSettings(w http.ResponseWriter, r *http.Request, status int, errs []string) {
	values := map[string]string{}
	for _, spec := range settingsSpec {
		if v, err := s.deps.Store.GetSetting(r.Context(), spec.Key); err == nil {
			values[spec.Key] = v
		}
	}
	data := struct {
		pageData
		Fields []struct {
			Key   string
			Label string
			Value string
		}
		Saved bool
		Error []string
	}{
		pageData: s.base(r, "Settings"),
		Saved:    r.URL.Query().Get("saved") == "1",
		Error:    errs,
	}
	for _, spec := range settingsSpec {
		data.Fields = append(data.Fields, struct {
			Key   string
			Label string
			Value string
		}{spec.Key, spec.Label, values[spec.Key]})
	}
	s.renderStatus(w, "settings", status, data)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	entries, err := s.deps.Store.ListAudit(r.Context(), 50)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data := struct {
		pageData
		Entries []store.AuditEntry
	}{
		pageData: s.base(r, "Audit log"),
		Entries:  entries,
	}
	s.render(w, "audit", data)
}

func (s *Server) handleScanTrigger(w http.ResponseWriter, r *http.Request) {
	if s.deps.Jobs == nil {
		http.Error(w, "jobs not configured", http.StatusServiceUnavailable)
		return
	}
	ctx := r.Context()
	u, _ := UserFrom(ctx)
	id, err := s.deps.Jobs.TriggerScan(ctx, "manual", &u.ID)
	if err != nil {
		if errors.Is(err, jobs.ErrBusy) {
			http.Error(w, "a scan is already running", http.StatusConflict)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_ = s.deps.Store.Audit(ctx, &u.ID, "scan.trigger", strconv.FormatInt(id, 10), nil, clientIP(r))
	http.Redirect(w, r, "/scans/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
}

func (s *Server) handleScanCancel(w http.ResponseWriter, r *http.Request) {
	if s.deps.Jobs == nil {
		http.Error(w, "jobs not configured", http.StatusServiceUnavailable)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	u, _ := UserFrom(ctx)
	if err := s.deps.Jobs.Cancel(id); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	_ = s.deps.Store.Audit(ctx, &u.ID, "scan.cancel", strconv.FormatInt(id, 10), nil, clientIP(r))
	http.Redirect(w, r, "/scans/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
}

func quotedJoin(in []string) string {
	parts := make([]string, 0, len(in))
	for _, s := range in {
		parts = append(parts, strconv.Quote(s))
	}
	return strings.Join(parts, ",")
}
