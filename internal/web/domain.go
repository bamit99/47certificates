package web

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/bamit99/47certificates/internal/store"
)

// domainRequest is the domain a request is about.
//
// The domain comes from the path, the query, or the session's last choice.
// The path wins, so a link to one domain's page always shows that domain.
type domainRequest struct {
	ID   int64
	Name string
}

// domainOf resolves the domain a request is about.
//
// It returns the domain named in the query parameter "domain", or the one
// whose name matches a path segment, or the newest domain when neither is
// given. A request that names a domain that does not exist gets an empty
// result rather than an error: the caller shows an empty page.
func (s *Server) domainOf(r *http.Request) (domainRequest, error) {
	ctx := r.Context()

	// The path may name the domain: /domains/colt.net, /colt.net/certs, ...
	if name := domainFromPath(r.URL.Path); name != "" {
		d, err := s.deps.Store.DomainByName(ctx, name)
		if err != nil {
			return domainRequest{}, nil
		}
		return domainRequest{ID: d.ID, Name: d.Name}, nil
	}

	if name := strings.TrimSpace(r.URL.Query().Get("domain")); name != "" {
		d, err := s.deps.Store.DomainByName(ctx, name)
		if err != nil {
			return domainRequest{}, nil
		}
		return domainRequest{ID: d.ID, Name: d.Name}, nil
	}

	domains, err := s.deps.Store.ListDomains(ctx)
	if err != nil {
		return domainRequest{}, err
	}
	if len(domains) == 0 {
		return domainRequest{}, nil
	}
	return domainRequest{ID: domains[0].ID, Name: domains[0].Name}, nil
}

// domainFromPath returns the domain name a path names, if any.
func domainFromPath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i, p := range parts {
		if p == "domains" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// domainPath returns the path of a page within a domain.
func domainPath(domain string, suffix string) string {
	if domain == "" {
		return suffix
	}
	if suffix == "" || suffix == "/" {
		return "/domains/" + domain
	}
	return "/domains/" + domain + suffix
}

// domainQuery returns the query string that selects a domain.
func domainQuery(domain string) string {
	if domain == "" {
		return ""
	}
	return "?domain=" + domain
}

// setDomainCookie remembers the domain a request was about, so the next
// page without an explicit domain keeps it.
func (s *Server) setDomainCookie(w http.ResponseWriter, d domainRequest) {
	if d.Name == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     domainCookie,
		Value:    d.Name,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// domainCookie is the name of the cookie holding the last chosen domain.
const domainCookie = "47c_domain"

// lastDomain returns the domain the last request was about.
func (s *Server) lastDomain(r *http.Request) string {
	c, err := r.Cookie(domainCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

// domainsForPicker returns the domains shown in the picker, filtered by a
// search term.
func (s *Server) domainsForPicker(ctx context.Context, search string) ([]store.Domain, error) {
	all, err := s.deps.Store.ListDomains(ctx)
	if err != nil {
		return nil, err
	}
	search = strings.ToLower(strings.TrimSpace(search))
	if search == "" {
		return all, nil
	}
	var out []store.Domain
	for _, d := range all {
		if strings.Contains(strings.ToLower(d.Name), search) {
			out = append(out, d)
		}
	}
	return out, nil
}

// domainIDParam parses a domain id from a path value.
func domainIDParam(s string) (int64, bool) {
	id, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}
