// Package discover finds hostnames for the allowlist and resolves them.
//
// Certificate transparency logs are the discovery source; DNS turns names into
// the addresses the collector dials. Scope is applied here so that nothing
// outside the allowlist can reach the collector.
package discover

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/amit/47certificates/internal/scope"
)

// Source yields candidate hostnames for a domain. Names may be wildcards and
// may be outside the allowlist; Run filters them.
type Source interface {
	Names(ctx context.Context, domain string) ([]string, error)
}

// Resolver is the DNS surface discovery needs.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// Options controls discovery.
type Options struct {
	// Fallback is tried when the primary source fails. It may be nil.
	Fallback Source
	// Timeout bounds each source request. Zero means 15s.
	Timeout time.Duration
	// LookupTimeout bounds each DNS lookup pair. Zero means 2s.
	LookupTimeout time.Duration
	// CachedNames returns the previously discovered names for a domain when
	// the cache is still fresh. The names are replayed instead of querying
	// the source again: a cached domain must still contribute its hosts, or
	// a rescan would look like the certificates were retired.
	CachedNames func(domain string) ([]string, bool)
	// RememberSuccess records the names a source returned for a domain.
	RememberSuccess func(domain string, names []string)
}

// Result is the discovery output for one run.
type Result struct {
	Hosts    []string
	IPs      map[string][]string
	CNAMEs   map[string]string
	Warnings []string
}

// Run expands the scope into in-scope hostnames and resolves them.
func Run(ctx context.Context, set *scope.Set, src Source, res Resolver, opts Options) (Result, error) {
	out := Result{
		IPs:    map[string][]string{},
		CNAMEs: map[string]string{},
	}

	names := append([]string{}, set.Hosts()...)
	if src != nil {
		found, err := namesFor(ctx, src, set.Hosts(), opts, func(w string) {
			out.Warnings = append(out.Warnings, w)
		})
		if err != nil {
			out.Warnings = append(out.Warnings, "ct: "+err.Error())
			if opts.Fallback != nil {
				more, ferr := namesFor(ctx, opts.Fallback, set.Hosts(), opts, func(w string) {
					out.Warnings = append(out.Warnings, w)
				})
				if ferr != nil {
					out.Warnings = append(out.Warnings, "ct-fallback: "+ferr.Error())
				} else {
					found = more
				}
			}
		}
		names = append(names, found...)
	}

	seen := map[string]bool{}
	hosts := make([]string, 0, len(names))
	for _, raw := range names {
		name := strings.TrimSpace(raw)
		if strings.Contains(name, "*") {
			out.Warnings = append(out.Warnings, "wildcard coverage only: "+name)
			continue
		}
		norm, err := scope.NormalizeHost(name)
		if err != nil {
			continue
		}
		if !set.Match(norm) {
			continue
		}
		if seen[norm] {
			continue
		}
		seen[norm] = true
		hosts = append(hosts, norm)
	}
	sort.Strings(hosts)
	out.Hosts = hosts

	if res == nil {
		return out, nil
	}
	lookupTimeout := opts.LookupTimeout
	if lookupTimeout <= 0 {
		lookupTimeout = 2 * time.Second
	}
	for _, host := range hosts {
		lctx, cancel := context.WithTimeout(ctx, lookupTimeout)
		ips, err := res.LookupHost(lctx, host)
		cancel()
		if err != nil {
			out.Warnings = append(out.Warnings, fmt.Sprintf("dns %s: %v", host, err))
			continue
		}
		out.IPs[host] = dedupeSorted(ips)

		lctx, cancel = context.WithTimeout(ctx, lookupTimeout)
		cname, err := res.LookupCNAME(lctx, host)
		cancel()
		if err == nil && cname != "" {
			if norm, nerr := scope.NormalizeHost(cname); nerr == nil {
				out.CNAMEs[host] = norm
			}
		}
	}
	return out, nil
}

// namesFor queries one source once per starting host, using the 6-hour cache
// when configured, and dedupes the answers.
func namesFor(ctx context.Context, src Source, domains []string, opts Options, warnf func(string)) ([]string, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	var (
		out  []string
		errs []string
	)
	for _, d := range domains {
		if opts.CachedNames != nil {
			if cached, ok := opts.CachedNames(d); ok {
				if warnf != nil {
					warnf(fmt.Sprintf("ct: cache fresh for %s; %d names replayed", d, len(cached)))
				}
				out = append(out, cached...)
				continue
			}
		}
		ictx, cancel := context.WithTimeout(ctx, timeout)
		names, err := src.Names(ictx, d)
		cancel()
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", d, err))
			continue
		}
		if opts.RememberSuccess != nil {
			opts.RememberSuccess(d, names)
		}
		out = append(out, names...)
	}
	if len(errs) > 0 {
		return out, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return out, nil
}

func dedupeSorted(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	if len(out) < 2 {
		return out
	}
	kept := out[:1]
	for _, v := range out[1:] {
		if v != kept[len(kept)-1] {
			kept = append(kept, v)
		}
	}
	return kept
}
