// Package scope owns the allowlist that governs what may be discovered and
// dialled. It is the authorization boundary of the scanner.
package scope

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// Kind classifies a scope entry.
type Kind int

const (
	// Include grants permission for a domain and all of its subdomains.
	Include Kind = iota
	// Exclude removes a host or subtree from the allowlist; it always wins.
	Exclude
	// Seed adds a discovery hint. It must already be inside an include.
	Seed
)

// Entry is one line of the allowlist.
type Entry struct {
	Kind  Kind
	Value string
}

// Set is a validated allowlist.
type Set struct {
	includes []string
	excludes []string
	seeds    []string
}

// New normalizes and validates entries. A seed outside every include is an
// error: seeds widen discovery, never permission.
func New(entries []Entry) (*Set, error) {
	s := &Set{}
	for _, e := range entries {
		v, err := NormalizeHost(e.Value)
		if err != nil {
			return nil, fmt.Errorf("scope: %q: %w", e.Value, err)
		}
		switch e.Kind {
		case Include:
			s.includes = append(s.includes, v)
		case Exclude:
			s.excludes = append(s.excludes, v)
		case Seed:
			s.seeds = append(s.seeds, v)
		default:
			return nil, fmt.Errorf("scope: unknown entry kind %d", e.Kind)
		}
	}
	sort.Strings(s.includes)
	s.includes = dedupe(s.includes)
	sort.Strings(s.excludes)
	s.excludes = dedupe(s.excludes)
	sort.Strings(s.seeds)
	s.seeds = dedupe(s.seeds)

	if len(s.includes) == 0 {
		return nil, fmt.Errorf("scope: at least one include is required")
	}
	for _, seed := range s.seeds {
		if !s.Match(seed) {
			return nil, fmt.Errorf("scope: seed %q is not inside any include", seed)
		}
	}
	return s, nil
}

// Match reports whether host is inside the allowlist and not excluded.
// Wildcards and non-ASCII names never match.
func (s *Set) Match(host string) bool {
	h, err := NormalizeHost(host)
	if err != nil {
		return false
	}
	for _, ex := range s.excludes {
		if within(h, ex) {
			return false
		}
	}
	for _, in := range s.includes {
		if within(h, in) {
			return true
		}
	}
	return false
}

// Hosts returns the include apexes plus seeds, deduplicated and sorted. These
// are the names discovery starts from.
func (s *Set) Hosts() []string {
	out := append([]string{}, s.includes...)
	out = append(out, s.seeds...)
	sort.Strings(out)
	return dedupe(out)
}

// Includes returns the normalized include apexes.
func (s *Set) Includes() []string { return append([]string{}, s.includes...) }

// Excludes returns the normalized exclusions.
func (s *Set) Excludes() []string { return append([]string{}, s.excludes...) }

// Seeds returns the normalized discovery hints.
func (s *Set) Seeds() []string { return append([]string{}, s.seeds...) }

// NormalizeHost lowercases and strips one trailing dot. It rejects wildcards,
// empty labels, and any non-ASCII input; v1 has no IDNA mapping.
func NormalizeHost(host string) (string, error) {
	h := strings.TrimSpace(host)
	h = strings.TrimSuffix(h, ".")
	h = strings.ToLower(h)
	if h == "" {
		return "", fmt.Errorf("empty hostname")
	}
	if strings.Contains(h, "*") {
		return "", fmt.Errorf("wildcards are not dialable")
	}
	for _, r := range h {
		if r > unicode.MaxASCII {
			return "", fmt.Errorf("non-ASCII hostname %q is not supported", host)
		}
	}
	if len(h) > 253 {
		return "", fmt.Errorf("hostname too long")
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" {
			return "", fmt.Errorf("empty label in %q", host)
		}
	}
	return h, nil
}

// within reports whether h equals suffix or is a subdomain of it, on label
// boundaries.
func within(h, suffix string) bool {
	return h == suffix || strings.HasSuffix(h, "."+suffix)
}

func dedupe(sorted []string) []string {
	if len(sorted) < 2 {
		return sorted
	}
	out := sorted[:1]
	for _, v := range sorted[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}
