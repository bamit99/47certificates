package discover

import (
	"context"
	"net"
	"testing"

	"github.com/bamit99/47certificates/internal/scope"
)

// A cached resolution is replayed instead of asking the resolver again. The
// resolver is never called, so a repeated scan puts no load on it.
func TestCachedDNSAnswerIsReplayed(t *testing.T) {
	set, _ := scope.New([]scope.Entry{{Kind: scope.Include, Value: "example.com"}})
	src := fakeSource{names: []string{"a.example.com"}}
	res := &countingResolver{ips: map[string][]string{"a.example.com": {"192.0.2.1"}}}
	lookups := 0
	opts := Options{
		DNSLookup: func(host string) ([]string, string, bool, bool) {
			return []string{"192.0.2.9"}, "cdn.example.com", false, true
		},
		DNSStore: func(string, []string, string, bool) { lookups++ },
	}
	got, err := Run(context.Background(), set, src, res, opts)
	if err != nil {
		t.Fatal(err)
	}
	if res.calls != 0 {
		t.Fatalf("resolver was called %d times; the cache should answer", res.calls)
	}
	if lookups != 0 {
		t.Fatalf("the cache was written %d times; a cache hit must not write", lookups)
	}
	if len(got.IPs["a.example.com"]) != 1 || got.IPs["a.example.com"][0] != "192.0.2.9" {
		t.Fatalf("ips = %v", got.IPs["a.example.com"])
	}
	if got.CNAMEs["a.example.com"] != "cdn.example.com" {
		t.Fatalf("cname = %q", got.CNAMEs["a.example.com"])
	}
}

// A name that does not exist is cached as such, so the next scan does not
// ask again.
func TestNXDomainIsCached(t *testing.T) {
	set, _ := scope.New([]scope.Entry{{Kind: scope.Include, Value: "example.com"}})
	res := &countingResolver{ips: map[string][]string{}}
	var stored []string
	opts := Options{
		DNSStore: func(host string, ips []string, cname string, nxdomain bool) {
			if nxdomain {
				stored = append(stored, host)
			}
		},
	}
	if _, err := Run(context.Background(), set, nil, res, opts); err != nil {
		t.Fatal(err)
	}
	if res.calls == 0 {
		t.Fatal("the resolver was not called")
	}
	if len(stored) == 0 {
		t.Fatal("a name that does not exist must be cached")
	}
}

// The cap drops the extra names and says so, rather than silently scanning
// a smaller estate than the operator asked for.
func TestMaxHostsCapsTheScope(t *testing.T) {
	set, _ := scope.New([]scope.Entry{{Kind: scope.Include, Value: "example.com"}})
	src := fakeSource{names: []string{
		"a.example.com", "b.example.com", "c.example.com", "d.example.com",
	}}
	res := &countingResolver{ips: map[string][]string{}}
	got, err := Run(context.Background(), set, src, res, Options{MaxHosts: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Hosts) != 2 {
		t.Fatalf("hosts = %v, want 2", got.Hosts)
	}
	// The scope include itself plus the four names the source returned.
	found := false
	for _, w := range got.Warnings {
		if w == "host cap: 3 names dropped for this scope (limit 2)" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the cap must be reported: %v", got.Warnings)
	}
}

// countingResolver counts the lookups it receives.
type countingResolver struct {
	ips   map[string][]string
	calls int
}

func (r *countingResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	r.calls++
	if ips, ok := r.ips[host]; ok {
		return ips, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (r *countingResolver) LookupCNAME(context.Context, string) (string, error) {
	r.calls++
	return "", nil
}
