package scope

import (
	"reflect"
	"testing"
)

func TestMatchLabelBoundaries(t *testing.T) {
	s, err := New([]Entry{{Kind: Include, Value: "example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if !s.Match("a.example.com") {
		t.Fatal("subdomain should match")
	}
	if !s.Match("example.com") {
		t.Fatal("apex should match")
	}
	if s.Match("notexample.com") {
		t.Fatal("partial label must not match")
	}
	if s.Match("example.com.evil.net") {
		t.Fatal("suffix trick must not match")
	}
	if s.Match("badexample.com") {
		t.Fatal("prefix trick must not match")
	}
}

func TestExcludeBeatsInclude(t *testing.T) {
	s, err := New([]Entry{
		{Kind: Include, Value: "example.com"},
		{Kind: Exclude, Value: "admin.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.Match("admin.example.com") {
		t.Fatal("exclusion must win")
	}
	if !s.Match("www.example.com") {
		t.Fatal("other hosts stay in scope")
	}
}

func TestSeedMustBeInScope(t *testing.T) {
	if _, err := New([]Entry{
		{Kind: Include, Value: "example.com"},
		{Kind: Seed, Value: "other.net"},
	}); err == nil {
		t.Fatal("out-of-scope seed must be rejected")
	}
	if _, err := New([]Entry{
		{Kind: Include, Value: "example.com"},
		{Kind: Seed, Value: "seed.example.com"},
	}); err != nil {
		t.Fatalf("in-scope seed: %v", err)
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"A.Example.COM.": "a.example.com",
		"example.com":    "example.com",
	}
	for in, want := range cases {
		got, err := NormalizeHost(in)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "*", "*.example.com", "münchen.de", "a..b", "example.com.."} {
		if _, err := NormalizeHost(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestWildcardNeverMatches(t *testing.T) {
	s, _ := New([]Entry{{Kind: Include, Value: "example.com"}})
	if s.Match("*.example.com") {
		t.Fatal("wildcards are coverage metadata, never endpoints")
	}
}

func TestHostsSortedDeduped(t *testing.T) {
	s, err := New([]Entry{
		{Kind: Include, Value: "b.example.com"},
		{Kind: Include, Value: "a.example.com"},
		{Kind: Seed, Value: "B.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := s.Hosts(), []string{"a.example.com", "b.example.com"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}
