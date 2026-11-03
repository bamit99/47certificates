package discover

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/amit/47certificates/internal/scope"
)

type fakeSource struct {
	names []string
	err   error
}

func (f fakeSource) Names(context.Context, string) ([]string, error) { return f.names, f.err }

type fakeResolver struct {
	ips    map[string][]string
	cnames map[string]string
	err    error
}

func (f fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.ips[host], nil
}

func (f fakeResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.cnames[host], nil
}

func TestRunFiltersAndExpands(t *testing.T) {
	src := fakeSource{names: []string{"a.example.com", "b.other.net", "A.EXAMPLE.COM."}}
	set, err := scope.New([]scope.Entry{{Kind: scope.Include, Value: "example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	res := fakeResolver{
		ips:    map[string][]string{"a.example.com": {"192.0.2.1"}, "example.com": {"192.0.2.2"}},
		cnames: map[string]string{"a.example.com": "lb.example.net"},
	}
	got, err := Run(context.Background(), set, src, res, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.example.com", "example.com"}
	if !reflect.DeepEqual(got.Hosts, want) {
		t.Fatalf("hosts = %v, want %v", got.Hosts, want)
	}
	if got.IPs["a.example.com"][0] != "192.0.2.1" {
		t.Fatalf("ips = %v", got.IPs)
	}
	if got.CNAMEs["a.example.com"] != "lb.example.net" {
		t.Fatalf("cnames = %v", got.CNAMEs)
	}
}

func TestRunRecordsWildcardAsWarning(t *testing.T) {
	set, _ := scope.New([]scope.Entry{{Kind: scope.Include, Value: "example.com"}})
	got, err := Run(context.Background(), set, fakeSource{names: []string{"*.example.com"}}, fakeResolver{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range got.Hosts {
		if h == "*.example.com" {
			t.Fatal("wildcard must never become an endpoint")
		}
	}
	if len(got.Warnings) == 0 {
		t.Fatal("wildcard should be recorded as a warning")
	}
}

func TestRunFallsBackWhenCTFails(t *testing.T) {
	set, _ := scope.New([]scope.Entry{{Kind: scope.Include, Value: "example.com"}})
	got, err := Run(context.Background(), set,
		fakeSource{err: errors.New("ct down")},
		fakeResolver{},
		Options{Fallback: fakeSource{names: []string{"seed.example.com"}}})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range got.Hosts {
		if h == "seed.example.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("fallback names missing: %v", got.Hosts)
	}
	if len(got.Warnings) == 0 {
		t.Fatal("primary failure should be recorded")
	}
}

func TestCRTSourceParsesNames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") != "%.example.com" {
			t.Errorf("q = %q", r.URL.Query().Get("q"))
		}
		io.WriteString(w, `[{"name_value":"a.example.com\nb.example.com"},{"name_value":"*.example.com"}]`)
	}))
	defer srv.Close()
	names, err := NewCRTSource(srv.Client(), srv.URL).Names(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.example.com", "b.example.com", "*.example.com"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("names = %v", names)
	}
}

func TestCertSpotterSourceParsesNames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `[{"dns_names":["c.example.com","d.example.com"]}]`)
	}))
	defer srv.Close()
	names, err := NewCertSpotterSource(srv.Client(), srv.URL).Names(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("names = %v", names)
	}
}
