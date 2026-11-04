package collect

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bamit99/47certificates/internal/roots"
	"github.com/bamit99/47certificates/internal/testutil"
	"github.com/bamit99/47certificates/internal/x509eval"
)

// tlsServer serves TLS on loopback and selects a certificate by SNI.
func tlsServer(t *testing.T, fallback tls.Certificate, byName map[string]tls.Certificate) int {
	t.Helper()
	cfg := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if c, ok := byName[hello.ServerName]; ok {
				return &c, nil
			}
			return &fallback, nil
		},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestProbeUsesSNI(t *testing.T) {
	ca, caKey := testutil.NewCA(t)
	nameCert := func(name string) tls.Certificate {
		der, key := testutil.NewLeaf(t, ca, caKey, testutil.LeafOpts{DNSNames: []string{name}})
		return tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key}
	}
	port := tlsServer(t, nameCert("default.example.com"), map[string]tls.Certificate{
		"a.example.com": nameCert("a.example.com"),
	})

	obs := Probe(context.Background(), Endpoint{Host: "a.example.com", Port: port, IP: "127.0.0.1"}, Options{Timeout: 2 * time.Second})
	if obs.Err != nil {
		t.Fatal(obs.Err)
	}
	c, err := x509eval.Parse(obs.LeafDER, obs.ChainDER)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.SANs) != 1 || c.SANs[0] != "a.example.com" {
		t.Fatalf("got cert for %v", c.SANs)
	}
	if len(obs.ChainDER) != 1 {
		t.Fatalf("chain = %d certs", len(obs.ChainDER))
	}
}

func TestProbeIncompleteChainStaysUntrusted(t *testing.T) {
	ca, caKey := testutil.NewCA(t)
	der, key := testutil.NewLeaf(t, ca, caKey, testutil.LeafOpts{
		DNSNames:        []string{"a.example.com"},
		IssuingCertURLs: []string{"file:///tmp/ca.pem"},
	})
	// Serve only the leaf: no intermediate, no root.
	port := tlsServer(t, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil)

	obs := Probe(context.Background(), Endpoint{Host: "a.example.com", Port: port, IP: "127.0.0.1"}, Options{
		Timeout: 2 * time.Second,
		AIA:     NewAIAFetcher(http.DefaultClient, 1<<20),
	})
	if obs.Err != nil {
		t.Fatal(obs.Err)
	}
	if len(obs.ChainDER) != 0 {
		t.Fatalf("file:// AIA must not be fetched, chain = %d", len(obs.ChainDER))
	}
	v := x509eval.Verify(obs.LeafDER, obs.ChainDER, "a.example.com", roots.Pool(), time.Now())
	if v.Trust != "untrusted" || v.Reason != "incomplete" {
		t.Fatalf("%+v", v)
	}
}

func TestProbeRetriesOnceAfterHandshakeFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port

	ca, caKey := testutil.NewCA(t)
	der, key := testutil.NewLeaf(t, ca, caKey, testutil.LeafOpts{DNSNames: []string{"a.example.com"}})
	serverCfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key}}}

	// First connection is dropped mid-handshake, second one completes.
	go func() {
		for i := 0; i < 2; i++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn, drop bool) {
				defer c.Close()
				if drop {
					return
				}
				tc := tls.Server(c, serverCfg)
				_ = tc.Handshake()
			}(conn, i == 0)
		}
	}()

	obs := Probe(context.Background(), Endpoint{Host: "a.example.com", Port: port, IP: "127.0.0.1"}, Options{Timeout: 2 * time.Second})
	if obs.Err != nil {
		t.Fatalf("second attempt should succeed: %v", obs.Err)
	}
	if len(obs.LeafDER) == 0 {
		t.Fatal("no leaf")
	}
}

// stubTransport answers every request with one canned response, so the AIA
// policy can be tested without network access.
type stubTransport struct {
	status int
	body   []byte
	header http.Header
	calls  int
}

func (s *stubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s.calls++
	h := s.header
	if h == nil {
		h = http.Header{}
	}
	return &http.Response{
		StatusCode: s.status,
		Header:     h,
		Body:       io.NopCloser(bytes.NewReader(s.body)),
		Request:    req,
	}, nil
}

func TestAIAFetcherRefusesUnsafeURLs(t *testing.T) {
	f := NewAIAFetcher(http.DefaultClient, 1<<20)
	cases := []string{
		"file:///etc/passwd",
		"ftp://example.com/ca.pem",
		"http://127.0.0.1:1/x",
		"http://[::1]/x",
		"http://169.254.169.254/latest/meta-data",
		"http://10.0.0.5/ca.pem",
		"http://192.168.1.1/ca.pem",
		"http://172.16.0.1/ca.pem",
		"",
	}
	for _, u := range cases {
		if _, err := f.Fetch(context.Background(), []string{u}); err == nil {
			t.Errorf("%q should be refused", u)
		}
	}
}

func TestAIAFetcherRefusesTooManyURLs(t *testing.T) {
	f := NewAIAFetcher(http.DefaultClient, 1<<20)
	urls := []string{"https://ca.example.test/1", "https://ca.example.test/2", "https://ca.example.test/3", "https://ca.example.test/4"}
	if _, err := f.Fetch(context.Background(), urls); err == nil {
		t.Fatal("expected error for 4 URLs")
	}
}

func TestAIAFetcherParsesPEM(t *testing.T) {
	ca, _ := testutil.NewCA(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	tr := &stubTransport{status: 200, body: pemBytes}
	f := NewAIAFetcher(&http.Client{Transport: tr}, 1<<20)
	ders, err := f.Fetch(context.Background(), []string{"https://ca.example.test/root.pem"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ders) != 1 || !bytes.Equal(ders[0], ca.Raw) {
		t.Fatalf("got %d certs", len(ders))
	}
}

func TestAIAFetcherEnforcesLimit(t *testing.T) {
	tr := &stubTransport{status: 200, body: bytes.Repeat([]byte("A"), 100)}
	f := NewAIAFetcher(&http.Client{Transport: tr}, 10)
	if _, err := f.Fetch(context.Background(), []string{"https://ca.example.test/big"}); err == nil {
		t.Fatal("expected size error")
	}
}

func TestAIAFetcherRefusesRedirect(t *testing.T) {
	tr := &stubTransport{status: 302, header: http.Header{"Location": []string{"https://elsewhere.example.test/"}}}
	f := NewAIAFetcher(&http.Client{Transport: tr}, 1<<20)
	if _, err := f.Fetch(context.Background(), []string{"https://ca.example.test/moved"}); err == nil {
		t.Fatal("redirect must be refused")
	}
	if tr.calls != 1 {
		t.Fatalf("transport called %d times, redirect was followed", tr.calls)
	}
}

func TestAIAFetcherRefusesDERlessBody(t *testing.T) {
	tr := &stubTransport{status: 200, body: []byte("<html>not a cert</html>")}
	f := NewAIAFetcher(&http.Client{Transport: tr}, 1<<20)
	if _, err := f.Fetch(context.Background(), []string{"https://ca.example.test/ca"}); err == nil {
		t.Fatal("expected error for non-certificate body")
	} else if !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAIAFetcherEmptyURLListIsError(t *testing.T) {
	f := NewAIAFetcher(http.DefaultClient, 1<<20)
	if _, err := f.Fetch(context.Background(), nil); err == nil {
		t.Fatal("expected error")
	}
}
