package collect

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"

	"github.com/amit/47certificates/internal/testutil"
)

// pemBlock wraps DER in a PEM certificate block.
func pemBlock(der []byte) *pem.Block {
	return &pem.Block{Type: "CERTIFICATE", Bytes: der}
}

var _ = x509.Certificate{}

// The AIA fetcher must not reach an address that is not publicly routable,
// even when the hostname resolves to one.
func TestAIAFetcherRefusesInternalAddresses(t *testing.T) {
	// The safe transport resolves the name and refuses the address. The
	// localhost name is refused before any request is made.
	f := NewAIAFetcher(nil, 1<<20)
	if _, err := f.Fetch(context.Background(), []string{"http://localhost/ca.pem"}); err == nil {
		t.Fatal("localhost must be refused")
	}
	if _, err := f.Fetch(context.Background(), []string{"http://127.0.0.1/ca.pem"}); err == nil {
		t.Fatal("a loopback literal must be refused")
	}
}

// A hostname that resolves to a private address is refused: the check
// happens after resolution.
func TestSafeDialerRefusesPrivateResolution(t *testing.T) {
	d := &safeDialer{}
	_, err := d.DialContext(context.Background(), "tcp", "localhost:80")
	if err == nil {
		t.Fatal("a name resolving to a loopback address must be refused")
	}
	if !strings.Contains(err.Error(), "not routable") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// The fetcher considers at most three URLs and uses the first that works.
func TestAIAFetcherUsesAtMostThreeURLs(t *testing.T) {
	ca, _ := testutil.NewCA(t)
	pemBytes := pem.EncodeToMemory(pemBlock(ca.Raw))
	tr := &stubTransport{status: 200, body: pemBytes}
	f := NewAIAFetcher(&http.Client{Transport: tr}, 1<<20)
	urls := []string{
		"https://ca.example.test/1",
		"https://ca.example.test/2",
		"https://ca.example.test/3",
		"https://ca.example.test/4",
	}
	ders, err := f.Fetch(context.Background(), urls)
	if err != nil {
		t.Fatal(err)
	}
	if len(ders) != 1 {
		t.Fatalf("got %d certs", len(ders))
	}
}
