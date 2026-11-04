package roots

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
	"net/http"
	"sync"
	"time"
)

//go:embed ca.pem
var bundle []byte

// HTTPClient returns an HTTPS client verified against the embedded Mozilla
// bundle. The scratch runtime has no CA directory, so every outbound HTTPS
// call must pin here instead of relying on system defaults.
func HTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: Pool()},
		},
	}
}

var (
	once sync.Once
	pool *x509.CertPool
)

// Pool returns the embedded Mozilla root pool. It panics when the bundle is
// unusable: a missing trust store would silently misclassify every chain.
func Pool() *x509.CertPool {
	once.Do(func() {
		p := x509.NewCertPool()
		n := 0
		rest := bundle
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				panic(fmt.Sprintf("roots: parse embedded root: %v", err))
			}
			p.AddCert(cert)
			n++
		}
		if n < 100 {
			panic(fmt.Sprintf("roots: embedded bundle has only %d certificates", n))
		}
		pool = p
	})
	return pool
}
