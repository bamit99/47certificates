package roots

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
	"sync"
)

//go:embed ca.pem
var bundle []byte

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
