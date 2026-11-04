package collect

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/bamit99/47certificates/internal/roots"
)

// safeDialer refuses to connect to addresses that are not publicly routable.
// It is the last line of defence for the one outbound request 47c makes to a
// URL that came from remote data (the AIA caIssuers URL in a certificate).
//
// The hostname check happens after resolution, so a public name that points at
// 127.0.0.1 or 169.254.169.254 is refused too.
type safeDialer struct {
	dialer *net.Dialer
}

// newSafeTransport returns a transport that dials only public addresses and
// refuses redirects. HTTPS is verified against the embedded Mozilla bundle:
// the scratch runtime has no CA directory.
func newSafeTransport(timeout time.Duration) *http.Transport {
	return &http.Transport{
		DialContext:           (&safeDialer{dialer: &net.Dialer{Timeout: timeout}}).DialContext,
		TLSClientConfig:       &tls.Config{RootCAs: roots.Pool(), MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DisableKeepAlives:     false,
	}
}

func (d *safeDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("aia: bad address %q", addr)
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("aia: resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("aia: %q has no addresses", host)
	}
	var firstErr error
	for _, ip := range ips {
		if unsafeIP(ip.IP) {
			firstErr = fmt.Errorf("aia: address %s is not routable", ip.IP)
			continue
		}
		conn, err := d.dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = errors.New("aia: no usable address")
	}
	return nil, firstErr
}
