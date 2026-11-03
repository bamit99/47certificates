// Package collect dials TLS endpoints and returns the certificates they serve.
package collect

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strconv"
	"time"
)

// Endpoint is one address to probe. Host is sent as SNI; IP is dialled.
type Endpoint struct {
	Host string
	Port int
	IP   string
}

// Observation is the result of one probe.
type Observation struct {
	Endpoint   Endpoint
	LeafDER    []byte
	ChainDER   [][]byte
	TLSVersion uint16
	Cipher     uint16
	// CAA is reserved: v1 does not query CAA records.
	CAA []string
	Err error
}

// Options controls a probe.
type Options struct {
	// Timeout bounds one connection attempt. Zero means 10s.
	Timeout time.Duration
	// MinVersion is the lowest TLS version accepted. Zero means TLS 1.2.
	MinVersion uint16
	// AIA, when set, fetches missing intermediates from caIssuers URLs.
	AIA *AIAFetcher
}

// Probe dials ep and returns the served chain. A failed handshake is retried
// once after 500 ms; the final error is reported in Observation.Err.
func Probe(ctx context.Context, ep Endpoint, opts Options) Observation {
	obs := Observation{Endpoint: ep}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	minVersion := opts.MinVersion
	if minVersion == 0 {
		minVersion = tls.VersionTLS12
	}

	var err error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				obs.Err = ctx.Err()
				return obs
			case <-time.After(500 * time.Millisecond):
			}
		}
		obs, err = probeOnce(ctx, ep, timeout, minVersion)
		if err == nil {
			break
		}
	}
	if err != nil {
		obs.Err = err
		return Observation{Endpoint: ep, Err: err}
	}

	if opts.AIA != nil && len(obs.LeafDER) > 0 {
		obs.ChainDER = append(obs.ChainDER, fetchAIA(ctx, opts.AIA, obs.LeafDER, obs.ChainDER)...)
	}
	return obs
}

func probeOnce(ctx context.Context, ep Endpoint, timeout time.Duration, minVersion uint16) (Observation, error) {
	obs := Observation{Endpoint: ep}
	dialer := &net.Dialer{Timeout: timeout}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	raw, err := dialer.DialContext(dctx, "tcp", net.JoinHostPort(ep.IP, strconv.Itoa(ep.Port)))
	if err != nil {
		return obs, err
	}
	defer raw.Close()

	conn := tls.Client(raw, &tls.Config{
		ServerName:         ep.Host,
		InsecureSkipVerify: true, // we classify trust ourselves
		MinVersion:         minVersion,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	hctx, hcancel := context.WithTimeout(ctx, timeout)
	defer hcancel()
	if err := conn.HandshakeContext(hctx); err != nil {
		return obs, err
	}
	state := conn.ConnectionState()
	obs.TLSVersion = state.Version
	obs.Cipher = state.CipherSuite
	if len(state.PeerCertificates) > 0 {
		obs.LeafDER = append([]byte{}, state.PeerCertificates[0].Raw...)
		for _, c := range state.PeerCertificates[1:] {
			obs.ChainDER = append(obs.ChainDER, append([]byte{}, c.Raw...))
		}
	}
	return obs, nil
}

// fetchAIA downloads missing issuers. Failures are ignored: an unreachable AIA
// URL leaves the chain incomplete, which is a finding, not a probe failure.
func fetchAIA(ctx context.Context, f *AIAFetcher, leafDER []byte, existing [][]byte) [][]byte {
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil || len(leaf.IssuingCertificateURL) == 0 {
		return nil
	}
	fetched, err := f.Fetch(ctx, leaf.IssuingCertificateURL)
	if err != nil {
		return nil
	}
	var out [][]byte
	for _, der := range fetched {
		if bytes.Equal(der, leafDER) {
			continue
		}
		dup := false
		for _, have := range existing {
			if bytes.Equal(have, der) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, der)
		}
	}
	return out
}
