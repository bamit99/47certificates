// Package scan runs the discovery, collection, and evaluation pipeline for one
// scan and exports its results.
package scan

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/amit/47certificates/internal/collect"
	"github.com/amit/47certificates/internal/discover"
	"github.com/amit/47certificates/internal/scope"
	"github.com/amit/47certificates/internal/store"
	"github.com/amit/47certificates/internal/x509eval"
)

// Progress is emitted while a scan advances.
type Progress struct {
	Stage string
	Done  int
	Total int
}

// Stats summarizes one scan.
type Stats struct {
	Stage    string   `json:"stage,omitempty"`
	Hosts    int      `json:"hosts"`
	Endpoints int     `json:"endpoints"`
	Observed int      `json:"observed"`
	Failed   int      `json:"failed"`
	Public   int      `json:"public"`
	Private  int      `json:"private"`
	Untrusted int     `json:"untrusted"`
	Warnings []string `json:"warnings,omitempty"`
}

// Engine executes one scan. All dependencies are injected so the pipeline can
// be exercised without network access.
type Engine struct {
	Store       *store.Store
	Source      discover.Source
	Fallback    discover.Source
	Resolver    discover.Resolver
	Roots       *x509.CertPool
	Now         func() time.Time
	Concurrency int
	QPS         int
	// HostQPS caps the probes per second to any one hostname. Zero means
	// one per second.
	HostQPS int
	// MaxHosts caps how many names one scope may contribute. Zero means no
	// cap.
	MaxHosts int
	Timeout  time.Duration
	// Wait makes lock acquisition block instead of failing when another scan
	// is running.
	Wait bool
}

// domainFor resolves the domain a scan covers. A scan covers one domain, so
// the scope must name exactly one.
//
// The lookup uses its own context: a scan whose context is already cancelled
// must still be able to name its domain, or the scan would never record a
// terminal status.
func (e *Engine) domainFor(ctx context.Context, set *scope.Set) (int64, error) {
	includes := set.Includes()
	if len(includes) != 1 {
		return 0, fmt.Errorf("scan: a scan covers exactly one domain, the scope names %d", len(includes))
	}
	lookupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return e.Store.EnsureDomain(lookupCtx, includes[0])
}

// Run executes the scan identified by scanID. It always records a terminal
// status. A cancelled context cancels the scan and never retires
// certificates.
//
// The scope must cover exactly one domain: a scan's observations, lifecycle
// and findings all belong to that domain, so nothing mixes between estates.
func (e *Engine) Run(ctx context.Context, scanID int64, set *scope.Set, ports []int, progress func(Progress)) (Stats, error) {
	if e.Store == nil {
		return Stats{}, errors.New("scan: engine has no store")
	}
	if e.Roots == nil {
		return Stats{}, errors.New("scan: engine has no root pool")
	}
	if set == nil {
		return Stats{}, errors.New("scan: engine has no scope")
	}
	if len(ports) == 0 {
		ports = []int{443}
	}
	domainID, err := e.domainFor(ctx, set)
	if err != nil {
		e.finish(scanID, "failed", Stats{}, err.Error())
		return Stats{}, err
	}
	now := time.Now
	if e.Now != nil {
		now = e.Now
	}

	release, err := e.acquire(ctx)
	if err != nil {
		e.finish(scanID, "failed", Stats{}, err.Error())
		return Stats{}, err
	}
	defer release.Release()

	// A scan can run longer than the lock's stale threshold. Refresh the
	// lease while it works so no second scan can start alongside it.
	stopHeartbeat := make(chan struct{})
	defer close(stopHeartbeat)
	go e.heartbeat(release, stopHeartbeat)

	markCtx, markCancel := context.WithTimeout(context.Background(), 15*time.Second)
	err = e.Store.MarkRunning(markCtx, scanID)
	markCancel()
	if err != nil {
		e.finish(scanID, "failed", Stats{}, err.Error())
		return Stats{}, err
	}

	report := func(p Progress) {
		if progress != nil {
			progress(p)
		}
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		stats := Stats{}
		e.finish(scanID, "cancelled", stats, ctxErr.Error())
		return stats, ctxErr
	}

	// The counters are published while the scan runs so the UI can show
	// movement, and again when it ends.
	stats := Stats{Stage: "discover"}
	publish := func(stage string) {
		stats.Stage = stage
		payload, err := jsonStats(stats)
		if err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = e.Store.UpdateScanStats(ctx, scanID, payload)
	}

	report(Progress{Stage: "discover"})
	// Publish before discovery starts: it can take a while, and the UI
	// should show that the scan is running rather than an empty page.
	publish("discover")
	cachedNames, remember := ctCache(e.Store)
	dnsLookup, dnsStore := dnsCache(e.Store)
	disc, derr := discover.Run(ctx, set, e.Source, e.Resolver, discover.Options{
		Fallback:        e.Fallback,
		CachedNames:     cachedNames,
		RememberSuccess: remember,
		DNSLookup:       dnsLookup,
		DNSStore:        dnsStore,
		DNSMaxAge:       dnsCacheMaxAge,
		MaxHosts:        e.MaxHosts,
	})
	stats.Warnings = disc.Warnings
	if derr != nil {
		stats.Warnings = append(stats.Warnings, "discover: "+derr.Error())
	}
	stats.Hosts = len(disc.Hosts)
	publish("discover")
	if ctxErr := ctx.Err(); ctxErr != nil {
		e.finish(scanID, "cancelled", stats, ctxErr.Error())
		return stats, ctxErr
	}

	endpoints := expand(disc, ports)
	stats.Endpoints = len(endpoints)
	report(Progress{Stage: "probe", Done: 0, Total: len(endpoints)})
	publish("probe")

	var (
		mu     sync.Mutex
		runErr error
		done   int
	)
	workers := e.Concurrency
	if workers <= 0 {
		workers = 32
	}
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	aia := collect.NewAIAFetcher(nil, 1<<20)
	probeOpts := collect.Options{Timeout: timeout, AIA: aia}

	jobs := make(chan collect.Endpoint)
	results := make(chan collect.Observation, workers)
	tick := newTicker(e.QPS)
	// Per-host limiter: a scan must not hammer one server. Many names of a
	// domain share a single address, and a burst of handshakes to one IP
	// from one client is what an edge firewall sees as an attack.
	hostLimiter := newHostLimiter(e.HostQPS)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ep := range jobs {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
				}
				select {
				case <-ctx.Done():
					return
				case <-hostLimiter.wait(ctx, ep.Host):
				}
				results <- collect.Probe(ctx, ep, probeOpts)
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, ep := range endpoints {
			select {
			case <-ctx.Done():
				return
			case jobs <- ep:
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	// The counters are published while the scan runs so the UI can show
	// movement, and again when it ends.
	for obs := range results {
		done++
		func() {
			defer func() {
				report(Progress{Stage: "probe", Done: done, Total: len(endpoints)})
				publish("probe")
			}()
			if obs.Err != nil {
				stats.Failed++
				if len(stats.Warnings) < 50 {
					stats.Warnings = append(stats.Warnings, fmt.Sprintf("probe %s:%d: %v", obs.Endpoint.Host, obs.Endpoint.Port, obs.Err))
				}
				return
			}
			if len(obs.LeafDER) == 0 {
				stats.Failed++
				return
			}
			trust, err := e.record(ctx, scanID, domainID, obs, now())
			if err != nil {
				mu.Lock()
				if runErr == nil {
					runErr = err
				}
				mu.Unlock()
				stats.Failed++
				return
			}
			stats.Observed++
			switch trust {
			case "public":
				stats.Public++
			case "private":
				stats.Private++
			default:
				stats.Untrusted++
			}
		}()
	}
	if tick.Stop != nil {
		tick.Stop()
	}

	if ctxErr := ctx.Err(); ctxErr != nil {
		e.finish(scanID, "cancelled", stats, ctxErr.Error())
		return stats, ctxErr
	}
	if runErr != nil {
		e.finish(scanID, "failed", stats, runErr.Error())
		return stats, runErr
	}
	stats.Stage = "done"
	e.finish(scanID, "done", stats, "")
	// Lifecycle fields (last_seen, retired_at) and finding closure are owned
	// by scans that end "done". A cancelled or failed scan persists its
	// observations and progress but must never look like mass retirement.
	finalizeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := e.Store.MarkSeen(finalizeCtx, scanID, domainID); err != nil {
		return stats, err
	}
	if err := e.Store.ResolveStaleFindings(finalizeCtx, scanID, domainID); err != nil {
		return stats, err
	}
	if err := e.Store.RetireUnseen(finalizeCtx, scanID, domainID); err != nil {
		return stats, err
	}
	report(Progress{Stage: "done", Done: len(endpoints), Total: len(endpoints)})
	return stats, nil
}

func (e *Engine) record(ctx context.Context, scanID, domainID int64, obs collect.Observation, now time.Time) (string, error) {
	c, err := x509eval.Parse(obs.LeafDER, obs.ChainDER)
	if err != nil {
		return "", err
	}
	v := x509eval.Verify(obs.LeafDER, obs.ChainDER, obs.Endpoint.Host, e.Roots, now)
	findings := x509eval.Findings(c, v, now)

	// Certificate-level findings (lifetime, expiry) belong to the certificate:
	// one row per certificate however many endpoints serve it. Endpoint-level
	// findings (hostname mismatch, chain trust) belong to the endpoint.
	certLevel, endpointLevel := x509eval.SplitFindings(findings)

	certID, err := e.Store.UpsertCert(ctx, c)
	if err != nil {
		return "", err
	}
	endpointID, err := e.Store.UpsertEndpoint(ctx, domainID, obs.Endpoint.Host, obs.Endpoint.Port, obs.Endpoint.IP, scanID)
	if err != nil {
		return "", err
	}
	if err := e.Store.RecordObservation(ctx, scanID, domainID, endpointID, certID, v, obs.TLSVersion, obs.Cipher, obs.CAA); err != nil {
		return "", err
	}
	if err := e.Store.SyncFindings(ctx, scanID, domainID, certID, nil, certLevel, now); err != nil {
		return "", err
	}
	if err := e.Store.SyncFindings(ctx, scanID, domainID, certID, &endpointID, endpointLevel, now); err != nil {
		return "", err
	}
	return v.Trust, nil
}

// ctCache wires the 6-hour certificate-transparency cache to the store's
// settings table, so a rescan within the window does not re-hit crt.sh.
//
// The cache stores the names it saw, not just the time: a cached domain must
// still contribute its hosts, or the rescan would retire the certificates
// that only CT had revealed.
func ctCache(st *store.Store) (func(string) ([]string, bool), func(string, []string)) {
	if st == nil {
		return nil, nil
	}
	cached := func(domain string) ([]string, bool) {
		v, err := st.GetSetting(context.Background(), ctCacheKey(domain))
		if err != nil {
			return nil, false
		}
		var entry ctCacheEntry
		if err := json.Unmarshal([]byte(v), &entry); err != nil {
			return nil, false
		}
		if time.Since(time.Unix(entry.At, 0)) >= ctCacheTTL {
			return nil, false
		}
		return entry.Names, true
	}
	remember := func(domain string, names []string) {
		entry := ctCacheEntry{At: time.Now().Unix(), Names: names}
		b, err := json.Marshal(entry)
		if err != nil {
			return
		}
		_ = st.SetSetting(context.Background(), ctCacheKey(domain), string(b))
	}
	return cached, remember
}

// ctCacheTTL is how long a CT answer is reused.
const ctCacheTTL = 6 * time.Hour

// dnsCacheMaxAge is how long a DNS answer is reused.
//
// A scan resolves every name a transparency log mentions. Most of those
// names are retired and do not exist, so most of the queries are answered
// "no such host" and re-asking them changes nothing. Caching the negative
// answers keeps the resolver load of a repeated scan near zero, which is
// what stops the scan from looking like a flood.
const dnsCacheMaxAge = 24 * time.Hour

func ctCacheKey(domain string) string { return "ct_cache:" + domain }

// dnsCache wires the DNS answer cache to the store.
func dnsCache(st *store.Store) (func(string) ([]string, string, bool, bool), func(string, []string, string, bool)) {
	if st == nil {
		return nil, nil
	}
	cache := st.DNSCache()
	lookup := func(host string) ([]string, string, bool, bool) {
		a, ok := cache.Lookup(context.Background(), host, dnsCacheMaxAge)
		if !ok {
			return nil, "", false, false
		}
		return a.IPs, a.CNAME, a.NXDomain, true
	}
	remember := func(host string, ips []string, cname string, nxdomain bool) {
		_ = cache.Store(context.Background(), host, store.DNSAnswer{
			IPs:      ips,
			CNAME:    cname,
			NXDomain: nxdomain,
		})
	}
	return lookup, remember
}

// ctCacheEntry is the cached CT answer for one domain.
type ctCacheEntry struct {
	At    int64    `json:"at"`
	Names []string `json:"names"`
}

func expand(disc discover.Result, ports []int) []collect.Endpoint {
	var out []collect.Endpoint
	for _, host := range disc.Hosts {
		for _, ip := range disc.IPs[host] {
			for _, port := range ports {
				out = append(out, collect.Endpoint{Host: host, Port: port, IP: ip})
			}
		}
	}
	return out
}

func (e *Engine) acquire(ctx context.Context) (*store.ScanLock, error) {
	for {
		lockCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		release, err := e.Store.AcquireScanLock(lockCtx)
		cancel()
		if err == nil {
			return release, nil
		}
		if !errors.Is(err, store.ErrScanInProgress) || !e.Wait {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// heartbeat extends the scan lock's lease until stop is closed.
func (e *Engine) heartbeat(lock *store.ScanLock, stop <-chan struct{}) {
	ticker := time.NewTicker(lockRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			ok, err := lock.Refresh(ctx)
			cancel()
			if err != nil {
				return
			}
			if !ok {
				// The lock was reclaimed by another holder; stop touching it.
				return
			}
		}
	}
}

// lockRefreshInterval is how often a running scan extends its lock lease.
const lockRefreshInterval = 5 * time.Minute

func (e *Engine) finish(scanID int64, status string, stats Stats, errMsg string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	payload, err := jsonStats(stats)
	if err != nil {
		payload = []byte(`{}`)
	}
	_ = e.Store.FinishScan(ctx, scanID, status, payload, errMsg)
}

// limiter is a stoppable ticker. A non-positive QPS is treated as 1000/s,
// which is effectively unlimited for an allowlist under 1,000 names.
type limiter struct {
	C    <-chan time.Time
	Stop func()
}

func newTicker(qps int) limiter {
	if qps <= 0 {
		qps = 1000
	}
	interval := time.Second / time.Duration(qps)
	if interval <= 0 {
		interval = time.Millisecond
	}
	t := time.NewTicker(interval)
	return limiter{C: t.C, Stop: t.Stop}
}

// hostLimiter spaces out the probes of one hostname.
//
// A scan resolves every name a transparency log mentions, and the names of
// one domain often share an address. Without this, a scan can open dozens of
// connections to one server in a second, which is what a firewall or an edge
// provider sees as an attack rather than an audit.
type hostLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     map[string]time.Time
}

// newHostLimiter returns a limiter that allows qps probes per second per
// hostname. A non-positive qps means one probe per second.
func newHostLimiter(qps int) *hostLimiter {
	if qps <= 0 {
		qps = 1
	}
	return &hostLimiter{
		interval: time.Second / time.Duration(qps),
		next:     map[string]time.Time{},
	}
}

// wait returns a channel that becomes ready when the host may be probed.
func (l *hostLimiter) wait(ctx context.Context, host string) <-chan time.Time {
	ch := make(chan time.Time, 1)
	delay := l.reserve(host)
	if delay <= 0 {
		ch <- time.Now()
		return ch
	}
	t := time.NewTimer(delay)
	go func() {
		defer t.Stop()
		select {
		case <-ctx.Done():
			close(ch)
		case <-t.C:
			ch <- time.Now()
		}
	}()
	return ch
}

// reserve books the next slot for host and returns how long to wait.
func (l *hostLimiter) reserve(host string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	at := l.next[host]
	if at.Before(now) {
		at = now
	}
	l.next[host] = at.Add(l.interval)
	return at.Sub(now)
}
