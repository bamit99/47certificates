// Package jobs runs scans in the background and broadcasts their progress.
package jobs

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amit/47certificates/internal/scan"
	"github.com/amit/47certificates/internal/scope"
	"github.com/amit/47certificates/internal/store"
)

// ErrBusy is returned when a scan is already running.
var ErrBusy = errors.New("jobs: a scan is already running")

// Runner launches scans and tracks the one currently in flight.
type Runner struct {
	Store *store.Store
	Eng   *scan.Engine
	Now   func() time.Time

	mu      sync.Mutex
	current int64 // 0 idle, -1 reserving, >0 running scan id
	cancel  context.CancelFunc
	subs    map[int64][]chan scan.Progress
	// pending holds the domains still to scan, in order. A scan covers one
	// domain, so a request for every domain is a queue of scans.
	pending []domainScan
}

// domainScan is one queued scan of one domain.
type domainScan struct {
	domainID int64
	domain   string
	set      *scope.Set
}

// New returns a Runner. A nil Engine is rejected at trigger time.
func New(st *store.Store, eng *scan.Engine, now func() time.Time) *Runner {
	if now == nil {
		now = time.Now
	}
	return &Runner{Store: st, Eng: eng, Now: now, subs: map[int64][]chan scan.Progress{}}
}

// TriggerScan reserves the single-flight slot, inserts a queued scan, and
// starts it in the background.
//
// The scan covers one domain. An empty domain name scans every domain the
// allowlist names, one after another.
func (r *Runner) TriggerScan(ctx context.Context, trigger string, userID *int64) (int64, error) {
	return r.TriggerDomainScan(ctx, trigger, userID, "")
}

// TriggerDomainScan starts a scan of one domain. An empty name scans every
// domain the allowlist names, one after another.
func (r *Runner) TriggerDomainScan(ctx context.Context, trigger string, userID *int64, domainName string) (int64, error) {
	if r.Store == nil || r.Eng == nil {
		return 0, fmt.Errorf("jobs: runner is not configured")
	}
	r.mu.Lock()
	if r.current != 0 {
		r.mu.Unlock()
		return 0, ErrBusy
	}
	r.current = -1
	r.mu.Unlock()

	releaseReservation := func() {
		r.mu.Lock()
		r.current = 0
		r.mu.Unlock()
	}

	domains, err := r.targetDomains(ctx, domainName)
	if err != nil {
		releaseReservation()
		return 0, err
	}
	if len(domains) == 0 {
		releaseReservation()
		return 0, fmt.Errorf("jobs: no domain to scan")
	}
	ports, concurrency, qps, hostQPS, maxHosts, timeout := r.scanSettings(ctx)

	// Re-check the store lock so a CLI scan also blocks the web trigger.
	lockCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	lock, err := r.Store.AcquireScanLock(lockCtx)
	cancel()
	if err != nil {
		releaseReservation()
		if errors.Is(err, store.ErrScanInProgress) {
			return 0, ErrBusy
		}
		return 0, err
	}
	lock.Release()

	// The first domain's scan row is the one the caller follows.
	scanID, err := r.Store.BeginDomainScan(ctx, trigger, userID, domains[0].domainID)
	if err != nil {
		releaseReservation()
		return 0, err
	}

	eng := *r.Eng
	eng.Concurrency = concurrency
	eng.QPS = qps
	eng.HostQPS = hostQPS
	eng.MaxHosts = maxHosts
	eng.Timeout = timeout

	scanCtx, scanCancel := context.WithCancel(context.Background())
	r.mu.Lock()
	r.current = scanID
	r.cancel = scanCancel
	r.mu.Unlock()

	go func() {
		defer func() {
			r.mu.Lock()
			r.current = 0
			r.cancel = nil
			subs := r.subs[scanID]
			delete(r.subs, scanID)
			r.mu.Unlock()
			for _, ch := range subs {
				close(ch)
			}
		}()
		for _, d := range domains {
			if scanCtx.Err() != nil {
				break
			}
			id := scanID
			if d.domainID != domains[0].domainID {
				id, err = r.Store.BeginDomainScan(scanCtx, trigger, userID, d.domainID)
				if err != nil {
					break
				}
			}
			_, _ = eng.Run(scanCtx, id, d.set, ports, func(p scan.Progress) {
				r.broadcast(scanID, p)
			})
		}
		r.broadcast(scanID, scan.Progress{Stage: "done", Done: 1, Total: 1})
	}()

	return scanID, nil
}

// targetDomains returns the domains to scan, each with the scope that covers
// it. An empty name means every domain the allowlist names.
func (r *Runner) targetDomains(ctx context.Context, name string) ([]domainScan, error) {
	entries, err := r.Store.ListScope(ctx)
	if err != nil {
		return nil, err
	}
	var includes, excludes, seeds []string
	for _, e := range entries {
		switch e.Kind {
		case "include":
			includes = append(includes, e.Value)
		case "exclude":
			excludes = append(excludes, e.Value)
		case "seed":
			seeds = append(seeds, e.Value)
		}
	}
	if name != "" {
		found := false
		for _, inc := range includes {
			if strings.EqualFold(inc, name) {
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("jobs: %q is not in the allowlist", name)
		}
		includes = []string{name}
	}
	if len(includes) == 0 {
		return nil, fmt.Errorf("jobs: the allowlist names no domain")
	}

	var out []domainScan
	for _, inc := range includes {
		// The scope of one domain: the domain, the excludes that apply to
		// it, and the seeds that sit inside it.
		entries := []scope.Entry{{Kind: scope.Include, Value: inc}}
		for _, ex := range excludes {
			entries = append(entries, scope.Entry{Kind: scope.Exclude, Value: ex})
		}
		for _, sd := range seeds {
			if !strings.HasSuffix(sd, "."+inc) && !strings.EqualFold(sd, inc) {
				continue
			}
			entries = append(entries, scope.Entry{Kind: scope.Seed, Value: sd})
		}
		set, err := scope.New(entries)
		if err != nil {
			return nil, err
		}
		domainID, err := r.Store.EnsureDomain(ctx, inc)
		if err != nil {
			return nil, err
		}
		out = append(out, domainScan{domainID: domainID, domain: inc, set: set})
	}
	return out, nil
}

// Cancel cancels the currently running scan.
func (r *Runner) Cancel(scanID int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current == scanID && r.cancel != nil {
		r.cancel()
		return nil
	}
	if r.current > 0 {
		return fmt.Errorf("jobs: scan %d is running, not %d", r.current, scanID)
	}
	return fmt.Errorf("jobs: scan %d is not running", scanID)
}

// Subscribe registers for progress events of one scan. The returned channel is
// closed when the scan ends.
func (r *Runner) Subscribe(scanID int64) (<-chan scan.Progress, func()) {
	ch := make(chan scan.Progress, 16)
	r.mu.Lock()
	r.subs[scanID] = append(r.subs[scanID], ch)
	r.mu.Unlock()
	cancel := func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		list := r.subs[scanID]
		for i, c := range list {
			if c == ch {
				r.subs[scanID] = append(list[:i], list[i+1:]...)
				close(ch)
				return
			}
		}
	}
	return ch, cancel
}

func (r *Runner) broadcast(scanID int64, p scan.Progress) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ch := range r.subs[scanID] {
		select {
		case ch <- p:
		default:
		}
	}
}

func (r *Runner) scopeSet(ctx context.Context) (*scope.Set, error) {
	entries, err := r.Store.ListScope(ctx)
	if err != nil {
		return nil, err
	}
	set := make([]scope.Entry, 0, len(entries))
	for _, e := range entries {
		switch e.Kind {
		case "include":
			set = append(set, scope.Entry{Kind: scope.Include, Value: e.Value})
		case "exclude":
			set = append(set, scope.Entry{Kind: scope.Exclude, Value: e.Value})
		case "seed":
			set = append(set, scope.Entry{Kind: scope.Seed, Value: e.Value})
		}
	}
	return scope.New(set)
}

func (r *Runner) scanSettings(ctx context.Context) (ports []int, concurrency, qps, hostQPS, maxHosts int, timeout time.Duration) {
	// Defaults: 443 only, 32 workers, 25 qps overall, 1 qps per host, 1000
	// hosts per scope, 10s timeout.
	ports = []int{443}
	concurrency = 32
	qps = 25
	hostQPS = 1
	maxHosts = 1000
	timeout = 10 * time.Second

	if v := r.stringSetting(ctx, "ports", ""); v != "" {
		if parsed := parsePorts(v); len(parsed) > 0 {
			ports = parsed
		}
	}
	if v := r.stringSetting(ctx, "concurrency", ""); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			concurrency = n
		}
	}
	if v := r.stringSetting(ctx, "qps", ""); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			qps = n
		}
	}
	if v := r.stringSetting(ctx, "host_qps", ""); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			hostQPS = n
		}
	}
	if v := r.stringSetting(ctx, "max_hosts", ""); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxHosts = n
		}
	}
	if v := r.stringSetting(ctx, "timeout", ""); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			timeout = d
		}
	}
	return ports, concurrency, qps, hostQPS, maxHosts, timeout
}

func (r *Runner) stringSetting(ctx context.Context, key, def string) string {
	v, err := r.Store.GetSetting(ctx, key)
	if err != nil || strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func parsePorts(s string) []int {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if n, err := strconv.Atoi(part); err == nil && n >= 1 && n <= 65535 {
			out = append(out, n)
		}
	}
	return out
}
