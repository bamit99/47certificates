// Package scan runs the discovery, collection, and evaluation pipeline for one
// scan and exports its results.
package scan

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
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
	Hosts     int      `json:"hosts"`
	Endpoints int      `json:"endpoints"`
	Observed  int      `json:"observed"`
	Failed    int      `json:"failed"`
	Public    int      `json:"public"`
	Private   int      `json:"private"`
	Untrusted int      `json:"untrusted"`
	Warnings  []string `json:"warnings,omitempty"`
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
	Timeout     time.Duration
	// Wait makes lock acquisition block instead of failing when another scan
	// is running.
	Wait bool
}

// Run executes the scan identified by scanID. It always records a terminal
// status. A cancelled context cancels the scan and never retires certificates.
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
	now := time.Now
	if e.Now != nil {
		now = e.Now
	}

	release, err := e.acquire(ctx)
	if err != nil {
		e.finish(scanID, "failed", Stats{}, err.Error())
		return Stats{}, err
	}
	defer release()

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

	report(Progress{Stage: "discover"})
	disc, derr := discover.Run(ctx, set, e.Source, e.Resolver, discover.Options{Fallback: e.Fallback})
	stats := Stats{Warnings: disc.Warnings}
	if derr != nil {
		stats.Warnings = append(stats.Warnings, "discover: "+derr.Error())
	}
	stats.Hosts = len(disc.Hosts)
	if ctxErr := ctx.Err(); ctxErr != nil {
		e.finish(scanID, "cancelled", stats, ctxErr.Error())
		return stats, ctxErr
	}

	endpoints := expand(disc, ports)
	stats.Endpoints = len(endpoints)
	report(Progress{Stage: "probe", Done: 0, Total: len(endpoints)})

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
	aia := collect.NewAIAFetcher(&http.Client{}, 1<<20)
	probeOpts := collect.Options{Timeout: timeout, AIA: aia}

	jobs := make(chan collect.Endpoint)
	results := make(chan collect.Observation, workers)
	tick := newTicker(e.QPS)

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

	for obs := range results {
		done++
		func() {
			defer func() { report(Progress{Stage: "probe", Done: done, Total: len(endpoints)}) }()
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
			trust, err := e.record(ctx, scanID, obs, now())
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
	e.finish(scanID, "done", stats, "")
	retireCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := e.Store.RetireUnseen(retireCtx, scanID); err != nil {
		return stats, err
	}
	report(Progress{Stage: "done", Done: len(endpoints), Total: len(endpoints)})
	return stats, nil
}

func (e *Engine) record(ctx context.Context, scanID int64, obs collect.Observation, now time.Time) (string, error) {
	c, err := x509eval.Parse(obs.LeafDER, obs.ChainDER)
	if err != nil {
		return "", err
	}
	v := x509eval.Verify(obs.LeafDER, obs.ChainDER, obs.Endpoint.Host, e.Roots, now)
	findings := x509eval.Findings(c, v, now)

	certID, err := e.Store.UpsertCert(ctx, c)
	if err != nil {
		return "", err
	}
	endpointID, err := e.Store.UpsertEndpoint(ctx, obs.Endpoint.Host, obs.Endpoint.Port, obs.Endpoint.IP, scanID)
	if err != nil {
		return "", err
	}
	if err := e.Store.RecordObservation(ctx, scanID, endpointID, certID, v, obs.TLSVersion, obs.Cipher, obs.CAA); err != nil {
		return "", err
	}
	if err := e.Store.SyncFindings(ctx, scanID, certID, &endpointID, findings, now); err != nil {
		return "", err
	}
	return v.Trust, nil
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

func (e *Engine) acquire(ctx context.Context) (func(), error) {
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
