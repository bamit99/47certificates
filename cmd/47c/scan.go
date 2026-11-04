package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bamit99/47certificates/internal/discover"
	"github.com/bamit99/47certificates/internal/roots"
	"github.com/bamit99/47certificates/internal/scan"
	"github.com/bamit99/47certificates/internal/scope"
	"github.com/bamit99/47certificates/internal/store"
)

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	dataDir := fs.String("data-dir", envOr("47C_DATA_DIR", "./data"), "directory for the database")
	scopePath := fs.String("scope", "", "scope file: one kind:value per line (default: the scope stored in the database)")
	outPath := fs.String("out", "", "write results to this .csv or .json file")
	portsFlag := fs.String("ports", "443", "comma-separated TCP ports")
	wait := fs.Bool("wait", false, "wait for a running scan instead of failing")
	timeout := fs.Duration("timeout", 10*time.Second, "per-connection timeout")
	concurrency := fs.Int("concurrency", 32, "parallel probes")
	qps := fs.Int("qps", 25, "probes per second")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *outPath != "" {
		ext := strings.ToLower(filepath.Ext(*outPath))
		if ext != ".csv" && ext != ".json" {
			return fmt.Errorf("scan: --out must end in .csv or .json, got %q", *outPath)
		}
	}
	ports, err := parsePorts(*portsFlag)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(*dataDir, "47c.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(); err != nil {
		return err
	}

	// A scope file overrides the stored scope; without one, the scan runs
	// against the allowlist in force, which is what the UI scans use.
	var set *scope.Set
	if *scopePath != "" {
		set, err = loadScope(*scopePath)
		if err != nil {
			return err
		}
	} else {
		set, err = storedScope(st)
		if err != nil {
			return err
		}
	}
	// A scan covers one domain. The CLI scans each of them in turn.
	domains, err := scopeDomains(set)
	if err != nil {
		return err
	}

	ctx := context.Background()
	for _, domain := range domains {
		one, err := scope.New([]scope.Entry{{Kind: scope.Include, Value: domain}})
		if err != nil {
			return err
		}
		domainID, err := st.EnsureDomain(ctx, domain)
		if err != nil {
			return err
		}
		scanID, err := st.BeginDomainScan(ctx, "cli", nil, domainID)
		if err != nil {
			return err
		}

		eng := &scan.Engine{
			Store:       st,
			Source:      discover.NewCRTSource(nil),
			Fallback:    discover.NewCertSpotterSource(nil),
			Resolver:    discover.NetResolver{},
			Roots:       roots.Pool(),
			Now:         time.Now,
			Concurrency: *concurrency,
			QPS:         *qps,
			Timeout:     *timeout,
			Wait:        *wait,
		}
		stats, runErr := eng.Run(ctx, scanID, one, ports, nil)
		if writeErr := writeExport(ctx, st, scanID, *outPath); writeErr != nil && runErr == nil {
			runErr = writeErr
		}

		sc, _ := st.ScanByID(ctx, scanID)
		fmt.Printf("scan %d %s %s: hosts=%d endpoints=%d observed=%d public=%d private=%d untrusted=%d failed=%d\n",
			scanID, domain, sc.Status, stats.Hosts, stats.Endpoints, stats.Observed,
			stats.Public, stats.Private, stats.Untrusted, stats.Failed)
		if runErr != nil {
			return runErr
		}
	}
	return nil
}

// scopeDomains returns the domains a scope names.
func scopeDomains(set *scope.Set) ([]string, error) {
	includes := set.Includes()
	if len(includes) == 0 {
		return nil, errors.New("scan: the scope names no domain")
	}
	return includes, nil
}

func writeExport(ctx context.Context, st *store.Store, scanID int64, path string) error {
	if path == "" {
		return nil
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if strings.ToLower(filepath.Ext(path)) == ".json" {
		return scan.ExportJSON(ctx, st, scanID, f)
	}
	return scan.ExportCSV(ctx, st, scanID, f)
}

// storedScope builds the allowlist from the rows in the database.
func storedScope(st *store.Store) (*scope.Set, error) {
	entries, err := st.ListScope(context.Background())
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errors.New("scan: no scope configured; add one in the UI or pass --scope")
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

// loadScope parses "kind:value" lines. Blank lines and # comments are ignored.
func loadScope(path string) (*scope.Set, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("scan: read scope: %w", err)
	}
	var entries []scope.Entry
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kind, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("scan: scope line %d: expected kind:value", i+1)
		}
		var k scope.Kind
		switch strings.ToLower(strings.TrimSpace(kind)) {
		case "include":
			k = scope.Include
		case "exclude":
			k = scope.Exclude
		case "seed":
			k = scope.Seed
		default:
			return nil, fmt.Errorf("scan: scope line %d: unknown kind %q", i+1, kind)
		}
		entries = append(entries, scope.Entry{Kind: k, Value: strings.TrimSpace(value)})
	}
	return scope.New(entries)
}

func parsePorts(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	ports := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("scan: invalid port %q", p)
		}
		ports = append(ports, n)
	}
	if len(ports) == 0 {
		return nil, errors.New("scan: no ports given")
	}
	return ports, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
