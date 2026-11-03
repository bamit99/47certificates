# 47-Day TLS Certificate Impact Auditor — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `47c`, a single-binary Go service that inventories publicly-trusted TLS certificates for an allowlisted set of domains, classifies them against the CA/B Forum 398/200/100/47-day schedule, and serves a UI to scan, triage, and report.

**Architecture:** One binary with `serve` and `scan` subcommands. A scan pipeline (discover → collect → evaluate → persist) writes to SQLite; a `net/http` UI reads it and queues jobs through a single-flight runner. Reports are immutable rendered artifacts stored beside the database.

**Tech Stack:** Go 1.24, stdlib `crypto/tls`/`crypto/x509`/`html/template`, `modernc.org/sqlite` (pure Go), `golang.org/x/crypto/argon2`, `github.com/robfig/cron/v3`.

**Spec:** `docs/superpowers/specs/2026-11-03-47day-cert-audit-design.md`

## Global Constraints

- Go 1.24, `CGO_ENABLED=0`. Runtime image `scratch`.
- Dependencies limited to `modernc.org/sqlite`, `golang.org/x/crypto`, `github.com/robfig/cron/v3`. No other modules. Tests use the stdlib only.
- All timestamps stored as Unix seconds (INTEGER) in UTC. All schedules in UTC.
- Fingerprints are lowercase hex SHA-256 of the leaf DER, no colons.
- Hostname normalization: lowercase, strip one trailing dot. Non-ASCII scope entries are rejected with an error; no IDNA mapping in v1.
- The scope allowlist is authoritative: never dial a hostname that `scope.Set.Match` rejects.
- `severity` is never stored; derive it at read time. Only `phase` is persisted.
- Only scans ending `done` update `certs.last_seen` / `certs.retired_at`.
- Bind `127.0.0.1:8080` unless `--tls-cert`/`--tls-key` or `--insecure-http` is given.
- Expected scale: <1,000 hostnames; 90 retained scans.
- Mozilla root bundle is vendored at `internal/roots/ca.pem` and embedded.

## Review Focus

Inputs and conditions the spec implies but no single task's happy-path test covers. Each line has its test pinned in the named task.

1. Cert served on a non-443 port whose SNI selects a different vhost than the default — the collected leaf must belong to the hostname dialled, not the default vhost. (Task 8)
2. `notBefore` backdated by the CA so ordered validity differs from `notAfter - notBefore` — classification must use the arithmetic, not the ordered span; a cert exactly on a phase boundary belongs to the later phase. (Tasks 2, 9)
3. Incomplete chain plus a hostile or broken AIA URL (`file://`, redirect, >1 MiB, loopback) — must be refused without fetching, and the chain reported `untrusted/incomplete`, never `private`. (Tasks 7, 8)
4. Scope confusion: `notexample.com` must not match `example.com`; an exclusion beats an include; a wildcard SAN is never dialled. (Tasks 3, 6)
5. CLI scan running while the server scans — no overlap, no partial lifecycle update, no "mass retirement". (Tasks 6, 9, 12)

---

### Task 1: Repository scaffold and CLI shell

**Files:**
- Create: `go.mod`, `.gitignore`, `cmd/47c/main.go`, `internal/config/config.go`, `internal/config/config_test.go`, `README.md`

**Interfaces:**
- Consumes: nothing.
- Produces: `config.Config{DataDir, Listen, TLSCert, TLSKey, InsecureHTTP string; AdminPassword string}` and `config.Load(args []string, getenv func(string) string) (config.Config, error)`; `47c version`, `47c scan`, `47c serve`, `47c user`, `47c backup`, `47c health` dispatch.

- [ ] **Step 1: Initialize the module and repository**

```bash
cd /run/media/amit/2TBNVME/Git/47Certificates
git init
go mod init github.com/amit/47certificates
```

`.gitignore`: `data/`, `*.db`, `*.db-wal`, `*.db-shm`, `47c`.

- [ ] **Step 2: Write the failing config test**

`internal/config/config_test.go`:

```go
func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(nil, func(string) string { return "" })
	if err != nil { t.Fatal(err) }
	if cfg.DataDir != "./data" { t.Fatalf("DataDir = %q", cfg.DataDir) }
	if cfg.Listen != "127.0.0.1:8080" { t.Fatalf("Listen = %q", cfg.Listen) }
}

func TestLoadRejectsNonLoopbackWithoutTLS(t *testing.T) {
	_, err := Load([]string{"--listen", "0.0.0.0:8080"}, func(string) string { return "" })
	if err == nil { t.Fatal("expected error") }
}
```

- [ ] **Step 3: Run it and watch it fail**

Run: `go test ./internal/config/ -run TestLoad -v`
Expected: FAIL, `undefined: Load`.

- [ ] **Step 4: Implement config and the CLI shell**

`config.Load` parses flags (`--data-dir`, `--listen`, `--tls-cert`, `--tls-key`, `--insecure-http`), applies `47C_DATA_DIR` / `47C_LISTEN` / `ADMIN_PASSWORD` from `getenv` only when the flag is absent, and returns an error when `Listen` is not a loopback host and neither TLS nor `--insecure-http` is set. `main.go` switches on `os.Args[1]` and prints `47c version dev` for `version`; other subcommands return `errNotImplemented` until their task lands.

- [ ] **Step 5: Verify and commit**

Run: `go test ./... && go build ./... && ./47c version`
Expected: tests PASS, build clean, `47c version dev`.

```bash
git add -A && git commit -m "chore: scaffold 47c module and CLI shell"
```

---

### Task 2: Phase schedule and boundary classification

**Files:**
- Create: `internal/phase/phase.go`, `internal/phase/phase_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `phase.Rules{Name string; StartsAt time.Time; MaxLifetimeDays int; MaxDVReuseDays int}`, `phase.Schedule []Rules`, `phase.For(t time.Time) Rules`, `phase.LifetimeDays(notBefore, notAfter time.Time) int`.

- [ ] **Step 1: Write the failing table test**

```go
func TestForBoundaries(t *testing.T) {
	cases := []struct{ at time.Time; want string }{
		{time.Date(2026, 3, 14, 23, 59, 59, 0, time.UTC), "P0"},
		{time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), "P1"},
		{time.Date(2027, 3, 15, 0, 0, 0, 0, time.UTC), "P2"},
		{time.Date(2029, 3, 15, 0, 0, 0, 0, time.UTC), "P3"},
	}
	for _, c := range cases {
		if got := For(c.at).Name; got != c.want { t.Errorf("%s: got %s, want %s", c.at, got, c.want) }
	}
}

func TestLifetimeDaysUsesArithmetic(t *testing.T) {
	nb := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	na := nb.Add(397*24*time.Hour + 23*time.Hour)
	if got := LifetimeDays(nb, na); got != 397 { t.Fatalf("got %d", got) }
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `go test ./internal/phase/ -v`
Expected: FAIL, `undefined: For`.

- [ ] **Step 3: Implement the schedule**

`Schedule` holds P0 `0001-01-01 / 398 / 398`, P1 `2026-03-15 / 200 / 200`, P2 `2027-03-15 / 100 / 100`, P3 `2029-03-15 / 47 / 10`. `For` returns the last entry whose `StartsAt <= t`. `LifetimeDays` is `int(notAfter.Sub(notBefore) / (24 * time.Hour))`.

- [ ] **Step 4: Verify**

Run: `go test ./internal/phase/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/phase && git commit -m "feat: add CA/B phase schedule with boundary tests"
```

---

### Task 3: Scope allowlist and matching

**Files:**
- Create: `internal/scope/scope.go`, `internal/scope/scope_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `scope.Kind` (`Include`, `Exclude`, `Seed`), `scope.Entry{Kind Kind; Value string}`, `scope.New([]Entry) (*Set, error)`, `(*Set).Match(host string) bool`, `(*Set).Hosts() []string`, `scope.NormalizeHost(string) (string, error)`.

- [ ] **Step 1: Write the failing tests**

```go
func TestMatchLabelBoundaries(t *testing.T) {
	s, err := New([]Entry{{Kind: Include, Value: "example.com"}})
	if err != nil { t.Fatal(err) }
	if !s.Match("a.example.com") { t.Fatal("subdomain should match") }
	if s.Match("notexample.com") { t.Fatal("partial label must not match") }
	if s.Match("example.com.evil.net") { t.Fatal("suffix trick must not match") }
}

func TestExcludeBeatsInclude(t *testing.T) {
	s, _ := New([]Entry{{Kind: Include, Value: "example.com"}, {Kind: Exclude, Value: "admin.example.com"}})
	if s.Match("admin.example.com") { t.Fatal("exclusion must win") }
	if !s.Match("www.example.com") { t.Fatal("other hosts stay in scope") }
}

func TestSeedMustBeInScope(t *testing.T) {
	if _, err := New([]Entry{{Kind: Include, Value: "example.com"}, {Kind: Seed, Value: "other.net"}}); err == nil {
		t.Fatal("out-of-scope seed must be rejected")
	}
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `go test ./internal/scope/ -v`
Expected: FAIL, `undefined: New`.

- [ ] **Step 3: Implement normalize and match**

`NormalizeHost` lowercases, strips one trailing dot, rejects empty/`*`/non-ASCII with an error. `Match` accepts a host when it equals an include value or ends with `"."+include`; any matching exclusion rejects. `Hosts` returns include values plus seeds, deduplicated and sorted.

- [ ] **Step 4: Verify**

Run: `go test ./internal/scope/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/scope && git commit -m "feat: add scope allowlist with boundary-safe matching"
```

---

### Task 4: Certificate parsing and metadata

**Files:**
- Create: `internal/testutil/testutil.go`, `internal/roots/roots.go`, `internal/roots/ca.pem`, `internal/x509eval/x509eval.go`, `internal/x509eval/parse_test.go`

**Interfaces:**
- Consumes: `phase` (Task 2).
- Produces: `x509eval.Cert{Fingerprint, Subject, Issuer, KeyAlg, SigAlg, ARIURL, OCSPURL, CRLURL string; NotBefore, NotAfter time.Time; LifetimeDays, KeyBits int; SANs []string}`, `x509eval.Parse(leafDER []byte, chainDER [][]byte) (Cert, error)`, `roots.Pool() *x509.CertPool`, `testutil.NewCA(t)`, `testutil.NewLeaf(t, ca, key, LeafOpts) ([]byte, *ecdsa.PrivateKey)`.

- [ ] **Step 1: Vendor the Mozilla bundle**

```bash
mkdir -p internal/roots
curl -fsSL https://curl.se/ca/cacert.pem -o internal/roots/ca.pem
```

- [ ] **Step 2: Write the failing tests**

```go
func TestParseMetadata(t *testing.T) {
	ca, caKey := testutil.NewCA(t)
	nb := time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC)
	der, _ := testutil.NewLeaf(t, ca, caKey, testutil.LeafOpts{
		DNSNames: []string{"a.example.com"}, NotBefore: nb, NotAfter: nb.Add(397 * 24 * time.Hour),
	})
	c, err := Parse(der, nil)
	if err != nil { t.Fatal(err) }
	if c.LifetimeDays != 397 { t.Fatalf("lifetime = %d", c.LifetimeDays) }
	if len(c.Fingerprint) != 64 { t.Fatalf("fingerprint = %q", c.Fingerprint) }
	if c.SANs[0] != "a.example.com" { t.Fatalf("sans = %v", c.SANs) }
}

func TestEmbeddedRootsParse(t *testing.T) {
	p := roots.Pool()
	if p == nil { t.Fatal("nil pool") }
}
```

- [ ] **Step 3: Run and confirm failure**

Run: `go test ./internal/x509eval/ -v`
Expected: FAIL, `undefined: Parse`.

- [ ] **Step 4: Implement parsing and test helpers**

`Parse` decodes the leaf with `x509.ParseCertificate`, computes the SHA-256 fingerprint, copies SANs, key algorithm/bits, signature algorithm, and the first `IssuingCertificateURL` / `OCSP` / CRL value, and calls `phase.LifetimeDays`. `roots.Pool` embeds `ca.pem` via `//go:embed` and appends every `CERTIFICATE` block; panic at init if fewer than 100 roots parse. `testutil` generates ECDSA P-256 CAs and leaves with fixed serials.

- [ ] **Step 5: Verify**

Run: `go test ./internal/x509eval/ ./internal/roots/ -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/roots internal/testutil internal/x509eval && git commit -m "feat: parse certificate metadata against embedded roots"
```

---

### Task 5: Trust classification, findings, and derived severity

**Files:**
- Create: `internal/x509eval/verify.go`, `internal/x509eval/findings.go`, `internal/x509eval/verify_test.go`, `internal/x509eval/findings_test.go`

**Interfaces:**
- Consumes: `Cert` and `Parse` (Task 4); `phase` (Task 2).
- Produces: `x509eval.Verdict{Trust string; ChainValid, HostnameValid bool; Reason string}`, `x509eval.Verify(leafDER, chainDER [][]byte, host string, roots *x509.CertPool, now time.Time) Verdict`, `x509eval.Finding{Type string; Detail map[string]any}`, `x509eval.Findings(c Cert, v Verdict, now time.Time) []Finding`, `x509eval.Severity(f Finding, now time.Time) string`, `x509eval.Bucket([]Finding) string`.

- [ ] **Step 1: Write the failing trust tests**

```go
func TestVerifyPublicChain(t *testing.T) {
	ca, caKey := testutil.NewCA(t)
	der, _ := testutil.NewLeaf(t, ca, caKey, testutil.LeafOpts{DNSNames: []string{"a.example.com"}})
	pool := x509.NewCertPool(); pool.AddCert(ca)
	v := Verify(der, nil, "a.example.com", pool, time.Now())
	if v.Trust != "public" || !v.HostnameValid { t.Fatalf("%+v", v) }
}

func TestVerifyPrivateRootIsPrivateNotUntrusted(t *testing.T) {
	ca, caKey := testutil.NewCA(t) // not added to pool
	der, _ := testutil.NewLeaf(t, ca, caKey, testutil.LeafOpts{DNSNames: []string{"a.example.com"}})
	v := Verify(der, [][]byte{ca.Raw}, "a.example.com", roots.Pool(), time.Now())
	if v.Trust != "private" || v.Reason != "private_root" { t.Fatalf("%+v", v) }
}

func TestVerifyExpiredStillClassifiesTrust(t *testing.T) {
	ca, caKey := testutil.NewCA(t)
	nb := time.Now().Add(-48 * time.Hour)
	der, _ := testutil.NewLeaf(t, ca, caKey, testutil.LeafOpts{DNSNames: []string{"a.example.com"}, NotBefore: nb, NotAfter: nb.Add(24 * time.Hour)})
	pool := x509.NewCertPool(); pool.AddCert(ca)
	if v := Verify(der, nil, "a.example.com", pool, time.Now()); v.Trust != "public" { t.Fatalf("%+v", v) }
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `go test ./internal/x509eval/ -run TestVerify -v`
Expected: FAIL, `undefined: Verify`.

- [ ] **Step 3: Implement Verify**

Build an intermediates pool from `chainDER`. Verify twice: at `now` for `ChainValid`, and at `leaf.NotBefore.Add(time.Minute)` to separate expiry from path failure. Add every served self-signed root to a scratch pool and, if that succeeds while Mozilla does not, set `Trust="private"`, `Reason="private_root"`. If neither builds, `Trust="untrusted"`, `Reason="incomplete"` when no self-signed root was present, else `untrusted_root`. `HostnameValid` comes from `leaf.VerifyHostname(host)`.

- [ ] **Step 4: Write the failing findings tests**

```go
func TestFindingsAreIndependent(t *testing.T) {
	c := Cert{NotBefore: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2025, 5, 1, 0, 0, 0, 0, time.UTC), LifetimeDays: 486}
	got := Findings(c, Verdict{Trust: "public", ChainValid: true}, time.Now())
	types := map[string]bool{}
	for _, f := range got { types[f.Type] = true }
	if !types["grandfathered_too_long"] || !types["exceeds_47_target"] { t.Fatalf("%v", types) }
	if types["violates_current_phase"] { t.Fatal("pre-2026 cert must not violate the current phase") }
}
```

Also assert: a 2026-04-01 cert with 300 days is `violates_current_phase`; `Bucket` of `{exceeds_47_target, grandfathered_too_long}` is `grandfathered`; `Severity` of `expires_soon` at 10 days is `high`, at 25 days `medium`.

- [ ] **Step 5: Implement findings and severity**

`Findings` emits the spec §8 rows (`violates_current_phase`, `grandfathered_too_long`, `exceeds_47_target`, `expires_soon`, `expired_served`, `hostname_mismatch`, `untrusted_chain`, `private_trust`) using union semantics. `Bucket` orders `violation > grandfathered > expiring > target > info`. `Severity` implements the spec §8 table.

- [ ] **Step 6: Verify and commit**

Run: `go test ./internal/x509eval/ -v`
Expected: PASS.

```bash
git add internal/x509eval && git commit -m "feat: classify trust, findings, and derived severity"
```

---

### Task 6: SQLite store, schema, and lifecycle rules

**Files:**
- Create: `internal/store/store.go`, `internal/store/migrations/0001_init.sql`, `internal/store/{scans,endpoints,certs,findings,scope,users,reports,audit}.go`, `internal/store/store_test.go`

**Interfaces:**
- Consumes: `x509eval.Cert`, `x509eval.Verdict`, `x509eval.Finding` (Tasks 4–5).
- Produces: `store.Open(path string) (*Store, error)`, `(*Store).Migrate() error`, `(*Store).Close() error`, `(*Store).BeginScan(ctx, trigger string, userID *int64) (int64, error)`, `(*Store).FinishScan(ctx, scanID int64, status string, stats []byte, scanErr string) error`, `(*Store).UpsertEndpoint(ctx, host string, port int, ip string, scanID int64) (int64, error)`, `(*Store).UpsertCert(ctx, c x509eval.Cert) (int64, error)`, `(*Store).RecordObservation(ctx, scanID, endpointID, certID int64, v x509eval.Verdict, tlsVersion, cipher uint16, caa []string) error`, `(*Store).SyncFindings(ctx, scanID, certID int64, endpointID *int64, fs []x509eval.Finding, now time.Time) error`, `(*Store).RetireUnseen(ctx, scanID int64) error`, `(*Store).AcquireScanLock(ctx) (release func(), err error)`.

- [ ] **Step 1: Write the failing schema test**

```go
func TestMigrateAndOpenTwice(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "t.db")); if err != nil { t.Fatal(err) }
	if err := s.Migrate(); err != nil { t.Fatal(err) }
	if err := s.Migrate(); err != nil { t.Fatalf("second migrate: %v", err) }
	var mode string
	s.db.QueryRow("PRAGMA journal_mode").Scan(&mode)
	if mode != "wal" { t.Fatalf("journal_mode = %s", mode) }
}

func TestOnlyDoneScansRetireCerts(t *testing.T) {
	// insert cert + observation on scan 1 (done); run scan 2 with no observation and status cancelled;
	// assert certs.retired_at IS NULL; then scan 3 done with no observation; assert retired_at IS NOT NULL.
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `go test ./internal/store/ -v`
Expected: FAIL, `undefined: Open`.

- [ ] **Step 3: Implement the store**

Create `0001_init.sql` exactly as spec §7, plus `schema_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER)`. Open with `_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)`, `SetMaxOpenConns(1)`. `AcquireScanLock` runs `BEGIN IMMEDIATE` against a `scan_lock` row and returns a release that commits/rolls back; it returns `ErrScanInProgress` on `SQLITE_BUSY`. `RetireUnseen` sets `retired_at` only when the calling scan has `status='done'`, via a single `UPDATE ... WHERE id NOT IN (SELECT cert_id FROM observations WHERE scan_id=?)`.

- [ ] **Step 4: Verify**

Run: `go test ./internal/store/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store && git commit -m "feat: add sqlite store with schema and done-only lifecycle"
```

---

### Task 7: Discovery — CT logs, DNS, scope filtering

**Files:**
- Create: `internal/discover/discover.go`, `internal/discover/ct.go`, `internal/discover/dns.go`, `internal/discover/discover_test.go`

**Interfaces:**
- Consumes: `scope.Set` (Task 3).
- Produces: `discover.Source interface{ Names(ctx context.Context, domain string) ([]string, error) }`, `discover.NewCRTSource(client *http.Client) Source`, `discover.NewCertSpotterSource(client *http.Client) Source`, `discover.Resolver interface{ LookupHost(ctx, host string) ([]string, error); LookupCNAME(ctx, host string) (string, error) }`, `discover.Run(ctx, set *scope.Set, src Source, res Resolver, opts Options) (Result, error)`, `discover.Result{Hosts []string; IPs map[string][]string; CNAMEs map[string]string; Warnings []string}`.

- [ ] **Step 1: Write the failing tests**

```go
func TestRunFiltersAndExpands(t *testing.T) {
	src := fakeSource{names: []string{"a.example.com", "b.other.net", "*.example.com", "A.EXAMPLE.COM."}}
	set, _ := scope.New([]scope.Entry{{Kind: scope.Include, Value: "example.com"}})
	got, err := Run(context.Background(), set, src, fakeResolver{}, Options{})
	if err != nil { t.Fatal(err) }
	if len(got.Hosts) != 1 || got.Hosts[0] != "a.example.com" { t.Fatalf("%v", got.Hosts) }
}

func TestCRTSourceParsesNames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `[{"name_value":"a.example.com\nb.example.com"},{"name_value":"*.example.com"}]`)
	}))
	defer srv.Close()
	names, err := NewCRTSource(srv.Client(), srv.URL).Names(context.Background(), "example.com")
	// expect a.example.com, b.example.com, *.example.com; no error
}

func TestRunFallsBackWhenCTFails(t *testing.T) {
	// primary returns error; secondary returns one name; assert name present and a warning recorded
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `go test ./internal/discover/ -v`
Expected: FAIL, `undefined: Run`.

- [ ] **Step 3: Implement sources and resolution**

`CRTSource` GETs `{base}?q=%.<domain>&output=json` (base injectable for tests), splits `name_value` on newlines, dedupes. `CertSpotterSource` GETs `{base}/v1/issuances?domain=<d>&include_subdomains=true`. `Run` normalizes every name, filters with `set.Match`, drops wildcards from `Hosts` but records them in `Warnings` as coverage-only, resolves A/AAAA via `net.Resolver` with a 2 s context, and records the CNAME. If the primary source errors, try the fallback and append `"ct: <err>"` to `Warnings`.

- [ ] **Step 4: Verify and commit**

Run: `go test ./internal/discover/ -v`
Expected: PASS.

```bash
git add internal/discover && git commit -m "feat: discover hostnames from CT logs and DNS"
```

---

### Task 8: TLS collection with SNI, per-IP dial, and AIA fetch

**Files:**
- Create: `internal/collect/collect.go`, `internal/collect/aia.go`, `internal/collect/collect_test.go`

**Interfaces:**
- Consumes: `discover.Result` (Task 7).
- Produces: `collect.Endpoint{Host string; Port int; IP string}`, `collect.Observation{Endpoint Endpoint; LeafDER []byte; ChainDER [][]byte; TLSVersion, Cipher uint16; CAA []string; Err error}`, `collect.Probe(ctx context.Context, ep Endpoint, opts Options) Observation`, `collect.Options{Timeout time.Duration; MinVersion uint16; AIA *AIAFetcher}`, `collect.NewAIAFetcher(client *http.Client, maxBytes int64) *AIAFetcher`, `(*AIAFetcher).Fetch(ctx context.Context, urls []string) ([][]byte, error)`.

- [ ] **Step 1: Write the failing SNI test**

```go
func TestProbeUsesSNI(t *testing.T) {
	// Two local TLS servers share one listener: default cert "default.example.com",
	// SNI "a.example.com" selects the other. Dial the IP with Host "a.example.com".
	ep := Endpoint{Host: "a.example.com", Port: port, IP: "127.0.0.1"}
	obs := Probe(context.Background(), ep, Options{Timeout: 2 * time.Second})
	if obs.Err != nil { t.Fatal(obs.Err) }
	c, _ := x509eval.Parse(obs.LeafDER, obs.ChainDER)
	if !slices.Contains(c.SANs, "a.example.com") { t.Fatalf("got cert for %v", c.SANs) }
}

func TestAIAFetcherRefusesUnsafeURLs(t *testing.T) {
	f := NewAIAFetcher(http.DefaultClient, 1<<20)
	for _, u := range []string{"file:///etc/passwd", "http://127.0.0.1:1/x", "https://example.com/redirecting"} {
		if _, err := f.Fetch(context.Background(), []string{u}); err == nil {
			t.Errorf("%s should be refused", u)
		}
	}
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `go test ./internal/collect/ -v`
Expected: FAIL, `undefined: Probe`.

- [ ] **Step 3: Implement Probe and the AIA fetcher**

`Probe` dials `net.JoinHostPort(ep.IP, port)` with the timeout, wraps in `tls.Client` with `ServerName: ep.Host`, `InsecureSkipVerify: true`, `MinVersion` from opts, ALPN `h2,http/1.1`. On success, copy `PeerCertificates`. On handshake error, retry once after 500 ms; record the error. `AIAFetcher.Fetch` accepts at most 3 URLs, allows only `http`/`https`, rejects loopback/link-local/private IP literals and redirects (`CheckRedirect` returns `http.ErrUseLastResponse`), uses a 5 s context and `io.LimitReader(maxBytes+1)`; returns an error if the limit is exceeded.

- [ ] **Step 4: Add the incomplete-chain test**

Assert: a leaf served without its intermediate, whose AIA URL points at a `file://` path, yields `Verdict{Trust:"untrusted", Reason:"incomplete"}` after `Probe` + `Verify` — never `private`.

- [ ] **Step 5: Verify and commit**

Run: `go test ./internal/collect/ -v`
Expected: PASS.

```bash
git add internal/collect && git commit -m "feat: collect certificates with SNI and safe AIA fetch"
```

---

### Task 9: Scan pipeline and `47c scan`

**Files:**
- Create: `internal/scan/scan.go`, `internal/scan/export.go`, `internal/scan/scan_test.go`, `cmd/47c/scan.go`

**Interfaces:**
- Consumes: `discover.Run`, `collect.Probe`, `x509eval.Parse/Verify/Findings`, `store.*` (Tasks 3–8).
- Produces: `scan.Engine{Store *store.Store; Source discover.Source; Resolver discover.Resolver; Roots *x509.CertPool; Now func() time.Time; Concurrency, QPS int; Timeout time.Duration}`, `(*Engine).Run(ctx context.Context, scanID int64, set *scope.Set, ports []int, progress func(Progress)) (Stats, error)`, `scan.Stats{Hosts, Endpoints, Observed, Failed, Public, Private, Untrusted int}`, `scan.ExportCSV(ctx, st *store.Store, scanID int64, w io.Writer) error`, `scan.ExportJSON(ctx, st *store.Store, scanID int64, w io.Writer) error`.

- [ ] **Step 1: Write the failing pipeline test**

```go
func TestRunEndToEnd(t *testing.T) {
	// Local TLS server with testutil cert for "a.example.com".
	set, _ := scope.New([]scope.Entry{{Kind: scope.Include, Value: "example.com"}})
	eng := &Engine{Store: st, Source: fakeSource{"a.example.com"}, Resolver: fakeResolver{"a.example.com": {"127.0.0.1"}}, Roots: poolOf(ca), Now: time.Now, Concurrency: 4, Timeout: time.Second}
	id, _ := st.BeginScan(ctx, "cli", nil)
	stats, err := eng.Run(ctx, id, set, []int{port}, nil)
	if err != nil { t.Fatal(err) }
	if stats.Observed != 1 || stats.Public != 1 { t.Fatalf("%+v", stats) }
}

func TestCancelledScanDoesNotRetire(t *testing.T) {
	// Scan 1 done with cert A. Scan 2 cancelled with no observation. Assert A.retired_at IS NULL
	// and FinishScan status is "cancelled".
}

func TestCLIRefusesWhenLockHeld(t *testing.T) {
	release, _ := st.AcquireScanLock(ctx); defer release()
	if err := runScanCLI(ctx, st, set, nil); !errors.Is(err, store.ErrScanInProgress) { t.Fatalf("%v", err) }
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `go test ./internal/scan/ -v`
Expected: FAIL, `undefined: Engine`.

- [ ] **Step 3: Implement the pipeline**

`Run` writes `status='running'`, acquires the store scan lock, runs discovery, expands hosts × ports × IPs, probes with a 32-worker pool and a ticker-based QPS limiter, parses and verifies each observation, upserts certs/endpoints, records observations, and calls `SyncFindings`. AIA fetch runs when `ChainDER` lacks an intermediate. On success it calls `FinishScan("done")` then `RetireUnseen`; on `ctx.Err()` it calls `FinishScan("cancelled")` and skips retirement; on error, `failed`. Progress callbacks fire every 100 endpoints and on phase changes.

- [ ] **Step 4: Wire `47c scan` and verify**

`cmd/47c/scan.go` loads scope entries from `--scope` (one `kind:value` per line), opens the store, migrates, takes the lock (`--wait` supported), and writes `--out` CSV/JSON plus a one-line summary. Run: `go test ./internal/scan/ -v && go build ./...`.
Expected: PASS and clean build.

- [ ] **Step 5: Commit**

```bash
git add internal/scan cmd/47c && git commit -m "feat: add scan pipeline, lifecycle, and CLI export"
```

---

### Task 10: Web server, users, sessions, CSRF

**Files:**
- Create: `internal/web/server.go`, `internal/web/auth.go`, `internal/web/auth_test.go`, `internal/auth/password.go`, `internal/auth/password_test.go`, `cmd/47c/user.go`

**Interfaces:**
- Consumes: `store` (Task 6), `jobs` (Task 12, stubbed here).
- Produces: `web.Deps{Store *store.Store; Jobs JobTrigger; Now func() time.Time}`, `web.New(Deps) http.Handler`, `auth.HashPassword(pw string) (string, error)`, `auth.CheckPassword(hash, pw string) bool`, `47c user add --username --password`, `(*store.Store).CreateUser(ctx, username, hash string) error`, `(*store.Store).UserByUsername(ctx, username string) (store.User, error)`.

- [ ] **Step 1: Write the failing auth tests**

```go
func TestHashAndCheck(t *testing.T) {
	h, err := HashPassword("correct horse")
	if err != nil { t.Fatal(err) }
	if !CheckPassword(h, "correct horse") { t.Fatal("should match") }
	if CheckPassword(h, "wrong") { t.Fatal("must not match") }
	if !strings.HasPrefix(h, "$argon2id$") { t.Fatalf("hash = %q", h) }
}

func TestMutatingRouteRequiresSessionAndCSRF(t *testing.T) {
	srv := httptest.NewServer(New(Deps{Store: st, Now: time.Now}))
	defer srv.Close()
	resp, _ := http.Post(srv.URL+"/scope", "application/x-www-form-urlencoded", strings.NewReader("value=x"))
	if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `go test ./internal/web/ ./internal/auth/ -v`
Expected: FAIL, `undefined: New`.

- [ ] **Step 3: Implement auth and the server shell**

`HashPassword` emits `$argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>` (base64 raw std). `CheckPassword` parses parameters from the hash, so future cost changes stay verifiable. Sessions are random 32-byte IDs stored in `sessions`, cookie `HttpOnly; SameSite=Lax; Secure` when TLS. `web.New` builds a `http.ServeMux`, applies a session middleware that redirects unauthenticated requests to `/login`, and a CSRF middleware that requires `X-CSRF-Token` or `csrf` form field matching the session token on every non-GET. Login rate limit: in-memory token bucket, 5 attempts/min per remote IP.

- [ ] **Step 4: Verify, wire `47c user add`, commit**

Run: `go test ./internal/web/ ./internal/auth/ -v && ./47c user add --username admin --password test`
Expected: PASS; user row created; running `add` twice returns a clear "user exists" error.

```bash
git add internal/web internal/auth cmd/47c && git commit -m "feat: add multi-user auth, sessions, and CSRF"
```

---

### Task 11: Read-only UI — dashboard, certs, domains, scans

**Files:**
- Create: `internal/web/handlers_read.go`, `internal/web/templates/{layout,dashboard,certs,cert,domains,domain,scans,scan,login}.html`, `internal/web/static/app.css`, `internal/web/read_test.go`

**Interfaces:**
- Consumes: `web.New`, `store` (Tasks 6, 10).
- Produces: routes `GET /`, `/certs`, `/certs/{fp}`, `/domains`, `/domains/{d}`, `/scans`, `/scans/{id}`, `/api/certs`, `/api/scans`; template funcs `sev`, `bucket`, `days`, `when`.

- [ ] **Step 1: Write the failing view tests**

```go
func TestCertsListFiltersByBucket(t *testing.T) {
	// seed one grandfathered cert and one compliant cert; GET /certs?bucket=grandfathered;
	// assert only the first fingerprint appears in the body.
}

func TestCertDetailShowsEndpointAndWhy(t *testing.T) {
	// seed cert served on two endpoints; GET /certs/{fp};
	// assert both hostnames and the finding sentence ("lifetime 397d exceeds 200d allowed for certificates issued after 2026-03-15") appear.
}

func TestDashboardCountsBucketsNotRows(t *testing.T) {
	// cert with both exceeds_47_target and grandfathered_too_long; assert the "grandfathered" count is 1
	// and "info" count is 0.
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `go test ./internal/web/ -run 'TestCerts|TestCertDetail|TestDashboard' -v`
Expected: FAIL, `404` or missing template.

- [ ] **Step 3: Implement handlers and templates**

Server-side pagination (`?page=`, 100 rows). `/certs` joins certs with their latest observation, computes findings and bucket in Go, filters in Go after SQL, and sorts by severity then lifetime. `/certs/{fp}` loads endpoints via `observations`, renders the chain as PEM download (`/certs/{fp}/pem`). `/scans/{id}` returns an SSE stream (`text/event-stream`) reading `scans.stats_json` every second until terminal status. All templates are `embed`ded; `app.css` is the only static asset, inline-referenced as `/static/app.css`.

- [ ] **Step 4: Verify and commit**

Run: `go test ./internal/web/ -v`
Expected: PASS.

```bash
git add internal/web && git commit -m "feat: add read-only dashboard, cert, domain, and scan views"
```

---

### Task 12: Scope editor, settings, audit log, and job wiring

**Files:**
- Create: `internal/jobs/jobs.go`, `internal/jobs/jobs_test.go`, `internal/web/handlers_mutate.go`, `internal/web/templates/{scope,settings,audit}.html`, `internal/web/mutate_test.go`

**Interfaces:**
- Consumes: `scan.Engine` (Task 9), `store` (Task 6), `web.New` (Task 10).
- Produces: `jobs.Runner`, `jobs.New(st *store.Store, eng *scan.Engine, now func() time.Time) *Runner`, `(*Runner).TriggerScan(ctx, trigger string, userID *int64) (int64, error)`, `(*Runner).Cancel(scanID int64) error`, `(*Runner).Subscribe(scanID int64) (<-chan scan.Progress, func())`, `(*store.Store).ReplaceScope(ctx, entries []scope.Entry, userID int64) error`, `(*store.Store).Audit(ctx, userID int64, action, target string, detail []byte, ip string) error`.

- [ ] **Step 1: Write the failing tests**

```go
func TestTriggerIsSingleFlight(t *testing.T) {
	r := New(st, eng, time.Now)
	first, _ := r.TriggerScan(ctx, "manual", nil)
	if _, err := r.TriggerScan(ctx, "manual", nil); !errors.Is(err, jobs.ErrBusy) {
		t.Fatalf("second trigger err = %v", err)
	}
	r.Cancel(first)
}

func TestScopeRejectsOutOfScopeSeed(t *testing.T) {
	// POST /scope with include example.com and seed other.net -> 400, body contains "seed must be inside an include"
}

func TestEveryMutationIsAudited(t *testing.T) {
	// perform scope edit + settings edit + ack; assert 3 audit_log rows with the acting user id
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `go test ./internal/jobs/ ./internal/web/ -run 'TestTrigger|TestScopeRejects|TestEveryMutation' -v`
Expected: FAIL, `undefined: New`.

- [ ] **Step 3: Implement the runner and handlers**

`Runner` keeps an in-memory `current int64` guarded by a mutex and re-checks `store.AcquireScanLock` before starting, so a CLI-held lock also returns `ErrBusy`. `TriggerScan` inserts the scan row, marks it queued, and launches a goroutine that calls `eng.Run`. `Cancel` cancels the stored `context.CancelFunc`. Scope POST validates via `scope.New` and writes all entries in one transaction. Settings POST accepts only known keys (`ports`, `concurrency`, `qps`, `timeout`, `schedule`, `retention`, `report.schedule`, `report.webhook_url`), validating each. Every POST handler calls `store.Audit` before returning.

- [ ] **Step 4: Verify and commit**

Run: `go test ./internal/jobs/ ./internal/web/ -v`
Expected: PASS.

```bash
git add internal/jobs internal/web && git commit -m "feat: add scope editor, settings, audit log, and single-flight jobs"
```

---

### Task 13: Acknowledgement, snooze, and finding triage

**Files:**
- Create: `internal/web/handlers_findings.go`, `internal/web/findings_test.go`
- Modify: `internal/web/templates/cert.html`, `internal/web/templates/certs.html`

**Interfaces:**
- Consumes: `store.RecordObservation`, `findings` table (Task 6).
- Produces: `(*store.Store).AckFinding(ctx, findingID, userID int64, note string) error`, `(*store.Store).SnoozeFinding(ctx, findingID, userID int64, until time.Time, note string) error`, routes `POST /findings/{id}/ack`, `POST /findings/{id}/snooze`, `POST /findings/{id}/reopen`.

- [ ] **Step 1: Write the failing tests**

```go
func TestAckHidesFromDefaultListButKeepsRow(t *testing.T) {
	// ack finding; GET /certs -> cert absent from "open" filter; GET /certs?status=acked -> present;
	// finding row still has status=ack with ack_by set.
}

func TestSnoozeExpires(t *testing.T) {
	// snooze until now+1h; at now+2h the finding is returned to "open" by the read-time query,
	// without any write.
}

func TestNewCertIsNotAcked(t *testing.T) {
	// ack cert fingerprint A; insert fingerprint B with the same finding type; assert B is open.
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `go test ./internal/web/ -run 'TestAck|TestSnooze|TestNewCert' -v`
Expected: FAIL.

- [ ] **Step 3: Implement triage**

`ack` sets `status='ack'`, `ack_by`, `ack_at`, `note`. `snooze` sets `status='snoozed'`, `snooze_until`. Reads treat a finding as open when `status='open'` or (`status='snoozed'` and `snooze_until <= now`); nothing is written on expiry. `reopen` sets `status='open'` and clears ack fields. All three are audited.

- [ ] **Step 4: Verify and commit**

Run: `go test ./internal/web/ -v`
Expected: PASS.

```bash
git add internal/web && git commit -m "feat: add finding acknowledgement, snooze, and reopen"
```

---

### Task 14: Reports — generation, rendering, and download

**Files:**
- Create: `internal/report/report.go`, `internal/report/csv.go`, `internal/report/json.go`, `internal/report/templates/{executive,worklist,inventory,domain}.html`, `internal/report/report_test.go`, `internal/web/handlers_reports.go`, `internal/web/templates/reports.html`

**Interfaces:**
- Consumes: `store` (Task 6), `x509eval` (Task 5).
- Produces: `report.Kind` (`executive`, `worklist`, `inventory`, `domain`), `report.Artifacts{HTML, CSV, JSON []byte}`, `report.Generate(ctx context.Context, st *store.Store, scanID int64, kind report.Kind, domain string, now time.Time) (Artifacts, error)`, `(*store.Store).CreateReport(ctx, scanID int64, kind string, userID *int64) (int64, error)`, `(*store.Store).SaveReport(ctx, id int64, a report.Artifacts) error`, routes `GET /reports`, `GET /reports/{id}`, `POST /reports`, `GET /reports/{id}/download?format=`.

- [ ] **Step 1: Write the failing tests**

```go
func TestWorklistExcludes47DayCerts(t *testing.T) {
	// one cert 47d, one 48d; worklist HTML contains the 48d fingerprint only.
}

func TestReportRefusesNonDoneScan(t *testing.T) {
	// scan status cancelled; Generate returns report.ErrScanNotDone.
}

func TestReportEmbedsProvenance(t *testing.T) {
	// HTML contains scan id, scope string, tool version, and the "publicly-trusted certificates only" sentence.
}

func TestDeltaAgainstPreviousReport(t *testing.T) {
	// two reports for successive scans; second HTML says "1 new certificate, 1 retired".
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `go test ./internal/report/ -v`
Expected: FAIL, `undefined: Generate`.

- [ ] **Step 3: Implement generation**

`Generate` loads the scan (rejecting any status other than `done` with `ErrScanNotDone`), loads certs observed by that scan, filters `trust='public'` for counts while keeping private observations in an appendix, computes findings via `x509eval.Findings`, renders the kind-specific template with `html/template`, builds CSV rows (`cert` sheet and `endpoint` sheet) and a JSON object with `"schema_version": 1`. The delta block compares against the most recent earlier report of the same kind and lists new/retired/lifetime-changed certs. Every format embeds `report_id`, `generated_at`, `scan_id`, `scope`, `version`.

- [ ] **Step 4: Implement routes and storage**

`POST /reports` inserts the row, generates synchronously (these are fast at <1,000 certs), writes three files under `<DataDir>/reports/<id>/`, records `sha256` of each, and redirects to `GET /reports/{id}`. Download serves `html`, `csv`, `json`, or `zip` (`archive/zip`, stored not deflated for reproducibility). Delete removes the row and directory.

- [ ] **Step 5: Verify and commit**

Run: `go test ./internal/report/ ./internal/web/ -v`
Expected: PASS.

```bash
git add internal/report internal/web && git commit -m "feat: add immutable report generation and download"
```

---

### Task 15: Scheduler, scheduled reports, webhook delivery, retention

**Files:**
- Create: `internal/schedule/schedule.go`, `internal/schedule/schedule_test.go`, `internal/notify/webhook.go`, `internal/notify/webhook_test.go`
- Modify: `cmd/47c/serve.go`, `internal/store/store.go`

**Interfaces:**
- Consumes: `jobs.Runner` (Task 12), `report.Generate` (Task 14).
- Produces: `schedule.New(spec string, loc *time.Location) (*cron.Cron, error)`, `notify.Webhook{URL, Secret string; Client *http.Client}`, `(*notify.Webhook).Send(ctx, reportID int64, body []byte) error`, `(*store.Store).PruneObservations(ctx, keep int) error`, `(*store.Store).LatestDoneScan(ctx) (int64, error)`.

- [ ] **Step 1: Write the failing tests**

```go
func TestWebhookSignsBody(t *testing.T) {
	var gotSig, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-47C-Signature")
		b, _ := io.ReadAll(r.Body); gotBody = string(b)
	}))
	defer srv.Close()
	wh := Webhook{URL: srv.URL, Secret: "s3cret", Client: srv.Client()}
	if err := wh.Send(context.Background(), 7, []byte(`{"report":7}`)); err != nil { t.Fatal(err) }
	if !hmac.Equal([]byte(gotSig), []byte("sha256="+hexHMAC("s3cret", gotBody))) { t.Fatalf("sig %q", gotSig) }
}

func TestPruneKeepsNewestScans(t *testing.T) {
	// 5 scans, keep=2; assert observations for the 3 oldest are gone, certs/findings remain.
}

func TestScheduledReportUsesLatestDoneScan(t *testing.T) {
	// latest scan is cancelled; scheduler picks the newest done one and records a warning.
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `go test ./internal/schedule/ ./internal/notify/ -v`
Expected: FAIL.

- [ ] **Step 3: Implement scheduling and delivery**

`serve` starts two cron entries from settings: `schedule` (default `17 3 * * *`) triggering a scan, and `report.schedule` (default `7 4 1 * *`) generating `executive` + `worklist` from `LatestDoneScan` and delivering via the webhook when configured. Jitter is `rand.Intn(20)-10` minutes applied per run. Delivery records into `report_deliveries`, retries 3 times with 1/2/4 s backoff, and never blocks the scheduler. Retention runs after each successful scan.

- [ ] **Step 4: Verify and commit**

Run: `go test ./internal/schedule/ ./internal/notify/ ./internal/store/ -v`
Expected: PASS.

```bash
git add internal/schedule internal/notify internal/store cmd/47c && git commit -m "feat: add scheduler, scheduled reports, webhook delivery, retention"
```

---

### Task 16: Container, compose, health, backup, documentation

**Files:**
- Create: `Dockerfile`, `docker-compose.yml`, `cmd/47c/health.go`, `cmd/47c/backup.go`, `docs/operations.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: everything.
- Produces: `47c health` (exit 0 when DB opens and schema version matches), `47c backup --out path` (runs `VACUUM INTO`).

- [ ] **Step 1: Write the failing health test**

```go
func TestHealthFailsOnMissingDB(t *testing.T) {
	if err := healthCheck(filepath.Join(t.TempDir(), "absent.db")); err == nil { t.Fatal("expected error") }
}
```

- [ ] **Step 2: Implement health and backup**

`healthCheck` opens the DB read-only, reads `schema_migrations`, and compares against the embedded latest version. `backup` refuses to overwrite and runs `VACUUM INTO ?`.

- [ ] **Step 3: Write the Dockerfile**

Multi-stage: `golang:1.24-alpine` builder with `CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /47c ./cmd/47c`; runtime `scratch` with the binary, `/data` as a declared volume, `USER 65532:65532`, `HEALTHCHECK CMD ["/47c","health"]`, `ENTRYPOINT ["/47c"]`, `CMD ["serve"]`.

- [ ] **Step 4: Build and smoke-test the image**

```bash
docker build -t 47c:dev .
docker run --rm -v "$PWD/data:/data" -e ADMIN_PASSWORD=test -p 127.0.0.1:8080:8080 47c:dev serve
```
Expected: container healthy, `curl -sf http://127.0.0.1:8080/healthz` returns `ok`, login works with `admin`/`test`.

- [ ] **Step 5: Write compose and operations doc**

`docker-compose.yml`: `restart: unless-stopped`, `127.0.0.1:8080:8080`, `./data:/data`, `read_only: true`, `tmpfs: /tmp`, `ADMIN_PASSWORD` commented as first-boot only. `docs/operations.md`: first boot, adding users, backup/restore, phase-boundary behaviour (severity changes without a rescan), webhook payload shape, log locations.

- [ ] **Step 6: Verify and commit**

Run: `go test ./... && go vet ./... && docker build -t 47c:dev .`
Expected: all PASS, vet clean, image builds.

```bash
git add -A && git commit -m "chore: add container, compose, health, backup, and ops docs"
```

---

## Self-Review Notes

- Spec coverage: §1–§4 constraints in Global Constraints; §6 package map mirrored by tasks 2–15; §7 schema in Task 6; §8 rules in Task 5; §9 in Tasks 7–9; §10 in Tasks 10–13; §11 in Task 14–15; §12 in Task 16; §13 in Tasks 8, 10, 12; §14 tests distributed per task; §15 phases map to Tasks 1–9, 10–11, 12–13, 14–16; §18 excluded by definition.
- Types: `store.Store` methods used by `scan`, `jobs`, `report`, and `web` are all declared in Task 6 or the task that adds them.
- Review Focus items each have a named test: 1 → Task 8 SNI test; 2 → Task 2 boundaries and Task 5 grandfathering; 3 → Task 8 unsafe-AIA and incomplete-chain tests; 4 → Task 3 and Task 7 filtering; 5 → Task 6 done-only retirement, Task 9 cancelled-scan test, Task 12 lock test.
