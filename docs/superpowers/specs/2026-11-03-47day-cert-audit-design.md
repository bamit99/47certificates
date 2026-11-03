# Design: 47-Day TLS Certificate Impact Auditor (`47c`)

Date: 2026-11-03
Status: draft, awaiting approval
Author: design session

## 1. Intent

Build a self-hosted, recurring inventory of **publicly-trusted** TLS certificates
served by an allowlisted set of domains, and classify each one against the
CA/Browser Forum lifetime schedule:

| Phase | Effective | Max cert lifetime | Max DV/IP validation reuse |
|---|---|---|---|
| P0 | until 2026-03-15 | 398 days | 398 days |
| P1 | 2026-03-15 | 200 days | 200 days |
| P2 | 2027-03-15 | 100 days | 100 days |
| P3 | 2029-03-15 | 47 days | 10 days |

SII (OV/EV organisation data) reuse drops 825 → 398 days on 2026-03-15.

The point is not to prove the rule exists. It is to answer, for a specific
estate, three questions:

1. Which certificates are served today, and where?
2. Which ones have a lifetime that the current or next phase forbids?
3. Which ones have no automation signal at all, and will therefore break at the
   next renewal cliff?

Because the 2029 reuse window is 10 days, and the 2027 lifetime is 100 days,
manual renewal stops being viable well before 2027. The report is a migration
worklist, not a compliance certificate.

## 2. Goals

- Discover publicly-trusted TLS certs for a domain allowlist (CT logs + DNS +
  active TLS handshake).
- Deduplicate by leaf fingerprint; one cert serving 50 names is one renewal.
- Classify each cert against P1/P2/P3 thresholds, using issuance date, not
  "today".
- Track history: new certs, retired certs, changed lifetimes, per-scan diff.
- Explain *why* a cert is flagged, in one sentence, per finding.
- Let an authenticated user trigger scans, edit scope, acknowledge and snooze
  findings, from a browser.
- Run unattended on a home PC in a single container with persistent state.

## 3. Non-goals

- **Private CA / internal PKI compliance.** CABF Baseline Requirements bind
  publicly-trusted certs only. Private roots are not enforced by browsers. v1
  does not audit them. Certs that *are* observed but do not chain to a public
  root are recorded as `trust=private` and shown as informational, never as a
  violation.
- **Validation-reuse audit.** The tool cannot see how long a CA has held your
  domain validation data. It can only infer risk from cert lifetime, issuer, and
  ARI support. No finding claims otherwise.
- **STARTTLS protocols** (SMTP/IMAP/POP3/LDAP). v1 speaks direct TLS only.
- **Brute-force subdomain enumeration.** CT + DNS + explicit seeds; no wordlists.
- **Vulnerability scanning.** No cipher grading, no protocol downgrade tests,
  no HSTS/preload analysis. `testssl.sh` exists for that.
- **RBAC.** Every authenticated user has full permission.
- **Multi-tenant, HA, clustering.**

## 4. Constraints

- Go, single binary, `scratch` runtime image. Static link.
- No Node, no build step for the UI. Server-rendered HTML + small vanilla JS.
- Mozilla CA bundle embedded in the binary (a `scratch` image has no
  `/etc/ssl/certs`), so trust decisions are identical across hosts.
- SQLite as the only datastore, WAL mode, single writer.
- Home PC: outbound to configured ports only; UI published to loopback.
- The scope allowlist is authoritative. A hostname outside it is never dialed,
  even if CT returns it.

### Expected scale

Fewer than 1,000 hostnames across a handful of apex domains. Consequences, all
of which the defaults already satisfy:

- A full scan at 32 workers / 100 QPS finishes in single-digit minutes; the
  nightly window is not a constraint.
- 90 retained scans × 1,000 observations ≈ 90k rows. Trivial for SQLite.
- crt.sh returns one to a few pages per apex; the 6-hour cache keeps repeated
  queries off the API.
- Severity filtering in Go (§8) is fine at these row counts.

If scope later grows past ~10k names, revisit CT caching and observation
retention before tuning concurrency.

## 5. Approaches considered

Scanner core:

- **A. Orchestrate ProjectDiscovery** (`subfinder`/`dnsx`/`tlsx`) behind a
  Python wrapper. Fast to reach a working scan; but 500 MB–1 GB image, four
  upstream binaries, JSON schema drift, and timeout/retry semantics we do not
  control. Rejected.
- **B. Single Go binary, stdlib TLS.** Chosen. Small, deterministic, total
  control of SNI/ALPN/timeouts, no external tool supply chain.
- **C. Python + `sslyze`.** Richest x509 API, slowest to package, ~300 MB image,
  heavier than needed for "grab a chain". Rejected.

UI:

- **A. Built-in server-rendered UI in the same binary.** Chosen, extended from
  read-only to full mutation at the user's request.
- **B. Static HTML report per run.** No interaction, no history. Rejected.
- **C. Separate SPA + JSON API.** Node toolchain and two artefacts for a
  single-operator home tool. Rejected.

## 6. Architecture

One binary, three subcommands:

```
47c serve      # web UI + scheduler + job runner (long-running)
47c scan       # one-off scan against current scope, same engine, same DB
47c user add   # create a user (also bootstraps the first admin)
47c backup     # VACUUM INTO /data/backup-<ts>.db
```

Packages:

| Package | Responsibility |
|---|---|
| `internal/scope` | allowlist parse/validate, suffix matching, exclusions, seeds, port list |
| `internal/discover` | CT queries, DNS resolution, hostname → endpoint expansion |
| `internal/collect` | TLS dialer: SNI, ALPN, per-IP dial, timeouts, chain capture |
| `internal/x509eval` | parse, trust path build, hostname verify, lifetime calc, phase classification, ARI/OCSP/CRL extraction |
| `internal/store` | SQLite schema, migrations, repositories, retention |
| `internal/jobs` | single-flight queue, progress events, cancellation |
| `internal/web` | handlers, embedded templates/static, SSE, auth, CSRF |
| `internal/report` | CSV/JSON export, per-scan diff |

Dependencies, deliberately few:

- `modernc.org/sqlite` — pure Go, no cgo, works in `scratch`.
- `golang.org/x/crypto/argon2` — password hashing.
- `github.com/robfig/cron/v3` — schedule parsing.
- `time/tzdata` — embedded zoneinfo for UTC-bound schedules.

## 7. Data model

```sql
users(id, username UNIQUE, password_hash, created_at, disabled)
sessions(id, user_id, created_at, expires_at, last_seen, ip, user_agent)
scope_entries(id, kind, value, note, created_by, created_at)
  -- kind: include | exclude | seed
settings(key, value)

scans(id, started_at, finished_at, status, trigger, triggered_by, stats_json, error)
  -- status: queued | running | done | failed | cancelled
  -- trigger: manual | schedule | cli

endpoints(id, hostname, port, ip, first_seen_scan, last_seen_scan)
  UNIQUE(hostname, port, ip)

certs(id, fingerprint_sha256 UNIQUE, subject, issuer_dn,
      not_before, not_after, lifetime_days, key_alg, key_bits, sig_alg,
      san_json, chain_json, ari_url, ocsp_url, crl_url,
      first_seen, last_seen, retired_at)
  -- retired_at set by the first `done` scan that no longer observes the cert

observations(scan_id, endpoint_id, cert_id,
             trust, chain_valid, hostname_valid, expired,
             tls_version, cipher, caa_json, error)
  -- trust: public | private | untrusted | unknown

findings(id, cert_id, endpoint_id NULL, type, phase,
         detail_json, first_seen, last_seen,
         status, ack_by, ack_at, snooze_until, note)
  UNIQUE(cert_id, endpoint_id, type)

audit_log(id, user_id, action, target, detail_json, at, ip)

reports(id, scan_id, kind, status, params_json,
        html_path, csv_path, json_path, size_bytes, sha256,
        created_by, created_at, finished_at, error)
  -- kind: executive | worklist | inventory | domain
  -- status: queued | running | done | failed

report_deliveries(id, report_id, kind, target, status,
                  attempts, last_error, created_at)
  -- kind: webhook
```

`findings.endpoint_id` is nullable so cert-level findings (lifetime) and
endpoint-level findings (hostname mismatch) share one table.

Acknowledging a finding does not persist across a new certificate: the key
includes `cert_id`, and a new cert is a new row. That is the intended behaviour.

## 8. Impact classification

Let `phase(d)` map a date to its max lifetime (398/200/100/47).

- `lifetime_days = floor((not_after - not_before) / 24h)`
- `max_at_issue = phase(not_before)`
- `max_today = phase(now)`

Findings:

| Type | Rule | Meaning |
|---|---|---|
| `violates_current_phase` | `lifetime_days > max_at_issue` | issued under the current rule but too long; should not exist |
| `grandfathered_too_long` | `lifetime_days > max_today` and `not_before` predates the phase | legal when issued, but a renewal today must be shorter |
| `exceeds_47_target` | `lifetime_days > 47` | forward-looking worklist for P3 |
| `expires_soon` | `not_after - now <= 30d` | renewal lag risk |
| `expired_served` | `not_after < now` but the endpoint still serves it | outage or stale deploy |
| `hostname_mismatch` | leaf does not cover the hostname dialled | serving error |
| `untrusted_chain` | chain does not build to an embedded public root | misconfiguration; `detail_json.reason` is `incomplete` or `untrusted_root` |
| `private_trust` | builds only to a known non-public root | informational, not a violation |

Findings are **independent rows**, not exclusive buckets — a 500-day 2024 cert
can be both `grandfathered_too_long` and `exceeds_47_target`. The UI derives one
**impact bucket** per cert = the highest-severity finding present
(`violation > grandfathered > expiring > target > info`); the dashboard counts
buckets, never raw rows, so the permanently-true `exceeds_47_target` row does not
inflate anything.

`exceeds_47_target` is severity `info` and is excluded from default counts.

`severity` is **not stored**; it is derived at read time from finding type, cert
dates, and the current phase. Only `phase` (the phase in force at scan time) is
persisted, for historical context. Sorting and filtering on severity happen in
Go after the SQL query; at the expected row counts this is not a bottleneck, and
it avoids a recompute migration every phase boundary.

Dropped from v1: `no_ari`. Real ARI support is advertised through the CA's ACME
directory (`renewalInfo`), which this tool does not query. `ari_url` is displayed
when the cert carries it; absence is not a finding.

Derived severity:

| Severity | Findings |
|---|---|
| critical | `violates_current_phase`, `expired_served` |
| high | `grandfathered_too_long`, `untrusted_chain`, `expires_soon` when ≤14d |
| medium | `expires_soon` when ≤30d, `hostname_mismatch` |
| info | `exceeds_47_target`, `private_trust` |

As of 2026-11 `max_today = 200`, so a 398-day cert issued in 2024 is
`grandfathered_too_long` (high), not `violates_current_phase`.

Boundary rule: a cert is judged by its own `not_before`, inclusive of the phase
start date. `2026-03-15T00:00:00Z` belongs to P1.

Deliberately **not** a finding: "validation reuse will expire". Not observable.

## 9. Discovery and collection

**Discovery**

1. Seed from `include` entries (apex) plus explicit `seed` entries. A `seed`
   widens *discovery* only: it must still match an `include` suffix, otherwise
   the UI rejects it on save. Seeds never grant dial permission.
2. CT: query `crt.sh` (`?q=%.<domain>&output=json`), paginate, extract SANs.
   Fallback to Cert Spotter `/v1/issuances` when crt.sh fails or rate-limits.
   Cache the last successful query time per domain in `settings`; skip re-query
   within 6 hours.
3. Filter every discovered name through `scope.Match` (suffix match on label
   boundaries, plus exclusions). Never dial a name that fails. Wildcard SANs
   (`*.example.com`) are coverage metadata, never endpoints — they are not
   dialled and never resolve.
4. Resolve A/AAAA/CNAME with a 2 s timeout; record the CNAME chain for display.
5. Expand to endpoints over the configured port list (default `443, 8443, 9443`).
6. Look up CAA per hostname (informational, stored on the observation).

**Collection**

- Dial each resolved IP directly, `ServerName` = hostname (SNI), ALPN
  `h2,http/1.1`, min TLS 1.2, 5 s connect / 10 s handshake budget,
  `InsecureSkipVerify=true` because verification is ours.
- Capture the raw chain, parse with `crypto/x509`.
- **AIA intermediates are fetched** when the served chain is incomplete: up to 3
  `caIssuers` URLs taken from the parsed certs, `http`/`https` only, no
  redirects, 5 s timeout, 1 MiB cap, cached by URL. CRL and OCSP endpoints are
  recorded but **not** fetched in v1. This is the only outbound request whose
  target comes from remote data; the URL policy above is the whole of it.
- Verify against the embedded Mozilla roots; classify `trust`.
- If the chain still does not build, `trust=untrusted` with
  `detail_json.reason=incomplete` — distinct from `untrusted_root`.
- No redirect following in v1 — every discovered hostname is scanned on its own.
- Default 32 workers, global QPS cap configurable (default 100), one retry on
  timeout, none on TLS alert.

## 10. Web UI

Server-rendered, one template set, no client framework.

| Route | Purpose |
|---|---|
| `GET /login`, `POST /login`, `POST /logout` | session auth |
| `GET /` | dashboard: severity counts, phase buckets, next expiries, last scan |
| `GET /certs` | filter by impact bucket, issuer, trust, expiring-in, ack status, domain |
| `GET /certs/{fp}` | cert detail: metadata, SANs, chain, endpoints, findings, ack/snooze, PEM download |
| `GET /domains`, `GET /domains/{d}` | per-domain rollup |
| `GET /scans`, `GET /scans/{id}` | history, live progress via SSE, cancel |
| `GET /reports`, `GET /reports/{id}` | generated report list and inline HTML view |
| `POST /reports`, `POST /reports/{id}/delete` | generate a report, remove one |
| `GET /reports/{id}/download?format=html\|csv\|json\|zip` | download an artifact |
| `GET/POST /scope` | add/remove include, exclude, seed; inline validation |
| `GET/POST /settings` | cron schedule, ports, concurrency, timeouts, retention |
| `GET /audit` | audit log |
| `GET /api/*` | JSON mirrors, read-only |
| `GET /export?format=csv\|json` | offline copy |
| `GET /healthz` | liveness: DB open, version, schema version |

**Auth.** Multi-user, one permission level (ALL). No self-registration. First
user bootstrapped by `47c user add` or `ADMIN_PASSWORD` on first start. Argon2id
(m=64 MiB, t=3, p=2), per-user salt. Sessions: `HttpOnly`, `SameSite=Lax`,
`Secure` when TLS is on, 7-day idle / 30-day absolute. Login rate limit 5/min/IP.
CSRF double-submit token on every mutating request.

**Exposure.** Binds `127.0.0.1:8080` by default. Binding to a non-loopback
address requires `--tls-cert/--tls-key`, or an explicit `--insecure-http`
acknowledgement. Inside the container it listens on `0.0.0.0`; the compose file
publishes `127.0.0.1:8080:8080`.

## 11. Reporting

A report is an immutable snapshot tied to a scan. The UI shows current state; a
report is what you archive, send, or hand to someone who will never log in.

**Kinds**

| Kind | Audience | Contents |
|---|---|---|
| `executive` | manager | bucket counts, delta vs previous report, phase-exposure table, top 10 longest-lived certs, expiring ≤30d |
| `worklist` | engineer | every public cert with `lifetime_days > 47`, sorted by severity then lifetime, endpoints serving it, ack state |
| `inventory` | auditor | all certs + endpoints: chain, issuer, key/sig, dates, trust, ARI/OCSP/CRL, CAA |
| `domain` | app owner | per-domain rollup: certs, endpoints, trust, expiry, findings |

**Formats**

- **HTML** — one self-contained file, inline CSS, no JS, no external assets, with
  a print stylesheet. PDF comes from the browser's print dialog; no headless
  Chrome in the image.
- **CSV** — one row per cert for `worklist`/`inventory`, one row per endpoint for
  the endpoint sheet.
- **JSON** — full structured output with a `schema_version` field.
- **ZIP** — the three above bundled, when "all formats" is selected.

**Generation**

- On demand: `POST /reports` → queued on the same job engine as scans → row in
  `reports` with status, then rendered files under `/data/reports/<id>/`.
- Scheduled: `report.schedule` (default monthly, 1st at 04:07 UTC) generates
  `executive` + `worklist` from the latest `done` scan. A scheduled report with
  no new scan still generates, and says so.
- Every report embeds: generation time, source scan id and time, scope in force,
  tool version, and the sentence "publicly-trusted certificates only; private-CA
  observations are excluded."
- Rendered bytes are never regenerated. `sha256` is stored so a downloaded file
  can be matched to the audit trail.

**Delta section.** Each report diffs against the previous report of the same
kind: new certs, retired certs, lifetime changes, newly opened and newly closed
violations. This is why `certs.retired_at` and the `done`-only lifecycle rule
exist.

**Delivery**

- Authenticated download and inline view, always.
- One optional webhook destination (`settings.report.webhook_url`, HMAC-signed
  body, link to the report). Attempts recorded in `report_deliveries`, 3 retries
  with exponential backoff, failures shown in the UI.
- SMTP/email is deferred (§18).

## 12. Jobs and scheduling

- Single-flight: at most one running scan. A trigger while one runs is either
  queued (default) or rejected, per setting.
- A job writes progress counters to `scans.stats_json` and emits SSE events
  (`discovered`, `dialed`, `failed`, `phase`) so the UI shows movement.
- Cancel sets a context cancellation; partial results are committed and the scan
  is marked `cancelled`.
- Default schedule: daily at 03:17 UTC with ±10 min jitter. Skipped runs are
  recorded, not silently dropped.
- Retention: keep 90 scans, prune `observations` beyond that; keep `certs` and
  `findings` (they are history).
- Lifecycle (`certs.last_seen`, `certs.retired_at`, per-scan diff) is updated
  **only** by scans that end `done`. Cancelled and failed scans persist their
  observations and progress, but never touch lifecycle fields — a partial run
  must not read as mass retirement.
- Single-flight lives in the store, not only in-process: `47c scan` takes the
  SQLite write lock plus an advisory row in `settings`, and exits non-zero with
  "scan in progress" unless `--wait` is passed. `serve` and the CLI therefore
  cannot overlap.

## 13. Container and deployment

```
builder: golang:1.24-alpine   -> CGO_ENABLED=0 go build
runtime: scratch              -> /47c, embedded roots, /data volume
user 65532, read-only rootfs, /data writable
healthcheck: 47c health
```

Compose on the home PC: `restart: unless-stopped`, `127.0.0.1:8080:8080`,
`./data:/data`, `ADMIN_PASSWORD` set on first boot only.

## 14. Security

- Scope allowlist is enforced at dial time, not just at discovery time.
- No redirects. The only outbound request to a URL taken from remote data is the
  AIA fetch: http/https only, no redirect, 5 s, 1 MiB, cached (§9). CT responses
  are data, never endpoints to contact.
- All mutating routes require session + CSRF; all are audit-logged.
- Only password hashes are stored. No CA API tokens in v1.
- SQLite file permissions `0600`, owned by the container UID.

## 15. Testing

- Table-driven phase classification across every boundary date, including
  `not_before` exactly on 2026-03-15 / 2027-03-15 / 2029-03-15.
- Lifetime arithmetic with backdated `not_before`.
- Scope matching: `a.example.com` matches `example.com`; `notexample.com` does
  not; exclusions win over includes.
- Trust classification with fixture chains: public root, private root,
  incomplete chain, expired, hostname mismatch.
- Integration: local TLS servers with generated certs → discover → collect →
  classify → store, end to end.
- Migration test from empty DB; export snapshot tests.
- Manual acceptance: scan two owned domains, compare fingerprint and dates
  against `openssl s_client`.

## 16. Delivery phases

1. Core: scope, discover, collect, x509eval, store, `47c scan`, CSV/JSON.
2. Web read-only: dashboard, certs, domains, scans, export.
3. Mutations: auth, users, scope editor, settings, job trigger/cancel, acks,
   audit, on-demand report generation and download.
4. Ops: scheduler, scheduled reports, webhook delivery, container, compose,
   backup, docs.

Each phase is independently shippable.

## 17. Left to the builder

- Exact crt.sh pagination and backoff constants.
- Visual design of the templates (plain, dense, readable; no design system).
- Report layout within that template set; content is specified in §11.
- Default port list beyond the three above.
- Retention defaults beyond 90 scans.

## 18. Deferred (v2)

- STARTTLS (SMTP/IMAP/POP3/LDAP).
- TOTP / OIDC login.
- Notifications: email/SMTP and push (ntfy) on new `violates_*` or
  `expires_soon`. The v1 webhook delivers reports only, not per-event alerts.
- Prometheus `/metrics` exporter.
- Service/owner mapping (which team owns a cert).
- ACME/ARI renewal integration.
- Private-CA modules (ADCS, Vault, cert-manager) for internal visibility.
