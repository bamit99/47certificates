# 47c operations guide

47c is a self-hosted inventory of publicly-trusted TLS certificates for an allowlisted domain set, classified against the CA/Browser Forum lifetime schedule:

| Phase | Effective | Max lifetime | Max DV reuse |
|---|---|---|---|
| P0 | before 2026-03-15 | 398 days | 398 days |
| P1 | 2026-03-15 | 200 days | 200 days |
| P2 | 2027-03-15 | 100 days | 100 days |
| P3 | 2029-03-15 | 47 days | 10 days |

A certificate is judged by the phase in force at its `notBefore` date. Severity is computed at read time, so phase boundaries require no rescans or migrations.

## Scope of analysis

Publicly-trusted certificates only. Private CA / internal PKI is **out of scope** and is reported separately as an informational appendix. Chains are verified against an embedded Mozilla root bundle; only chain building, hostname, and validity are checked — CRL/OCSP are never fetched.

AIA `caIssuers` fetches (http/https, no redirects, max 3 URLs, 1 MiB cap) are used to recover missing intermediates. The fetch resolves the hostname and refuses to connect to loopback, private or link-local addresses, so a certificate cannot steer the collector at an internal service. The HTTPS transport verifies against the embedded bundle, because the container image has no CA directory.

## First boot

```sh
docker build -t 47c:dev .
docker compose up -d
```

On first boot with `ADMIN_PASSWORD` set in the environment and zero users, the binary creates the `admin` account with that password and logs that it did so. **Remove `ADMIN_PASSWORD` afterwards**; it is a one-time provisioning variable, not a credential store. The password is never written to the log.

Data lives in a named Docker volume (`47c-data`), pre-created with ownership matching the container's `65532:65532` UID. If you prefer a bind mount (`./data:/data`), run `chown -R 65532:65532 ./data` before first start; the scratch image runs as a non-root UID and cannot create `data/47c.db` inside a root-owned directory.

The database file is created with owner-only permissions (`0600`): it holds password hashes, live session ids and the CSRF and webhook secrets.

Without it, create the user with:

```sh
docker compose exec 47c /47c user add --username admin --password <pw>
```

The UI is served on `http://127.0.0.1:8080` (host-pinned loopback). The app refuses to bind a non-loopback address over plain HTTP unless `--tls-cert/--tls-key` are supplied or `--insecure-http` is passed; in compose we pass `--insecure-http` because Docker needs the non-loopback bind, and the host-side `127.0.0.1:` mapping enforces loopback on the host.

## Health

`/47c health` (used by `HEALTHCHECK`) exits 0 when the SQLite database opens read-only and `MAX(version)` in `schema_migrations` matches the binary's embedded latest version (currently 6). The HTTP `GET /healthz` endpoint returns `ok` when the database answers and `503` when it does not, so an external watchdog sees a broken database.

## Backup and restore

```sh
/47c backup --out /backup/47c-$(date +%F).db
```

`backup` runs `VACUUM INTO`. It **refuses to overwrite** an existing file. Restore by stopping the container, replacing `data/47c.db`, and starting again. Reports live under `data/reports/<id>/` and are immutable; snapshot them alongside the database if you need evidence retention.

## Adding users

```sh
/47c user list
/47c user add --username alice --password <pw>
```

All authenticated users have the same permissions. Usernames are unique; duplicates get a clear error.

## Scope

`/scope` holds one `kind:value` per line:

- `include` — grants a domain and all of its subdomains, and names a domain
  that is scanned.
- `exclude` — removes a host or subtree from the allowlist; always wins.
- `seed` — a discovery hint; must sit inside an include. Seeds widen discovery, never permission.

Wildcards are coverage metadata only; they are never dialled.

Every `include` entry is a domain with its own inventory. The scope editor
replaces the whole list, so keep every domain you still scan.

## Traffic profile and being a good citizen

A scan asks a resolver about every name a certificate transparency log mentions for the domain, and opens a TLS connection to each name that answers. On a large domain that is a few thousand DNS queries and a few hundred TLS handshakes. The numbers are small, but they come from one address at one time, which is the shape an abuse filter looks at.

What a scan does about it:

- **DNS answers are cached for 24 hours, including the negative ones.** Most names a transparency log mentions are retired and do not exist. On the 801-name scope of a real domain, 166 of them answered "no such host"; re-asking them changes nothing, so the cache holds them. A repeated scan asks the resolver only about names it has not seen, and a scan of an unchanged estate asks almost nothing.
- **Probes to one hostname are spaced one second apart** (`host_qps`). The names of a domain often share an address, and a burst of handshakes to a single server is what a firewall reads as an attack rather than an audit.
- **The number of names one scope may contribute is capped** (`max_hosts`, default 1000). The scan reports how many names it dropped instead of quietly scanning less than asked.
- **The overall probe rate is capped** (`qps`, default 25).
- **Only ports you configure are probed** (`ports`, default 443).

The TLS probes carry no user agent — a TLS handshake has no header to put one in — but they set the correct SNI, so the target sees an ordinary client that asked for a specific name and closed the connection.

If the domain owner or the network operator asks for a slower scan, lower `host_qps` and `qps` in `/settings`, or narrow the scope. A scan of a domain with a few dozen names can run at one probe per second per host without touching anything unusual.

## Scanning

Trigger from the UI (`/scans`) or the CLI (`/47c scan [--scope scope.txt] [--out report.csv]`). Without `--scope` the CLI scans the allowlist stored in the database, which is the same scope the UI uses. Scans are single-flight: the web UI and the CLI share a store-level lock and both refuse to double-run. The lock is refreshed while a scan runs, so a long scan cannot be overtaken.

Only `done` scans advance `certs.last_seen`, clear `certs.retired_at` and close findings whose condition no longer holds. A cancelled or failed scan persists its observations and progress but never looks like mass retirement.

Discovery starts from the scope includes and anything crt.sh knows about them (`Cert Spotter` is the fallback source), filters to the allowlist, resolves addresses, and probes with the configured concurrency/QPS. CT answers are cached for 6 hours per domain; the cache stores the names it saw, so a rescan inside the window still probes the hosts CT revealed.

### Watching a scan

The scan page streams its progress live. The counters are written to `scans.stats_json` while the scan runs — not only when it ends — and the server-sent event stream emits `discovered`, `dialed`, `failed` and `phase` events as they change. A scan of a few thousand endpoints takes minutes; the page shows the counters moving instead of a blank panel.

## Exporting

`GET /export?format=csv` and `GET /export?format=json` write the observations of a completed scan as a download. Without `scan_id` the newest completed scan is used. The `/certs` page links to both.

## Phase-boundary behaviour

Severity is derived at read time. When 2027-03-15 arrives, a 120-day cert that was `100-day max`-compliant later becomes a violation **without any rescan**, because `severity` and the bucket are computed from the stored notBefore/lifetime rather than persisted.

## Domains

The tool is a per-domain inventory. Every domain has its own certificates,
its own findings, its own scans and its own reports. Nothing mixes: a
certificate that colt.net stopped serving is retired there and still live at
another domain.

A domain is an `include` entry in the scope. The domain picker in the header
of every page switches between them, and the search on `/domains` narrows the
list. Each domain has its own page at `/domains/<name>` with its counts, its
certificates, its endpoints and its scans.

A scan covers one domain. The scheduler and the CLI scan each domain in
turn. The lifecycle of a certificate — when it was last seen, whether it was
retired — is recorded per domain.

### Choosing the columns

`/certs/columns` picks the columns the certificate list shows. The choice is
per user and is remembered. The available columns are fingerprint, subject,
issuer, SANs, not-before, expires, lifetime, key, signature, trust, chain,
hostname, bucket, severity, days left, endpoints, first seen, last seen and
retired.

## Reports

Kinds: `executive`, `worklist`, `inventory`, `domain`. Formats: PDF, HTML,
CSV, JSON, Markdown, ZIP (stored, not deflated). Reports are immutable: after
generation the files and their SHA-256 (combined + per-file) are recorded, and
only `GET /reports/{id}/download` hands them out. Re-generating creates a new
row and new files.

The formats are not equal choices, so the best one is chosen per kind and
marked as recommended:

| Kind | Recommended | Why |
|---|---|---|
| `executive` | PDF | A summary to send and print. |
| `worklist` | CSV | A list to work through in a spreadsheet. |
| `inventory` | CSV | An auditor's machine-readable dump. |
| `domain` | Markdown | A handover note that reads well in a ticket or a commit message. |

Every format stays downloadable, and the ZIP holds all five.

Each report embeds `report_id`, `scan_id`, the scan time, `generated_at`,
`scope` (the current allowlist string), `version` (`dev` until a release
build overrides it) and a delta sentence against the previous report of the
same kind ("N new certificate, M retired"). Every format carries the sentence
"publicly-trusted certificates only; private-CA observations are excluded."

Counts are per certificate: a certificate served by ten endpoints is counted
once, with its endpoints listed on the row. The CSV endpoint sheet lists every
endpoint separately.

The delta compares against the previous report of the same kind using the
certificate snapshot stored with that report (`report_snapshots`), so pruning
old observations does not corrupt it.

Scheduled reports (`report.schedule`, default `7 4 1 * *`) always use the **newest done scan**; if a newer non-done scan exists, the scheduler records a warning rather than silently using a stale or empty scan.

## Webhook payload

`POST $report.webhook_url` with:

```
Content-Type: application/json
X-47C-Signature: sha256=<hex HMAC-SHA256(webhook_secret, body)>
User-Agent: 47c/1 report delivery
```

```json
{
  "report_id": 123,
  "kind": "executive",
  "scan_id": 42,
  "status": "done",
  "sha256": "{\"combined\":\"...\",\"html\":\"...\",\"csv\":\"...\",\"json\":\"...\"}"
}
```

`webhook_secret` is auto-generated on first delivery and stored in the `settings` table (key `webhook_secret`). Delivery retries 3 times with 1/2/4-second backoff and is recorded in `report_deliveries` (`delivered`/`failed`, with `last_error`). Delivery never blocks the scheduler.

The webhook URL must be `http` or `https`. Link-local addresses (including the cloud metadata endpoint `169.254.169.254`) and `localhost` are refused, and redirects are not followed, so the delivery cannot be steered at an address the operator did not configure. Private LAN addresses are allowed: a report receiver on the operator's own network is a normal deployment.

## Logs

- Container: `docker compose logs -f 47c`
- Prefix: `2026/11/03 ... 47c: ...` (timestamps in the host's local timezone)
- Scan failures surface in `scans.error` and the UI scan detail page; probe errors are aggregated into the scan stats warnings.

## Retention

`retention` (default 90) is the number of newest scans whose `observations` rows are kept; older observation rows are deleted after each successful scheduled scan. Certificates and findings are never deleted by retention.

## Settings

| Key | Default | Meaning |
|---|---|---|
| `ports` | `443` | TCP ports to probe, comma separated |
| `concurrency` | 32 | probes in flight at once |
| `qps` | 25 | probes per second, overall |
| `host_qps` | 1 | probes per second to any one hostname |
| `max_hosts` | 1000 | names one scope may contribute |
| `timeout` | `10s` | per-connection timeout |
| `schedule` | `17 3 * * *` | nightly scan, UTC |
| `report.schedule` | `7 4 1 * *` | monthly report, UTC |
| `retention` | 90 | scans whose observations are kept |
| `report.webhook_url` | — | where to deliver reports |

`schedule` and `report.schedule` are read when the server starts, so a change to either needs a restart. The others take effect on the next scan.

The limits that protect a resolver and a target server are `host_qps`, `max_hosts` and `qps`; see "Traffic profile" above.
