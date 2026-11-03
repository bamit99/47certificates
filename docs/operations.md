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

Publicly-trusted certificates only. Private CA / internal PKI is **out of scope** and is reported separately as an informational appendix. Chains are verified against an embedded Mozilla root bundle; only chain building, hostname, and validity are checked — CRL/OCSP are never fetched. AIA `caIssuers` fetches (http/https, no redirects, max 3 URLs, 1 MiB cap) are used to recover missing intermediates.

## First boot

```sh
docker build -t 47c:dev .
docker compose up -d
```

On first boot with `ADMIN_PASSWORD` set in the environment and zero users, the binary creates the `admin` account with that password and logs it. **Remove `ADMIN_PASSWORD` afterwards**; it is a one-time provisioning variable, not a credential store.

Data lives in a named Docker volume (`47c-data`), pre-created with ownership matching the container's `65532:65532` UID. If you prefer a bind mount (`./data:/data`), run `chown -R 65532:65532 ./data` before first start; the scratch image runs as a non-root UID and cannot create `data/47c.db` inside a root-owned directory.

Without it, create the user with:

```sh
docker compose exec 47c /47c user add --username admin --password <pw>
```

The UI is served on `http://127.0.0.1:8080` (host-pinned loopback). The app refuses to bind a non-loopback address over plain HTTP unless `--tls-cert/--tls-key` are supplied or `--insecure-http` is passed; in compose we pass `--insecure-http` because Docker needs the non-loopback bind, and the host-side `127.0.0.1:` mapping enforces loopback on the host.

## Health

`/47c health` (used by `HEALTHCHECK`) exits 0 when the SQLite database opens read-only and `MAX(version)` in `schema_migrations` matches the binary's embedded latest version (currently 2). The HTTP `GET /healthz` endpoint returns `ok` for external watchdogs.

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

- `include` — grants a domain and all of its subdomains.
- `exclude` — removes a host or subtree from the allowlist; always wins.
- `seed` — a discovery hint; must sit inside an include. Seeds widen discovery, never permission.

Wildcards are coverage metadata only; they are never dialled.

## Scanning

Trigger from the UI (`/scans`) or the CLI (`/47c scan --scope scope.txt [--out report.csv]`). Scans are single-flight: the web UI and the CLI share a store-level lock and both refuse to double-run. Only `done` scans advance `certs.last_seen` and retire unseen certs; a cancelled scan never looks like mass retirement.

Discovery starts from the scope includes and anything crt.sh knows about them (`Cert Spotter` is the fallback source), filters to the allowlist, resolves addresses, and probes with the configured concurrency/QPS.

## Phase-boundary behaviour

Severity is derived at read time. When 2027-03-15 arrives, a 120-day cert that was `100-day max`-compliant later becomes a violation **without any rescan**, because `severity` and the bucket are computed from the stored notBefore/lifetime rather than persisted.

## Reports

Kinds: `executive`, `worklist`, `inventory`, `domain`. Formats: HTML, CSV, JSON, ZIP (stored, not deflated). Reports are immutable: after generation the files and their SHA-256 (combined + per-file) are recorded, and only `GET /reports/{id}/download` hands them out. Re-generating creates a new row and new files.

Each report embeds `report_id`, `scan_id`, `generated_at`, `scope` (the current allowlist string), `version` (`dev` until a release build overrides it) and a delta sentence against the previous report of the same kind ("N new certificate, M retired").

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

## Logs

- Container: `docker compose logs -f 47c`
- Prefix: `2026/11/03 ... 47c: ...` (timestamps in the host's local timezone)
- Scan failures surface in `scans.error` and the UI scan detail page; probe errors are aggregated into the scan stats warnings.

## Retention

`retention` (default 30) is the number of newest scans whose `observations` rows are kept; older observation rows are deleted after each successful scheduled scan. Certificates and findings are never deleted by retention.
