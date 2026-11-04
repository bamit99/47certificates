# 47c — 47-Day TLS Certificate Impact Auditor

Inventories publicly-trusted TLS certificates for an allowlisted set of domains and classifies them against the CA/Browser Forum lifetime schedule:

| Phase | Effective | Max lifetime | Max DV reuse |
|---|---|---|---|
| P0 | before 2026-03-15 | 398 days | 398 days |
| P1 | 2026-03-15 | 200 days | 200 days |
| P2 | 2027-03-15 | 100 days | 100 days |
| P3 | 2029-03-15 | 47 days | 10 days |

Single Go binary, embedded SQLite, server-rendered UI. Publicly-trusted certificates only; private CA / internal PKI is explicitly out of scope.

- Design: `docs/superpowers/specs/2026-11-03-47day-cert-audit-design.md`
- Plan: `docs/superpowers/plans/2026-11-03-47day-cert-audit.md`
- Operations: `docs/operations.md`

## Quick start

```sh
go build -o 47c ./cmd/47c
./47c user add --username admin --password <pw>
./47c serve                  # binds 127.0.0.1:8080
# or in Docker:
docker build -t 47c:dev .
docker compose up -d         # serves 127.0.0.1:8080
```

## Commands

- `serve` — web UI, scheduler, and background job runner
- `scan` — one-off scan against the scope in the database (`--scope file` overrides it)
- `user` — manage users (`add`, `list`)
- `backup` — `VACUUM INTO` snapshot, refuses to overwrite
- `health` — exits 0 when the database opens and the schema matches
- `version`

## Web UI

- `/` — dashboard: severity counts, phase exposure, next expiries, recent scans, and a legend explaining every status
- `/domains` — every domain, searchable, each with its own page and inventory
- `/certs` — the inventory of one domain; the columns are chosen per user at `/certs/columns`
- `/scans` — scan history; a running scan streams its progress live
- `/reports` — immutable PDF/HTML/CSV/JSON/Markdown reports with a delta against the previous one
- `/export?format=csv|json` — the observations of a completed scan, for an offline copy

## Development

```sh
go test ./...
go vet ./...
```
