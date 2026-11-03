# 47c — 47-Day TLS Certificate Impact Auditor

Inventories publicly-trusted TLS certificates for an allowlisted set of domains
and classifies them against the CA/Browser Forum lifetime schedule:

| Phase | Effective | Max lifetime | Max DV reuse |
|---|---|---|---|
| P1 | 2026-03-15 | 200 days | 200 days |
| P2 | 2027-03-15 | 100 days | 100 days |
| P3 | 2029-03-15 | 47 days | 10 days |

Single Go binary, SQLite, embedded web UI. Publicly-trusted certificates only;
private CA / internal PKI is out of scope.

- Design: `docs/superpowers/specs/2026-11-03-47day-cert-audit-design.md`
- Plan: `docs/superpowers/plans/2026-11-03-47day-cert-audit.md`

## Status

Under construction. See the plan for the delivery phases.

## Development

```bash
go test ./...
go build -o 47c ./cmd/47c
./47c version
```
