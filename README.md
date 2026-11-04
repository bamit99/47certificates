# 47c — 47-Day TLS Certificate Impact Auditor

A self-hosted, per-domain inventory of the **publicly-trusted TLS certificates**
your domains serve, classified against the CA/Browser Forum certificate-lifetime
schedule.

The CA/B Forum is shortening the maximum certificate lifetime in three steps:

| Phase | Effective from | Max certificate lifetime | Max DV/validation reuse |
|---|---|---|---|
| P0 | before 2026-03-15 | 398 days | 398 days |
| P1 | 2026-03-15 | 200 days | 200 days |
| P2 | 2027-03-15 | 100 days | 100 days |
| P3 | 2029-03-15 | **47 days** | 10 days |

Every certificate you hold today is too long for 2027, and almost all of them
are too long for 2029. Automating renewal against a 47-day lifetime is not a
change you make in 2029; it is a change you make now, because by then manual
renewal is already unworkable.

`47c` answers three questions about your estate, per domain:

1. **Which certificates are served today, and where?**
2. **Which ones have a lifetime the current or next phase forbids?**
3. **Which ones have no automation signal at all, and will break at the next
   renewal cliff?**

It is a *migration worklist*, not a compliance certificate.

---

## Table of contents

- [What it does](#what-it-does)
- [How it works](#how-it-works)
- [Installation](#installation)
- [First run](#first-run)
- [The web interface](#the-web-interface)
- [Command line](#command-line)
- [Reports](#reports)
- [Running it in an environment](#running-it-in-an-environment)
- [Configuration](#configuration)
- [Being a good citizen](#being-a-good-citizen)
- [How the classification works](#how-the-classification-works)
- [Data model](#data-model)
- [Development](#development)
- [Design documents](#design-documents)

---

## What it does

### Per-domain inventory

Every domain you add to the scope gets its own inventory: its own
certificates, its own findings, its own scans and its own reports. **Nothing
mixes.** A certificate that `colt.net` stopped serving is retired there and
still live at `example.com`.

A certificate's fingerprint is a global fact — the same certificate may serve
two domains — but whether a domain serves it, when it was last seen there, and
whether it was retired there are per-domain facts. The database records them
that way, so retirement and renewal tracking are correct for every estate
independently.

### Impact classification, not just a certificate list

Each certificate is judged against the phase in force **when it was issued**:

| Finding | Meaning |
|---|---|
| `violates_current_phase` | The lifetime exceeds what the phase allowed at issuance. This should not exist. |
| `grandfathered_too_long` | Legal when issued, too long for today's limit. A renewal must be shorter. |
| `exceeds_47_target` | Longer than the 47 days the 2029 phase will allow. |
| `expires_soon` | Expires within 30 days. |
| `expired_served` | Expired, and still being served. |
| `hostname_mismatch` | The certificate does not cover the name that was asked for. |
| `untrusted_chain` | The chain does not build to a public root. |
| `private_trust` | The chain anchors in a private root. Informational. |

Findings are **independent rows**, not exclusive buckets. A 400-day certificate
from 2024 is both `grandfathered_too_long` and `exceeds_47_target`.

The UI derives one **impact bucket** per certificate — the worst of its
findings — so the dashboard counts certificates, never raw finding rows:

| Bucket | Meaning |
|---|---|
| `violation` | A rule is broken now. |
| `grandfathered` | Legal when issued, too long today. A renewal has to be shorter. |
| `expiring` | Expires within 30 days. |
| `target` | Above the 47-day target. Worklist for 2029, not broken today. |
| `info` | A private certificate — out of scope for the 47-day analysis. |
| `ok` | Compliant. |

### Severity and buckets

Severity is derived at read time, never stored, so a phase boundary changes
the answer without a rescan or a migration:

| Severity | Findings |
|---|---|
| `critical` | `violates_current_phase`, `expired_served` |
| `high` | `grandfathered_too_long`, `untrusted_chain`, `expires_soon` within 14 days |
| `medium` | `expires_soon` within 30 days, `hostname_mismatch` |
| `info` | `exceeds_47_target`, `private_trust` |

### Triage you can act on

Every finding can be **acknowledged** or **snoozed**. An acknowledgement says
"I have seen this and I accept it"; a snooze says "not until next week". Both
are recorded in the audit log, and both are per finding, so a certificate
served on fifty names still needs one decision.

### Reports that are evidence, not screenshots

A report is an immutable snapshot tied to a scan: it never changes after
generation, and its SHA-256 is recorded so a downloaded file can be matched to
the audit trail. Each report diffs against the previous report of the same
kind, so you can see what changed since last month.

---

## How it works

A scan is four phases:

```
discover ──► probe ──► classify ──► persist
```

1. **Discover.** Certificate Transparency logs (crt.sh, with Cert Spotter as
   the fallback) are queried for the domain. The names are filtered through
   your allowlist — a name outside it is never dialled. Wildcards
   (`*.example.com`) are coverage metadata and are never dialled either.
2. **Probe.** Each name is resolved and each address is dialled directly, with
   the correct SNI, so the certificate collected is the one that serves *that*
   name and not a default vhost.
3. **Classify.** The chain is verified against an embedded Mozilla root
   bundle, the hostname is checked, and the lifetime is compared with the
   schedule.
4. **Persist.** Certificates, endpoints, observations and findings are written
   with the domain they belong to. Lifecycle changes and finding closures
   happen **only** for scans that end `done` — a cancelled scan never looks
   like mass retirement.

Two details that matter in practice:

- **The root bundle is embedded.** The container image has no CA directory, so
  every trust decision is made against the same bundle on every host.
- **AIA is fetched when the chain is incomplete.** Missing intermediates are
  recovered from the certificate's own `caIssuers` URL, under a strict policy:
  http/https only, no redirects, at most three URLs, 1 MiB cap, and the
  hostname must resolve to a publicly routable address.

---

## Installation

### Requirements

- Go 1.24 or later (to build from source), or Docker
- A host that can make outbound HTTPS and DNS queries
- About 100 MB of disk for the database, the reports and the images

There are no runtime dependencies beyond the binary itself: SQLite is
embedded, the root bundle is embedded, and the templates are embedded.

### From source

```sh
git clone https://github.com/bamit99/47certificates.git
cd 47certificates
go build -o 47c ./cmd/47c
```

The result is a single static binary. Copy it wherever you like.

### With Docker

```sh
git clone https://github.com/bamit99/47certificates.git
cd 47certificates
docker build -t 47c:dev .
docker run --rm -v "$PWD/data:/data" -p 127.0.0.1:8080:8080 47c:dev
```

Or with compose, which is what the shipped `docker-compose.yml` does:

```sh
docker compose up -d
```

The image is built `FROM scratch`: a non-root UID, a read-only root filesystem
and no shell. The only writable path is the `/data` volume.

> **Bind mounts and permissions.** The image runs as UID `65532`. If you bind
> mount a host directory, it has to be writable by that UID or the container
> cannot create the database:
> ```sh
> mkdir -p data && sudo chown -R 65532:65532 data
> ```
> The shipped compose file uses a named volume, which avoids this entirely.

### Installing the binary

```sh
sudo install -m 0755 47c /usr/local/bin/47c
47c version
```

---

## First run

### 1. Create a user

```sh
47c user add --data-dir ./data --username admin --password '<a strong password>'
```

Or, on the first container start only, set `ADMIN_PASSWORD` in the
environment. The account is created once, when there are no users at all.
**Remove the variable afterwards** — it is a provisioning convenience, not a
credential store.

### 2. Start the server

```sh
47c serve --data-dir ./data
```

The server binds `127.0.0.1:8080` by default. It refuses to bind a
non-loopback address over plain HTTP unless you supply `--tls-cert` and
`--tls-key`, or acknowledge it with `--insecure-http`.

```sh
47c serve --data-dir ./data \
  --tls-cert /etc/ssl/cert.pem --tls-key /etc/ssl/key.pem
```

### 3. Add your domains

Open <http://127.0.0.1:8080> and sign in, or edit the scope directly:

```sh
47c scan --data-dir ./data --scope scope.txt
```

where `scope.txt` holds one `kind:value` per line:

```
include:example.com
include:colt.net
exclude:dev.example.com
seed:legacy.example.com
```

- `include` — a domain, and all of its subdomains. Every include is a domain
  with its own inventory.
- `exclude` — removes a host or subtree from every domain. Always wins.
- `seed` — a discovery hint. Must sit inside an include; it widens discovery,
  never permission.

### 4. Scan

Press **Run scan** on `/scans`, or:

```sh
47c scan --data-dir ./data
```

The scan page shows its progress live: hosts discovered, endpoints dialled and
failures, updating as they happen.

---

## The web interface

| Page | What it is for |
|---|---|
| `/` | Dashboard: severity counts, phase exposure, next expiries, recent scans, and a legend explaining every status. |
| `/domains` | Every domain with its counts, searchable. Each domain has its own page. |
| `/certs` | The certificate inventory of one domain. |
| `/certs/columns` | Choose which columns the list shows. |
| `/certs/{fingerprint}` | One certificate: metadata, SANs, findings, endpoints, PEM download. |
| `/scans` | Scan history; a running scan streams progress live. |
| `/reports` | Generate and download reports. |
| `/audit` | Every mutating action, with who and when. |
| `/settings` | Schedule, ports, concurrency, timeouts, retention, webhook. |

### The domain picker

The header carries a drop-down that switches between domains on every page,
and `/domains` has a search box. The choice follows you around, and every link
keeps the domain in its URL so a shared link always shows the same estate.

### Choosing columns

`/certs/columns` lists every available column with a note on what it means.
Tick the ones you want; the choice is yours alone and is remembered:

fingerprint · subject · **issuer** · **SANs** · not-before · expires ·
lifetime · key · signature · trust · chain · hostname · bucket · severity ·
days left · endpoints · first seen · last seen · retired

### The legend

The dashboard carries a legend explaining the impact buckets, the severities
and every finding type in plain language, so the numbers on the cards are not a
puzzle.

---

## Command line

```
47c serve      web UI, scheduler and background job runner
47c scan       one-off scan of the domains in the allowlist
47c user       manage users (add, list)
47c backup     VACUUM INTO snapshot, refuses to overwrite
47c health     exits 0 when the database opens and the schema matches
47c version
```

Useful flags:

```sh
# Scan one domain from a file, without touching the stored scope.
47c scan --scope scope.txt

# Write the observations of a scan to a file.
47c scan --out inventory.csv
47c scan --out inventory.json

# Probe slowly and gently: one probe per second to any single hostname.
47c scan --concurrency 8 --qps 5

# Wait for a running scan instead of failing.
47c scan --wait

# Back up before you do anything else.
47c backup --data-dir ./data --out backup-$(date +%F).db
```

---

## Reports

Four kinds, each with a **recommended format** chosen for its audience:

| Kind | Recommended | Why | Contents |
|---|---|---|---|
| `executive` | **PDF** | A summary to send and print. | Bucket counts, phase exposure, delta against the last report, the ten longest-lived certificates, everything expiring within 30 days. |
| `worklist` | **CSV** | A list to work through in a spreadsheet. | Every certificate above the 47-day target, sorted by severity then lifetime, with its endpoints. |
| `inventory` | **CSV** | An auditor's machine-readable dump. | Every certificate with its chain, issuer, key, signature, dates, trust and endpoints. |
| `domain` | **Markdown** | A handover note that reads well in a ticket or a commit message. | The same inventory, as a Markdown document. |

Every format stays downloadable, and the ZIP holds all five.

Reports are **immutable**. Once generated, the files and their SHA-256 are
recorded; re-generating creates a new report rather than editing the old one.
Each report embeds its report id, scan id, scan time, generation time, the
scope in force, the tool version, and the sentence:

> publicly-trusted certificates only; private-CA observations are excluded.

### Delivery

Set `report.webhook_url` in `/settings` and the scheduled report is POSTed
there, signed with an HMAC:

```
POST $report.webhook_url
Content-Type: application/json
X-47C-Signature: sha256=<hex HMAC-SHA256(webhook_secret, body)>
```

The secret is generated on first delivery and stored with the report's other
metadata. Delivery is retried three times with exponential backoff and every
attempt is recorded.

---

## Running it in an environment

### On your own machine, continuously

```sh
47c serve --data-dir ./data
```

The scheduler runs a scan every night at 03:17 UTC by default and a report
once a month. Both schedules are cron expressions you can change in
`/settings`; note that they are read when the server starts, so a change needs
a restart.

### In Docker, continuously

```sh
docker compose up -d
docker compose logs -f 47c
```

The compose file publishes the port on `127.0.0.1` only, so the UI is not
reachable from the network. The container runs as a non-root UID with a
read-only root filesystem.

### Behind a reverse proxy

Put TLS in front of it and forward to the loopback port:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

`X-Forwarded-Proto: https` is honoured when deciding whether to mark the
session cookie `Secure`.

### On a schedule, unattended

For a machine that is not always on, run the scan from cron instead of
letting the scheduler do it:

```sh
17 3 * * * /usr/local/bin/47c scan --data-dir /var/lib/47c --out /var/lib/47c/inventory.csv
```

### Backing up

```sh
47c backup --data-dir /var/lib/47c --out /backup/47c-$(date +%F).db
```

`backup` runs `VACUUM INTO` and refuses to overwrite an existing file. The
reports under `data/reports/` are immutable, so snapshot them alongside the
database if you need the evidence to outlive the retention window.

### Restoring

Stop the service, put the database file back, start it again. The schema
version is checked at startup, so a binary that expects a newer schema
refuses to run against an older database rather than corrupting it.

### Sharing it with a team

Everything except the binary and the data directory lives in this repository.
To hand it to somebody else:

1. Give them the repository and the version tag you are running.
2. Give them a database, or let them create their own and add their domains.
3. Keep the webhook secret and the database private — the database holds
   password hashes, live session ids and the CSRF and webhook secrets.

Because the tool is a single binary with an embedded database, running one
instance per team member against their own estate is simpler than sharing
one, and it keeps the audit trail honest.

### Health checks

```sh
47c health --data-dir /var/lib/47c   # exit 0 when the schema matches
curl -sf http://127.0.0.1:8080/healthz
```

The HTTP endpoint answers `503` when the database does not, so an external
watchdog sees a broken database rather than a process that is up but useless.

---

## Configuration

Settings live in the database and are edited in `/settings`.

| Key | Default | Meaning |
|---|---|---|
| `ports` | `443` | TCP ports to probe, comma separated |
| `concurrency` | 32 | probes in flight at once |
| `qps` | 25 | probes per second, overall |
| `host_qps` | 1 | probes per second to any one hostname |
| `max_hosts` | 1000 | names one domain may contribute |
| `timeout` | `10s` | per-connection timeout |
| `schedule` | `17 3 * * *` | nightly scan, UTC |
| `report.schedule` | `7 4 1 * *` | monthly report, UTC |
| `retention` | 90 | scans whose observations are kept |
| `report.webhook_url` | — | where to deliver reports |

Flags for `serve`:

| Flag | Default | Meaning |
|---|---|---|
| `--data-dir` | `./data` | where the database and reports live |
| `--listen` | `127.0.0.1:8080` | address to bind |
| `--tls-cert` / `--tls-key` | — | serve TLS directly |
| `--insecure-http` | off | acknowledge binding a non-loopback address over plain HTTP |

Environment variables: `47C_DATA_DIR`, `47C_LISTEN`, `ADMIN_PASSWORD`.

---

## Being a good citizen

A scan asks a resolver about every name a transparency log mentions and opens
a TLS connection to each name that answers. On a large domain that is a few
thousand DNS queries and a few hundred handshakes. The numbers are small, but
they come from one address at one time, which is the shape an abuse filter
looks at.

The tool is careful about this:

- **DNS answers are cached for 24 hours, including the negative ones.** Most
  names a log mentions are retired and do not exist. On an 801-name scope, 166
  of them answered "no such host"; re-asking changes nothing, so the cache
  holds them. A repeated scan asks the resolver only about names it has not
  seen, and a scan of an unchanged estate asks almost nothing.
- **Probes to one hostname are spaced one second apart.** The names of a
  domain often share an address, and a burst of handshakes to a single server
  is what a firewall reads as an attack rather than an audit.
- **The number of names a domain may contribute is capped**, and the scan
  reports how many it dropped rather than quietly scanning less than asked.
- **Only the ports you configure are probed.**

If a domain owner or your network operator asks for a slower scan, lower
`host_qps` and `qps` in `/settings`, or narrow the scope. A scan of a domain
with a few dozen names can run at one probe per second per host without
touching anything unusual.

---

## How the classification works

**Lifetime** is `floor((not_after - not_before) / 24h)`.

**The phase of a certificate** is the phase in force at its `notBefore` date,
inclusive of the start date: `2026-03-15T00:00:00Z` belongs to P1. A
certificate is judged by the rules that applied when it was issued, not by
today's rules.

**`max_today`** is the maximum lifetime of the phase in force right now. A
certificate longer than that, but issued before the phase began, is
`grandfathered_too_long`: legal then, too long now.

**Expiry** is counted in whole days rounded up, so a certificate 30.9 days
from expiry is 31 days away and is not yet "expires soon", and one 14.9 days
away is 15 days away and is not yet the high-severity case.

**Trust** is decided inside the certificate's own validity window, so an
expired certificate is still reported as publicly trusted — expiry is a
finding, not a trust failure. A chain that anchors in a private root is
informational; a chain that does not build at all is a violation.

**Hostname** is checked against the name that was dialled, not the name in
the certificate.

---

## Data model

| Table | Holds |
|---|---|
| `domains` | One row per domain, kept after it leaves the allowlist. |
| `certs` | The certificate itself: fingerprint, subject, issuer, dates, key, SANs, chain. Global. |
| `domain_certs` | The lifecycle of a certificate **within** one domain: first seen, last seen, retired. |
| `endpoints` | A host, port and address, belonging to one domain. |
| `observations` | What one scan saw at one endpoint. |
| `findings` | Why a certificate needs attention, per domain and per endpoint. |
| `scans` | One scan of one domain. |
| `reports` | An immutable report and the hashes of its files. |
| `audit_log` | Every mutating action. |
| `dns_cache` | DNS answers, including the negative ones. |

The database file is created with owner-only permissions: it holds password
hashes, live session ids and the CSRF and webhook secrets.

---

## Development

```sh
go test ./...
go vet ./...
go build ./cmd/47c
```

The module has three dependencies — `modernc.org/sqlite`, `golang.org/x/crypto`
and `github.com/robfig/cron/v3` — and no others. Tests use the standard
library only.

The design documents are the reference for why things are the way they are:

- [Design](docs/superpowers/specs/2026-11-03-47day-cert-audit-design.md)
- [Implementation plan](docs/superpowers/plans/2026-11-03-47day-cert-audit.md)
- [Operations guide](docs/operations.md)

---

## Scope

**In scope:** publicly-trusted certificates, and the lifetime schedule that
will eventually require them to be short.

**Out of scope, deliberately:**

- Private CA and internal PKI. The CA/B Forum binds publicly-trusted
  certificates; a private root is not enforced by any browser. Certificates
  that are observed but do not chain to a public root are recorded as
  `trust=private` and shown as informational, never as a violation.
- Validation-reuse auditing. The tool cannot see how long a CA has held your
  validation data, so it does not claim to.
- STARTTLS protocols. Direct TLS only.
- Brute-force subdomain enumeration. Transparency logs, DNS and explicit seeds.
- Vulnerability scanning. No cipher grading, no protocol downgrade tests, no
  HSTS analysis.

---

## Licence

MIT. See [LICENSE](LICENSE).
