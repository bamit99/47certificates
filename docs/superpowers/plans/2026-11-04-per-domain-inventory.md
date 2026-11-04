# Plan: per-domain inventory, column chooser, report formats, legend

Date: 2026-11-04
Status: in progress
Origin: operator request after the colt.net trial scan

## Intent

The tool is a per-domain inventory. Today everything is global: one scope, one
certificate table, one dashboard. Scanning a second domain mixes its
certificates into the first domain's view, and the columns on the certificate
list are fixed. The operator wants:

1. **Per domain.** Every domain has its own page, its own inventory, its own
   scans and its own reports. Nothing mixes.
2. **Column chooser.** The operator picks which columns the certificate list
   shows. SANs and the issuer are missing today and must be available.
3. **Domain picker.** A drop-down plus a search chooses the domain.
4. **Cached DNS.** Already delivered: answers are cached for 24 hours,
   negative answers included. A repeated scan asks the resolver about new
   names only.
5. **Report output formats.** MD, CSV and PDF. The best format is chosen per
   report kind rather than offering everything as an equal choice.
6. **Legend.** The main window explains what each status means.

## Why domains are first class

A certificate's fingerprint is a global fact: the same certificate may serve
two domains. But *whether a domain serves it*, when it was last seen there,
and whether it was retired there are per-domain facts. The data model has to
say so, or retirement and the per-domain counts cannot both be right.

## Data model

`domains` becomes the anchor:

```sql
CREATE TABLE domains (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);
```

The scope's `include` entries name the domains that are scanned. A domain
row is created when an include appears and is kept afterwards, so the history
of a domain stays readable after it leaves the allowlist.

Everything that belongs to a domain carries `domain_id`:

| Table | Change |
|---|---|
| `endpoints` | `domain_id` — an endpoint belongs to one domain |
| `observations` | `domain_id` — an observation belongs to one domain |
| `findings` | `domain_id` — a finding belongs to one domain |
| `domain_certs` | new: `(domain_id, cert_id, first_seen, last_seen, retired_at)` |

`certs` stays global. It holds the fingerprint and the certificate's own
metadata, which do not depend on who serves it.

`domain_certs` carries the lifecycle. Retirement is per domain: a certificate
that colt.net stopped serving is retired there and still live at iana.org.

Findings become unique per `(domain_id, cert_id, endpoint, type)`, so the same
certificate serving two domains has its own finding row in each.

## Scans

A scan targets **one domain**. The domain list is the allowlist's includes;
each one is scanned in turn by the scheduler and on demand.

- `scans` gains `domain_id`.
- Discovery for a scan queries the transparency logs for that domain only.
- Excludes and seeds still apply: a seed must sit inside the scanned
  domain, an exclude always wins.
- Lifecycle and finding closure are per domain, and only for scans that end
  `done`.

This keeps one scan's observations belonging to one domain, which is what
makes the retirement rule correct without extra conditions.

## Column chooser

The certificate list renders a fixed set of columns today. The operator
chooses the set, per user, stored in `settings` under a per-user key.

Available columns: fingerprint, subject, issuer, SANs, not-before, not-after,
lifetime, key, signature, trust, chain, hostname, bucket, severity,
days-left, endpoints, first-seen, last-seen, retired.

Defaults: fingerprint, subject, issuer, SANs, not-after, lifetime, trust,
bucket, severity, days-left, endpoints.

## Report formats

Every report renders in every format. The *default* format is chosen per
kind, because the audiences differ:

| Kind | Default | Why |
|---|---|---|
| `executive` | PDF | A summary to send and print. |
| `worklist` | CSV | A list to work through in a spreadsheet. |
| `inventory` | CSV | An auditor's machine-readable dump. |
| `domain` | MD | A handover note that reads well in a ticket or a commit message. |

PDF is generated in-process with no dependency: a small writer that lays out
text and rules on the standard page sizes.

## Legend

The dashboard carries a legend explaining the impact buckets and the finding
types in plain language, so the numbers on the card are not a puzzle.

## Steps

1. Migration for the domain tables; store layer for domains.
2. Scope reconciles domains; the editor works on the domain list.
3. Scan engine targets one domain; lifecycle and findings follow.
4. Reads are domain-scoped; the UI gains a domain picker and per-domain pages.
5. Column chooser, with the issuer and SAN columns.
6. Report formats: MD, CSV, PDF; defaults per kind.
7. Legend.
8. Operations documentation.
