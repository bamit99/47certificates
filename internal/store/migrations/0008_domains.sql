-- Domains become first class. A certificate may serve several domains, but
-- whether a domain serves it, when it was last seen there and whether it was
-- retired there are per-domain facts.
CREATE TABLE IF NOT EXISTS domains (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);

-- Every domain named by an include entry gets a row. The scope keeps its
-- meaning; the domain table gives every domain a stable id that survives the
-- scope being edited.
INSERT OR IGNORE INTO domains (name, created_at)
    SELECT value, strftime('%s', 'now') FROM scope_entries WHERE kind = 'include';

-- A scan covers one domain.
ALTER TABLE scans ADD COLUMN domain_id INTEGER REFERENCES domains(id);

-- An endpoint belongs to one domain.
ALTER TABLE endpoints ADD COLUMN domain_id INTEGER REFERENCES domains(id);

-- An observation belongs to one domain.
ALTER TABLE observations ADD COLUMN domain_id INTEGER REFERENCES domains(id);

-- The lifecycle of a certificate within one domain.
CREATE TABLE IF NOT EXISTS domain_certs (
    domain_id  INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    cert_id    INTEGER NOT NULL REFERENCES certs(id) ON DELETE CASCADE,
    first_seen INTEGER,
    last_seen  INTEGER,
    retired_at INTEGER,
    PRIMARY KEY (domain_id, cert_id)
);

-- Backfill: the endpoints recorded so far belong to the domain whose name
-- covers their hostname.
UPDATE endpoints
   SET domain_id = (
       SELECT d.id FROM domains d
        WHERE d.name = endpoints.hostname
           OR endpoints.hostname LIKE '%.' || d.name
        ORDER BY length(d.name) DESC
        LIMIT 1)
 WHERE domain_id IS NULL;

UPDATE observations
   SET domain_id = (SELECT e.domain_id FROM endpoints e WHERE e.id = observations.endpoint_id)
 WHERE domain_id IS NULL;

-- Findings move to a domain too. The table is rebuilt because the uniqueness
-- constraint must include the domain: the same certificate serving two
-- domains has its own finding row in each.
CREATE TABLE findings_new (
    id           INTEGER PRIMARY KEY,
    domain_id    INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    cert_id      INTEGER NOT NULL REFERENCES certs(id) ON DELETE CASCADE,
    endpoint_id  INTEGER REFERENCES endpoints(id) ON DELETE CASCADE,
    type         TEXT NOT NULL,
    phase        TEXT NOT NULL,
    detail_json  TEXT,
    first_seen   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    scan_id      INTEGER,
    status       TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'ack', 'snoozed', 'resolved')),
    ack_by       INTEGER REFERENCES users(id),
    ack_at       INTEGER,
    snooze_until INTEGER,
    note         TEXT
);

-- A finding belongs to the domain of its endpoint. A certificate-level
-- finding belongs to the domain of the endpoint that observed it, or to the
-- domain whose name covers one of the certificate's names.
INSERT INTO findings_new (id, domain_id, cert_id, endpoint_id, type, phase, detail_json,
                          first_seen, last_seen, scan_id, status, ack_by, ack_at, snooze_until, note)
SELECT f.id,
       COALESCE((SELECT e.domain_id FROM endpoints e WHERE e.id = f.endpoint_id),
                (SELECT d.id FROM domains d
                  WHERE EXISTS (SELECT 1 FROM certs c, json_each(c.san_json) s
                                 WHERE c.id = f.cert_id
                                   AND (s.value = d.name OR s.value LIKE '%.' || d.name))),
                (SELECT d.id FROM domains d
                  WHERE EXISTS (SELECT 1 FROM certs c, json_each(c.san_json) s
                                 WHERE c.id = f.cert_id
                                   AND (s.value = d.name OR s.value LIKE '%.' || d.name)))),
       f.cert_id, f.endpoint_id, f.type, f.phase, f.detail_json,
       f.first_seen, f.last_seen, f.scan_id, f.status, f.ack_by, f.ack_at, f.snooze_until, f.note
  FROM findings f;

DROP TABLE findings;
ALTER TABLE findings_new RENAME TO findings;

CREATE UNIQUE INDEX findings_domain_cert_endpoint_type
    ON findings (domain_id, cert_id, COALESCE(endpoint_id, 0), type);
CREATE INDEX findings_domain ON findings (domain_id);
CREATE INDEX endpoints_domain ON endpoints (domain_id);
CREATE INDEX observations_domain ON observations (domain_id);
CREATE INDEX scans_domain ON scans (domain_id);
