-- Findings move from a NOT NULL 0 sentinel to NULL for cert-level rows, with
-- the uniqueness enforced by an expression index (SQLite treats NULLs as
-- distinct in table constraints).
PRAGMA foreign_keys = OFF;

CREATE TABLE findings_new (
    id           INTEGER PRIMARY KEY,
    cert_id      INTEGER NOT NULL REFERENCES certs(id) ON DELETE CASCADE,
    endpoint_id  INTEGER REFERENCES endpoints(id) ON DELETE CASCADE,
    type         TEXT NOT NULL,
    phase        TEXT NOT NULL,
    detail_json  TEXT,
    first_seen   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    status       TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'ack', 'snoozed', 'resolved')),
    ack_by       INTEGER REFERENCES users(id),
    ack_at       INTEGER,
    snooze_until INTEGER,
    note         TEXT
);

INSERT INTO findings_new (id, cert_id, endpoint_id, type, phase, detail_json,
                          first_seen, last_seen, status, ack_by, ack_at, snooze_until, note)
SELECT id, cert_id, NULLIF(endpoint_id, 0), type, phase, detail_json,
       first_seen, last_seen, status, ack_by, ack_at, snooze_until, note
FROM findings;

DROP TABLE findings;
ALTER TABLE findings_new RENAME TO findings;

CREATE UNIQUE INDEX findings_cert_endpoint_type ON findings (cert_id, COALESCE(endpoint_id, 0), type);

PRAGMA foreign_keys = ON;
