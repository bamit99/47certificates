CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    disabled      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    ip         TEXT,
    user_agent TEXT
);

CREATE TABLE IF NOT EXISTS scope_entries (
    id         INTEGER PRIMARY KEY,
    kind       TEXT NOT NULL CHECK (kind IN ('include', 'exclude', 'seed')),
    value      TEXT NOT NULL,
    note       TEXT,
    created_by INTEGER REFERENCES users(id),
    created_at INTEGER NOT NULL,
    UNIQUE (kind, value)
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY,
    started_at   INTEGER NOT NULL,
    finished_at  INTEGER,
    status       TEXT NOT NULL CHECK (status IN ('queued', 'running', 'done', 'failed', 'cancelled')),
    trigger      TEXT NOT NULL CHECK (trigger IN ('manual', 'schedule', 'cli')),
    triggered_by INTEGER REFERENCES users(id),
    stats_json   TEXT,
    error        TEXT
);

CREATE TABLE IF NOT EXISTS endpoints (
    id              INTEGER PRIMARY KEY,
    hostname        TEXT NOT NULL,
    port            INTEGER NOT NULL,
    ip              TEXT NOT NULL,
    first_seen_scan INTEGER REFERENCES scans(id),
    last_seen_scan  INTEGER REFERENCES scans(id),
    UNIQUE (hostname, port, ip)
);

CREATE TABLE IF NOT EXISTS certs (
    id                 INTEGER PRIMARY KEY,
    fingerprint_sha256 TEXT NOT NULL UNIQUE,
    subject            TEXT,
    issuer_dn          TEXT,
    not_before         INTEGER,
    not_after          INTEGER,
    lifetime_days      INTEGER,
    key_alg            TEXT,
    key_bits           INTEGER,
    sig_alg            TEXT,
    san_json           TEXT,
    chain_json         TEXT,
    ari_url            TEXT,
    ocsp_url           TEXT,
    crl_url            TEXT,
    first_seen         INTEGER,
    last_seen          INTEGER,
    retired_at         INTEGER
);

CREATE TABLE IF NOT EXISTS observations (
    scan_id        INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    endpoint_id    INTEGER NOT NULL REFERENCES endpoints(id),
    cert_id        INTEGER NOT NULL REFERENCES certs(id),
    trust          TEXT,
    chain_valid    INTEGER NOT NULL DEFAULT 0,
    hostname_valid INTEGER NOT NULL DEFAULT 0,
    expired        INTEGER NOT NULL DEFAULT 0,
    tls_version    INTEGER,
    cipher         INTEGER,
    caa_json       TEXT,
    error          TEXT,
    PRIMARY KEY (scan_id, endpoint_id, cert_id)
);

CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY,
    cert_id      INTEGER NOT NULL REFERENCES certs(id) ON DELETE CASCADE,
    endpoint_id  INTEGER NOT NULL DEFAULT 0,
    type         TEXT NOT NULL,
    phase        TEXT NOT NULL,
    detail_json  TEXT,
    first_seen   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    status       TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'ack', 'snoozed', 'resolved')),
    ack_by       INTEGER REFERENCES users(id),
    ack_at       INTEGER,
    snooze_until INTEGER,
    note         TEXT,
    UNIQUE (cert_id, endpoint_id, type)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY,
    user_id     INTEGER REFERENCES users(id),
    action      TEXT NOT NULL,
    target      TEXT,
    detail_json TEXT,
    at          INTEGER NOT NULL,
    ip          TEXT
);

CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER PRIMARY KEY,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    kind        TEXT NOT NULL,
    status      TEXT NOT NULL,
    params_json TEXT,
    html_path   TEXT,
    csv_path    TEXT,
    json_path   TEXT,
    size_bytes  INTEGER,
    sha256      TEXT,
    created_by  INTEGER REFERENCES users(id),
    created_at  INTEGER NOT NULL,
    finished_at INTEGER,
    error       TEXT
);

CREATE TABLE IF NOT EXISTS report_deliveries (
    id         INTEGER PRIMARY KEY,
    report_id  INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,
    target     TEXT,
    status     TEXT NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_lock (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    acquired_at INTEGER
);

INSERT OR IGNORE INTO scan_lock (id, acquired_at) VALUES (1, NULL);
