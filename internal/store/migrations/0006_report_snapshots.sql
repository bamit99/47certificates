-- Report snapshots record the certificate set a report was generated from, so
-- the delta of a later report does not depend on observations that retention
-- has already pruned.
CREATE TABLE IF NOT EXISTS report_snapshots (
    report_id     INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    fingerprint   TEXT NOT NULL,
    lifetime_days INTEGER NOT NULL,
    violation     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (report_id, fingerprint)
);
