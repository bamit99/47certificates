-- DNS answers are cached between scans so a repeated scan does not ask the
-- same questions again. Negative answers are cached too: a name that does
-- not exist stays a name that does not exist, and re-asking is the bulk of
-- the traffic a scan would otherwise generate.
CREATE TABLE IF NOT EXISTS dns_cache (
    hostname TEXT PRIMARY KEY,
    ips      TEXT NOT NULL DEFAULT '[]',
    cname    TEXT NOT NULL DEFAULT '',
    nxdomain INTEGER NOT NULL DEFAULT 0,
    at       INTEGER NOT NULL
);
