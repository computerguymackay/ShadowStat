-- ShadowStat schema (version 1)

CREATE TABLE IF NOT EXISTS schema_meta (
    version     INTEGER NOT NULL
);

-- ── Config / settings ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL
);

-- ── Users / credentials ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    must_reauth_at  INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
    token           TEXT PRIMARY KEY,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    elevated_until  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- ── Hosts ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS hosts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip              TEXT NOT NULL UNIQUE,
    display_name    TEXT,
    first_seen      INTEGER NOT NULL,
    last_seen       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hosts_last_seen ON hosts(last_seen);

-- ── Tier 1: full-fidelity recent flows (last 24h working set) ───────
CREATE TABLE IF NOT EXISTS flows_recent (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         INTEGER NOT NULL REFERENCES hosts(id),
    direction       INTEGER NOT NULL,
    proto           INTEGER NOT NULL,
    local_ip        TEXT NOT NULL,
    local_port      INTEGER NOT NULL,
    remote_ip       TEXT NOT NULL,
    remote_port     INTEGER NOT NULL,
    first_seen      INTEGER NOT NULL,
    last_seen       INTEGER NOT NULL,
    bytes_sent      INTEGER NOT NULL DEFAULT 0,
    bytes_recv      INTEGER NOT NULL DEFAULT 0,
    packets_sent    INTEGER NOT NULL DEFAULT 0,
    packets_recv    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_flows_recent_host_time ON flows_recent(host_id, last_seen);
CREATE INDEX IF NOT EXISTS idx_flows_recent_lastseen  ON flows_recent(last_seen);
CREATE INDEX IF NOT EXISTS idx_flows_recent_remote    ON flows_recent(remote_ip, remote_port);

-- ── Tier 2: rollups ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rollup_1m (
    host_id      INTEGER NOT NULL REFERENCES hosts(id),
    direction    INTEGER NOT NULL,
    bucket_ts    INTEGER NOT NULL,
    bytes_sent   INTEGER NOT NULL DEFAULT 0,
    bytes_recv   INTEGER NOT NULL DEFAULT 0,
    packets_sent INTEGER NOT NULL DEFAULT 0,
    packets_recv INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (host_id, direction, bucket_ts)
);
CREATE INDEX IF NOT EXISTS idx_rollup_1m_time ON rollup_1m(bucket_ts);

CREATE TABLE IF NOT EXISTS rollup_5m (
    host_id      INTEGER NOT NULL REFERENCES hosts(id),
    direction    INTEGER NOT NULL,
    bucket_ts    INTEGER NOT NULL,
    bytes_sent   INTEGER NOT NULL DEFAULT 0,
    bytes_recv   INTEGER NOT NULL DEFAULT 0,
    packets_sent INTEGER NOT NULL DEFAULT 0,
    packets_recv INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (host_id, direction, bucket_ts)
);
CREATE INDEX IF NOT EXISTS idx_rollup_5m_time ON rollup_5m(bucket_ts);

CREATE TABLE IF NOT EXISTS rollup_1h (
    host_id      INTEGER NOT NULL REFERENCES hosts(id),
    direction    INTEGER NOT NULL,
    bucket_ts    INTEGER NOT NULL,
    bytes_sent   INTEGER NOT NULL DEFAULT 0,
    bytes_recv   INTEGER NOT NULL DEFAULT 0,
    packets_sent INTEGER NOT NULL DEFAULT 0,
    packets_recv INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (host_id, direction, bucket_ts)
);
CREATE INDEX IF NOT EXISTS idx_rollup_1h_time ON rollup_1h(bucket_ts);

CREATE TABLE IF NOT EXISTS rollup_1d (
    host_id      INTEGER NOT NULL REFERENCES hosts(id),
    direction    INTEGER NOT NULL,
    bucket_ts    INTEGER NOT NULL,
    bytes_sent   INTEGER NOT NULL DEFAULT 0,
    bytes_recv   INTEGER NOT NULL DEFAULT 0,
    packets_sent INTEGER NOT NULL DEFAULT 0,
    packets_recv INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (host_id, direction, bucket_ts)
);
CREATE INDEX IF NOT EXISTS idx_rollup_1d_time ON rollup_1d(bucket_ts);
