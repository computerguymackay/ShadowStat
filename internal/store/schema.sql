-- ShadowStat schema (version 2)
--
-- Every statement is CREATE ... IF NOT EXISTS, so this file is safe to run
-- against any existing database. Columns added to an existing table after
-- v1 are added by migrate() in db.go, not here.

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
    role            TEXT NOT NULL DEFAULT 'admin', -- 'admin' or 'standard'
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
    mac_address     TEXT,
    first_seen      INTEGER NOT NULL,
    last_seen       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hosts_last_seen ON hosts(last_seen);

-- Hostnames learned by observing DHCP client traffic (option 12), keyed by
-- MAC since a client's IP isn't yet assigned during DISCOVER/SELECTING.
CREATE TABLE IF NOT EXISTS dhcp_hostnames (
    mac_address TEXT PRIMARY KEY,
    hostname    TEXT NOT NULL,
    last_seen   INTEGER NOT NULL
);

-- ── Tier 1: full-fidelity recent flows (last 24h working set) ───────
-- One row per conversation per flush interval, from the LAN host's side.
--   direction:      who started the conversation (see DirOutbound etc. in
--                   flows.go). Rows written before schema v2 hold 4 (unknown).
--   bytes_sent:     LAN host -> internet.   bytes_recv: internet -> LAN host.
--   service_port:   the server-side port (e.g. 443), so random client ports
--                   collapse into one service. 0 for port-less protocols.
--   app_proto:      application protocol label ('' = unknown).
--   app_confidence: 0 unknown, 1 guessed from port, 2 payload signature.
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
    packets_recv    INTEGER NOT NULL DEFAULT 0,
    service_port    INTEGER NOT NULL DEFAULT 0,
    app_proto       TEXT NOT NULL DEFAULT '',
    app_confidence  INTEGER NOT NULL DEFAULT 0
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

-- ── Long-term history (schema v2) ────────────────────────────────────

-- Progress markers for the rollup job. 'flows_recent_id' is the highest
-- flows_recent.id already folded into every rollup tier, host_totals and
-- host_peer_daily, so each flows_recent row is counted exactly once.
CREATE TABLE IF NOT EXISTS rollup_state (
    name  TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);

-- Cumulative per-host counters since the host was first seen. Never pruned.
-- totals_since is the earliest data the counters include. exact_since is
-- when exact counting began: NULL for hosts first seen after the v2 upgrade,
-- otherwise the upgrade time (totals before it were backfilled from rollups
-- and may be incomplete).
CREATE TABLE IF NOT EXISTS host_totals (
    host_id      INTEGER PRIMARY KEY REFERENCES hosts(id),
    bytes_sent   INTEGER NOT NULL DEFAULT 0,
    bytes_recv   INTEGER NOT NULL DEFAULT 0,
    packets_sent INTEGER NOT NULL DEFAULT 0,
    packets_recv INTEGER NOT NULL DEFAULT 0,
    totals_since INTEGER NOT NULL,
    exact_since  INTEGER
);

-- Per-host, per-UTC-day breakdown by remote peer and service, kept for
-- retention_days. Per-port and per-protocol views are GROUP BYs over this.
CREATE TABLE IF NOT EXISTS host_peer_daily (
    host_id      INTEGER NOT NULL REFERENCES hosts(id),
    day          INTEGER NOT NULL, -- unix seconds at 00:00 UTC
    remote_ip    TEXT NOT NULL,
    proto        INTEGER NOT NULL,
    service_port INTEGER NOT NULL,
    app_proto    TEXT NOT NULL,
    direction    INTEGER NOT NULL,
    app_confidence INTEGER NOT NULL DEFAULT 0, -- highest seen for this row
    bytes_sent   INTEGER NOT NULL DEFAULT 0,
    bytes_recv   INTEGER NOT NULL DEFAULT 0,
    packets_sent INTEGER NOT NULL DEFAULT 0,
    packets_recv INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (host_id, day, remote_ip, proto, service_port, app_proto, direction)
);
CREATE INDEX IF NOT EXISTS idx_host_peer_daily_day ON host_peer_daily(day);

-- Hostnames for remote IPs, learned passively from DNS answers seen on the
-- capture interface. One IP can serve many names (CDNs); the latest wins.
CREATE TABLE IF NOT EXISTS peer_names (
    ip        TEXT PRIMARY KEY,
    name      TEXT NOT NULL,
    last_seen INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_peer_names_last_seen ON peer_names(last_seen);
