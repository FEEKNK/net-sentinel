-- NetSentinel Enterprise PostgreSQL / TimescaleDB Production Schema
-- Matches the SQLite schema in backend/app/db/database.py for high-concurrency enterprise/hospital deployments.

CREATE TABLE IF NOT EXISTS devices (
    ip TEXT PRIMARY KEY,
    mac TEXT NOT NULL DEFAULT '',
    vendor TEXT NOT NULL DEFAULT 'Unknown',
    hostname TEXT NOT NULL DEFAULT '',
    custom_name TEXT NOT NULL DEFAULT '',
    trusted BOOLEAN NOT NULL DEFAULT FALSE,
    device_type TEXT NOT NULL DEFAULT 'unknown',
    os_guess TEXT NOT NULL DEFAULT 'Unknown',
    latency_ms DOUBLE PRECISION,
    open_ports_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    status TEXT NOT NULL DEFAULT 'online',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS device_history (
    id BIGSERIAL PRIMARY KEY,
    ip TEXT NOT NULL,
    status TEXT NOT NULL,
    latency_ms DOUBLE PRECISION,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alerts (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_ip TEXT NOT NULL,
    dest_ip TEXT NOT NULL DEFAULT '',
    src_port INTEGER,
    dest_port INTEGER,
    protocol TEXT NOT NULL DEFAULT 'ANY',
    rule_sid INTEGER,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL,
    detector_type TEXT NOT NULL,
    action_taken TEXT NOT NULL DEFAULT 'logged'
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC);

CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL DEFAULT 'viewer',
    salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor TEXT NOT NULL,
    role TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS sensors (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    vlan TEXT NOT NULL DEFAULT '',
    api_key_hash TEXT NOT NULL UNIQUE,
    last_seen TIMESTAMPTZ,
    events_received INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
