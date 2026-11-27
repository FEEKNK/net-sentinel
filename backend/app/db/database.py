"""Async SQLite database manager with strict parameterized queries."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, AsyncIterator

import aiosqlite


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS devices (
    ip TEXT PRIMARY KEY,
    mac TEXT NOT NULL DEFAULT '',
    vendor TEXT NOT NULL DEFAULT 'Unknown',
    hostname TEXT NOT NULL DEFAULT '',
    custom_name TEXT NOT NULL DEFAULT '',
    trusted INTEGER NOT NULL DEFAULT 0,
    device_type TEXT NOT NULL DEFAULT 'unknown',
    os_guess TEXT NOT NULL DEFAULT 'Unknown',
    latency_ms REAL,
    open_ports_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'online',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    status TEXT NOT NULL,
    latency_ms REAL,
    recorded_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_history_ip_id ON device_history(ip, id DESC);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
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
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);

CREATE TABLE IF NOT EXISTS snmp_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    host TEXT NOT NULL UNIQUE,
    community TEXT NOT NULL DEFAULT 'public',
    port INTEGER NOT NULL DEFAULT 161,
    snmp_version TEXT NOT NULL DEFAULT 'v2c',
    v3_username TEXT NOT NULL DEFAULT '',
    v3_auth_key TEXT NOT NULL DEFAULT '',
    v3_priv_key TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS snmp_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,
    target_name TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    cpu_pct REAL,
    mem_pct REAL,
    in_bps REAL NOT NULL DEFAULT 0.0,
    out_bps REAL NOT NULL DEFAULT 0.0,
    source_type TEXT NOT NULL DEFAULT 'local_nic'
);

CREATE INDEX IF NOT EXISTS idx_snmp_metrics_ts ON snmp_metrics(timestamp DESC);

CREATE TABLE IF NOT EXISTS blocked_ips (
    ip TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    blocked_at TEXT NOT NULL,
    expires_at TEXT,
    is_dry_run INTEGER NOT NULL DEFAULT 1,
    active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS syslog_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    severity TEXT NOT NULL,
    facility TEXT NOT NULL DEFAULT 'user',
    message TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_syslog_id ON syslog_events(id DESC);

CREATE TABLE IF NOT EXISTS watchdog_pings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_ip TEXT NOT NULL,
    online INTEGER NOT NULL,
    latency_ms REAL,
    checked_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS http_monitors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    url TEXT NOT NULL UNIQUE,
    last_status_code INTEGER,
    last_latency_ms REAL,
    ssl_days_remaining INTEGER,
    ssl_issuer TEXT NOT NULL DEFAULT '',
    last_error TEXT,
    last_checked_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL DEFAULT 'viewer',
    salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    actor TEXT NOT NULL,
    role TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_id ON audit_logs(id DESC);

CREATE TABLE IF NOT EXISTS sensors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    vlan TEXT NOT NULL DEFAULT '',
    api_key_hash TEXT NOT NULL UNIQUE,
    last_seen TEXT,
    events_received INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ioc_indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'manual',
    severity TEXT NOT NULL DEFAULT 'critical',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ipam_reservations (
    ip TEXT PRIMARY KEY,
    hostname TEXT NOT NULL DEFAULT '',
    mac TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS config_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    source_ip TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'open',
    alert_count INTEGER NOT NULL DEFAULT 1,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS playbooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    trigger_severity TEXT NOT NULL DEFAULT 'critical',
    trigger_detector TEXT NOT NULL DEFAULT 'any',
    action_type TEXT NOT NULL DEFAULT 'create_incident',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);
"""


class Database:
    """Async SQLite repository implementing fail-closed persistence."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._initialized = False

    async def initialize(self) -> None:
        """Create database directory, tables, and WAL pragmas."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        async with self.connection() as conn:
            await conn.execute("PRAGMA journal_mode=WAL;")
            await conn.execute("PRAGMA foreign_keys=ON;")
            await conn.executescript(SCHEMA_SQL)
            cursor = await conn.execute("PRAGMA table_info(devices)")
            cols = {row["name"] for row in await cursor.fetchall()}
            if "custom_name" not in cols:
                await conn.execute(
                    "ALTER TABLE devices ADD COLUMN custom_name TEXT NOT NULL DEFAULT ''"
                )
            if "trusted" not in cols:
                await conn.execute(
                    "ALTER TABLE devices ADD COLUMN trusted INTEGER NOT NULL DEFAULT 0"
                )
            if "device_type" not in cols:
                await conn.execute(
                    "ALTER TABLE devices ADD COLUMN device_type TEXT NOT NULL DEFAULT 'unknown'"
                )
            if "os_guess" not in cols:
                await conn.execute(
                    "ALTER TABLE devices ADD COLUMN os_guess TEXT NOT NULL DEFAULT 'Unknown'"
                )
            snmp_cur = await conn.execute("PRAGMA table_info(snmp_targets)")
            snmp_cols = {row["name"] for row in await snmp_cur.fetchall()}
            for col_name, col_def in (
                ("snmp_version", "TEXT NOT NULL DEFAULT 'v2c'"),
                ("v3_username", "TEXT NOT NULL DEFAULT ''"),
                ("v3_auth_key", "TEXT NOT NULL DEFAULT ''"),
                ("v3_priv_key", "TEXT NOT NULL DEFAULT ''"),
            ):
                if col_name not in snmp_cols:
                    await conn.execute(f"ALTER TABLE snmp_targets ADD COLUMN {col_name} {col_def}")
            await conn.commit()
        self._initialized = True

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[aiosqlite.Connection]:
        """Open an async SQLite connection with Row factory."""
        conn = await aiosqlite.connect(self.db_path)
        conn.row_factory = aiosqlite.Row
        try:
            yield conn
        finally:
            await conn.close()

    async def healthcheck(self) -> bool:
        """Verify database availability (Fail-Closed probe)."""
        async with self.connection() as conn:
            cursor = await conn.execute("SELECT 1;")
            row = await cursor.fetchone()
            return row is not None and row[0] == 1

    # --- Devices ---
    async def upsert_device(
        self,
        *,
        ip: str,
        mac: str,
        vendor: str,
        hostname: str,
        latency_ms: float | None,
        open_ports: list[dict[str, Any]],
        status: str = "online",
        os_guess: str = "Unknown",
    ) -> dict[str, Any]:
        now = utc_now_iso()
        ports_json = json.dumps(open_ports, ensure_ascii=False)
        async with self.connection() as conn:
            cur = await conn.execute(
                "SELECT ip, mac, trusted, custom_name FROM devices WHERE ip = ?", (ip,)
            )
            existing = await cur.fetchone()
            is_new = existing is None
            trusted = bool(existing["trusted"]) if existing else False
            prev_mac = str(existing["mac"]) if existing else ""
            mac_conflict = bool(
                existing and mac and prev_mac and prev_mac.upper() != mac.upper()
            )

            await conn.execute(
                """
                INSERT INTO devices (ip, mac, vendor, hostname, os_guess, latency_ms, open_ports_json, status, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    mac = CASE WHEN excluded.mac != '' THEN excluded.mac ELSE devices.mac END,
                    vendor = CASE WHEN excluded.vendor != 'Unknown' THEN excluded.vendor ELSE devices.vendor END,
                    hostname = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE devices.hostname END,
                    os_guess = CASE WHEN excluded.os_guess != 'Unknown' THEN excluded.os_guess ELSE devices.os_guess END,
                    latency_ms = excluded.latency_ms,
                    open_ports_json = excluded.open_ports_json,
                    status = excluded.status,
                    last_seen = excluded.last_seen
                """,
                (ip, mac, vendor, hostname, os_guess, latency_ms, ports_json, status, now, now),
            )
            await conn.execute(
                "INSERT INTO device_history (ip, status, latency_ms, recorded_at) VALUES (?, ?, ?, ?)",
                (ip, status, latency_ms, now),
            )
            await conn.execute(
                """
                DELETE FROM device_history
                WHERE id NOT IN (SELECT id FROM device_history ORDER BY id DESC LIMIT 5000)
                """
            )
            await conn.commit()
        return {"is_new": is_new, "trusted": trusted, "mac_conflict": mac_conflict, "previous_mac": prev_mac}

    async def get_device(self, ip: str) -> dict[str, Any] | None:
        async with self.connection() as conn:
            cur = await conn.execute("SELECT * FROM devices WHERE ip = ?", (ip,))
            row = await cur.fetchone()
        if row is None:
            return None
        item = dict(row)
        item["trusted"] = bool(item.get("trusted", 0))
        try:
            item["open_ports"] = json.loads(item.pop("open_ports_json", "[]"))
        except json.JSONDecodeError:
            item["open_ports"] = []
        return item

    async def update_device_metadata(
        self,
        ip: str,
        *,
        custom_name: str | None = None,
        trusted: bool | None = None,
        device_type: str | None = None,
    ) -> dict[str, Any] | None:
        async with self.connection() as conn:
            cur = await conn.execute("SELECT * FROM devices WHERE ip = ?", (ip,))
            row = await cur.fetchone()
            if row is None:
                return None
            new_name = custom_name.strip() if custom_name is not None else row["custom_name"]
            new_trusted = int(trusted) if trusted is not None else row["trusted"]
            new_type = device_type.strip() if device_type is not None else row["device_type"]
            await conn.execute(
                "UPDATE devices SET custom_name = ?, trusted = ?, device_type = ? WHERE ip = ?",
                (new_name, new_trusted, new_type, ip),
            )
            await conn.commit()
        return await self.get_device(ip)

    async def get_device_history(self, ip: str, limit: int = 60) -> list[dict[str, Any]]:
        safe_limit = max(1, min(limit, 240))
        async with self.connection() as conn:
            cur = await conn.execute(
                "SELECT id, ip, status, latency_ms, recorded_at FROM device_history WHERE ip = ? ORDER BY id DESC LIMIT ?",
                (ip, safe_limit),
            )
            rows = await cur.fetchall()
        return [dict(r) for r in reversed(rows)]

    async def mark_devices_offline_except(self, online_ips: set[str]) -> None:
        now = utc_now_iso()
        async with self.connection() as conn:
            if not online_ips:
                cur = await conn.execute("SELECT ip FROM devices WHERE status = 'online'")
                to_offline = [r["ip"] for r in await cur.fetchall()]
                await conn.execute("UPDATE devices SET status = 'offline'")
            else:
                placeholders = ",".join("?" for _ in online_ips)
                cur = await conn.execute(
                    f"SELECT ip FROM devices WHERE status = 'online' AND ip NOT IN ({placeholders})",
                    tuple(online_ips),
                )
                to_offline = [r["ip"] for r in await cur.fetchall()]
                await conn.execute(
                    f"UPDATE devices SET status = 'offline' WHERE ip NOT IN ({placeholders})",
                    tuple(online_ips),
                )
            for offline_ip in to_offline:
                await conn.execute(
                    "INSERT INTO device_history (ip, status, latency_ms, recorded_at) VALUES (?, 'offline', NULL, ?)",
                    (offline_ip, now),
                )
            await conn.commit()

    async def list_devices(self, limit: int = 512) -> list[dict[str, Any]]:
        safe_limit = max(1, min(limit, 2048))
        async with self.connection() as conn:
            cursor = await conn.execute(
                """
                SELECT d.ip, d.mac, d.vendor, d.hostname, d.custom_name, d.trusted, d.device_type,
                       d.os_guess, d.latency_ms, d.open_ports_json, d.status, d.first_seen, d.last_seen,
                       COALESCE(
                           ROUND(100.0 * SUM(CASE WHEN h.status = 'online' THEN 1 ELSE 0 END) / NULLIF(COUNT(h.id), 0), 1),
                           100.0
                       ) AS uptime_pct
                FROM devices d
                LEFT JOIN device_history h ON h.ip = d.ip
                GROUP BY d.ip
                ORDER BY d.status DESC, d.last_seen DESC
                LIMIT ?
                """,
                (safe_limit,),
            )
            rows = await cursor.fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["trusted"] = bool(item.get("trusted", 0))
            try:
                item["open_ports"] = json.loads(item.pop("open_ports_json", "[]"))
            except json.JSONDecodeError:
                item["open_ports"] = []
            results.append(item)
        return results

    # --- Alerts ---
    async def insert_alert(
        self,
        *,
        source_ip: str,
        dest_ip: str = "",
        src_port: int | None = None,
        dest_port: int | None = None,
        protocol: str = "ANY",
        rule_sid: int | None = None,
        title: str,
        description: str,
        severity: str,
        detector_type: str,
        action_taken: str = "logged",
        timestamp: str | None = None,
    ) -> dict[str, Any]:
        ts = timestamp or utc_now_iso()
        async with self.connection() as conn:
            cursor = await conn.execute(
                """
                INSERT INTO alerts (
                    timestamp, source_ip, dest_ip, src_port, dest_port, protocol,
                    rule_sid, title, description, severity, detector_type, action_taken
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    source_ip,
                    dest_ip,
                    src_port,
                    dest_port,
                    protocol,
                    rule_sid,
                    title,
                    description,
                    severity,
                    detector_type,
                    action_taken,
                ),
            )
            await conn.commit()
            alert_id = cursor.lastrowid
        return {
            "id": alert_id,
            "timestamp": ts,
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "src_port": src_port,
            "dest_port": dest_port,
            "protocol": protocol,
            "rule_sid": rule_sid,
            "title": title,
            "description": description,
            "severity": severity,
            "detector_type": detector_type,
            "action_taken": action_taken,
        }

    async def list_alerts(
        self, limit: int = 100, offset: int = 0, severity: str | None = None
    ) -> list[dict[str, Any]]:
        safe_limit = max(1, min(limit, 500))
        safe_offset = max(0, offset)
        async with self.connection() as conn:
            if severity and severity != "all":
                cursor = await conn.execute(
                    """
                    SELECT * FROM alerts
                    WHERE severity = ?
                    ORDER BY id DESC
                    LIMIT ? OFFSET ?
                    """,
                    (severity, safe_limit, safe_offset),
                )
            else:
                cursor = await conn.execute(
                    """
                    SELECT * FROM alerts
                    ORDER BY id DESC
                    LIMIT ? OFFSET ?
                    """,
                    (safe_limit, safe_offset),
                )
            rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def clear_alerts(self) -> int:
        async with self.connection() as conn:
            cursor = await conn.execute("DELETE FROM alerts")
            await conn.commit()
            return cursor.rowcount or 0

    async def count_alerts(self) -> dict[str, int]:
        async with self.connection() as conn:
            cursor = await conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"
            )
            rows = await cursor.fetchall()
        counts = {"total": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
        for row in rows:
            sev = str(row["severity"]).lower()
            cnt = int(row["cnt"])
            counts["total"] += cnt
            if sev in counts:
                counts[sev] = cnt
        return counts

    async def count_alerts_by_source_ip(self) -> dict[str, int]:
        async with self.connection() as conn:
            cursor = await conn.execute(
                "SELECT source_ip, COUNT(*) as cnt FROM alerts GROUP BY source_ip"
            )
            rows = await cursor.fetchall()
        return {str(row["source_ip"]): int(row["cnt"]) for row in rows}

    # --- SNMP Targets & Metrics ---
    async def list_snmp_targets(self) -> list[dict[str, Any]]:
        async with self.connection() as conn:
            cursor = await conn.execute(
                """
                SELECT id, name, host, community, port, snmp_version, v3_username, v3_auth_key, v3_priv_key, enabled, created_at
                FROM snmp_targets ORDER BY id ASC
                """
            )
            rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def create_snmp_target(
        self,
        *,
        name: str,
        host: str,
        community: str = "public",
        port: int = 161,
        snmp_version: str = "v2c",
        v3_username: str = "",
        v3_auth_key: str = "",
        v3_priv_key: str = "",
    ) -> dict[str, Any]:
        now = utc_now_iso()
        async with self.connection() as conn:
            cursor = await conn.execute(
                """
                INSERT INTO snmp_targets (name, host, community, port, snmp_version, v3_username, v3_auth_key, v3_priv_key, enabled, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (name, host, community, port, snmp_version, v3_username, v3_auth_key, v3_priv_key, now),
            )
            await conn.commit()
            target_id = cursor.lastrowid
        return {
            "id": target_id,
            "name": name,
            "host": host,
            "community": community,
            "port": port,
            "snmp_version": snmp_version,
            "v3_username": v3_username,
            "enabled": 1,
            "created_at": now,
        }

    async def delete_snmp_target(self, target_id: int) -> bool:
        async with self.connection() as conn:
            cursor = await conn.execute("DELETE FROM snmp_targets WHERE id = ?", (target_id,))
            await conn.commit()
            return (cursor.rowcount or 0) > 0

    async def insert_snmp_metric(
        self,
        *,
        target_id: int | None,
        target_name: str,
        cpu_pct: float | None,
        mem_pct: float | None,
        in_bps: float,
        out_bps: float,
        source_type: str,
    ) -> dict[str, Any]:
        ts = utc_now_iso()
        async with self.connection() as conn:
            cursor = await conn.execute(
                """
                INSERT INTO snmp_metrics (target_id, target_name, timestamp, cpu_pct, mem_pct, in_bps, out_bps, source_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (target_id, target_name, ts, cpu_pct, mem_pct, in_bps, out_bps, source_type),
            )
            await conn.execute(
                """
                DELETE FROM snmp_metrics
                WHERE id NOT IN (SELECT id FROM snmp_metrics ORDER BY id DESC LIMIT 2000)
                """
            )
            await conn.commit()
            row_id = cursor.lastrowid
        return {
            "id": row_id,
            "target_id": target_id,
            "target_name": target_name,
            "timestamp": ts,
            "cpu_pct": cpu_pct,
            "mem_pct": mem_pct,
            "in_bps": in_bps,
            "out_bps": out_bps,
            "source_type": source_type,
        }

    async def list_snmp_metrics(self, limit: int = 60) -> list[dict[str, Any]]:
        safe_limit = max(1, min(limit, 300))
        async with self.connection() as conn:
            cursor = await conn.execute(
                """
                SELECT * FROM snmp_metrics
                ORDER BY id DESC
                LIMIT ?
                """,
                (safe_limit,),
            )
            rows = await cursor.fetchall()
        return [dict(row) for row in reversed(rows)]

    # --- Blocked IPs ---
    async def upsert_blocked_ip(
        self,
        *,
        ip: str,
        reason: str,
        expires_at: str | None,
        is_dry_run: bool,
        active: bool = True,
    ) -> dict[str, Any]:
        now = utc_now_iso()
        async with self.connection() as conn:
            await conn.execute(
                """
                INSERT INTO blocked_ips (ip, reason, blocked_at, expires_at, is_dry_run, active)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    reason = excluded.reason,
                    blocked_at = excluded.blocked_at,
                    expires_at = excluded.expires_at,
                    is_dry_run = excluded.is_dry_run,
                    active = excluded.active
                """,
                (ip, reason, now, expires_at, int(is_dry_run), int(active)),
            )
            await conn.commit()
        return {
            "ip": ip,
            "reason": reason,
            "blocked_at": now,
            "expires_at": expires_at,
            "is_dry_run": bool(is_dry_run),
            "active": bool(active),
        }

    async def deactivate_blocked_ip(self, ip: str) -> bool:
        async with self.connection() as conn:
            cursor = await conn.execute(
                "UPDATE blocked_ips SET active = 0 WHERE ip = ? AND active = 1", (ip,)
            )
            await conn.commit()
            return (cursor.rowcount or 0) > 0

    async def list_blocked_ips(self, active_only: bool = False) -> list[dict[str, Any]]:
        async with self.connection() as conn:
            if active_only:
                cursor = await conn.execute(
                    "SELECT * FROM blocked_ips WHERE active = 1 ORDER BY blocked_at DESC LIMIT 500"
                )
            else:
                cursor = await conn.execute(
                    "SELECT * FROM blocked_ips ORDER BY active DESC, blocked_at DESC LIMIT 500"
                )
            rows = await cursor.fetchall()
        return [
            {
                **dict(row),
                "is_dry_run": bool(row["is_dry_run"]),
                "active": bool(row["active"]),
            }
            for row in rows
        ]

    # --- Persistent App Settings ---
    async def get_setting(self, key: str, default: Any = None) -> Any:
        async with self.connection() as conn:
            cursor = await conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,))
            row = await cursor.fetchone()
        if row is None:
            return default
        try:
            return json.loads(row["value"])
        except json.JSONDecodeError:
            return row["value"]

    async def set_setting(self, key: str, value: Any) -> None:
        now = utc_now_iso()
        serialized = json.dumps(value, ensure_ascii=False)
        async with self.connection() as conn:
            await conn.execute(
                """
                INSERT INTO app_settings (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at
                """,
                (key, serialized, now),
            )
            await conn.commit()

    # --- Syslog & Internet Watchdog ---
    async def insert_syslog_event(
        self, *, source_ip: str, severity: str, facility: str, message: str
    ) -> dict[str, Any]:
        ts = utc_now_iso()
        async with self.connection() as conn:
            cur = await conn.execute(
                "INSERT INTO syslog_events (received_at, source_ip, severity, facility, message) VALUES (?, ?, ?, ?, ?)",
                (ts, source_ip, severity, facility, message[:1000]),
            )
            await conn.execute(
                "DELETE FROM syslog_events WHERE id NOT IN (SELECT id FROM syslog_events ORDER BY id DESC LIMIT 1000)"
            )
            await conn.commit()
            row_id = cur.lastrowid
        return {
            "id": row_id,
            "received_at": ts,
            "source_ip": source_ip,
            "severity": severity,
            "facility": facility,
            "message": message[:1000],
        }

    async def list_syslog_events(self, limit: int = 100) -> list[dict[str, Any]]:
        safe_limit = max(1, min(limit, 500))
        async with self.connection() as conn:
            cur = await conn.execute(
                "SELECT * FROM syslog_events ORDER BY id DESC LIMIT ?", (safe_limit,)
            )
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def insert_watchdog_ping(
        self, *, target_ip: str, online: bool, latency_ms: float | None
    ) -> dict[str, Any]:
        ts = utc_now_iso()
        async with self.connection() as conn:
            cur = await conn.execute(
                "INSERT INTO watchdog_pings (target_ip, online, latency_ms, checked_at) VALUES (?, ?, ?, ?)",
                (target_ip, int(online), latency_ms, ts),
            )
            await conn.execute(
                "DELETE FROM watchdog_pings WHERE id NOT IN (SELECT id FROM watchdog_pings ORDER BY id DESC LIMIT 500)"
            )
            await conn.commit()
            row_id = cur.lastrowid
        return {
            "id": row_id,
            "target_ip": target_ip,
            "online": online,
            "latency_ms": latency_ms,
            "checked_at": ts,
        }

    async def list_watchdog_pings(self, limit: int = 40) -> list[dict[str, Any]]:
        safe_limit = max(1, min(limit, 200))
        async with self.connection() as conn:
            cur = await conn.execute(
                "SELECT * FROM watchdog_pings ORDER BY id DESC LIMIT ?", (safe_limit,)
            )
            rows = await cur.fetchall()
        return [{**dict(r), "online": bool(r["online"])} for r in reversed(rows)]

    # --- HTTP / SSL Monitors ---
    async def list_http_monitors(self) -> list[dict[str, Any]]:
        async with self.connection() as conn:
            cur = await conn.execute("SELECT * FROM http_monitors ORDER BY id ASC")
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def create_http_monitor(self, *, name: str, url: str) -> dict[str, Any]:
        now = utc_now_iso()
        async with self.connection() as conn:
            cur = await conn.execute(
                "INSERT INTO http_monitors (name, url, created_at) VALUES (?, ?, ?)",
                (name, url, now),
            )
            await conn.commit()
            row_id = cur.lastrowid
        return {
            "id": row_id,
            "name": name,
            "url": url,
            "last_status_code": None,
            "last_latency_ms": None,
            "ssl_days_remaining": None,
            "ssl_issuer": "",
            "last_error": None,
            "last_checked_at": None,
            "created_at": now,
        }

    async def get_http_monitor(self, monitor_id: int) -> dict[str, Any] | None:
        async with self.connection() as conn:
            cur = await conn.execute("SELECT * FROM http_monitors WHERE id = ?", (monitor_id,))
            row = await cur.fetchone()
        return dict(row) if row else None

    async def update_http_monitor_check(
        self,
        monitor_id: int,
        *,
        status_code: int | None,
        latency_ms: float | None,
        ssl_days_remaining: int | None,
        ssl_issuer: str,
        last_error: str | None,
    ) -> dict[str, Any] | None:
        now = utc_now_iso()
        async with self.connection() as conn:
            await conn.execute(
                """
                UPDATE http_monitors
                SET last_status_code = ?, last_latency_ms = ?, ssl_days_remaining = ?,
                    ssl_issuer = ?, last_error = ?, last_checked_at = ?
                WHERE id = ?
                """,
                (status_code, latency_ms, ssl_days_remaining, ssl_issuer, last_error, now, monitor_id),
            )
            await conn.commit()
        return await self.get_http_monitor(monitor_id)

    async def delete_http_monitor(self, monitor_id: int) -> bool:
        async with self.connection() as conn:
            cur = await conn.execute("DELETE FROM http_monitors WHERE id = ?", (monitor_id,))
            await conn.commit()
            return (cur.rowcount or 0) > 0

    # --- RBAC Users, Audit Trail, Sensors & Retention ---
    async def create_user(
        self, *, username: str, role: str, salt: str, password_hash: str
    ) -> dict[str, Any]:
        now = utc_now_iso()
        async with self.connection() as conn:
            cur = await conn.execute(
                "INSERT INTO users (username, role, salt, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
                (username, role, salt, password_hash, now),
            )
            await conn.commit()
            uid = cur.lastrowid
        return {"id": uid, "username": username, "role": role, "created_at": now}

    async def get_user_auth(self, username: str) -> dict[str, Any] | None:
        async with self.connection() as conn:
            cur = await conn.execute("SELECT * FROM users WHERE username = ?", (username,))
            row = await cur.fetchone()
        return dict(row) if row else None

    async def list_users(self) -> list[dict[str, Any]]:
        async with self.connection() as conn:
            cur = await conn.execute(
                "SELECT id, username, role, created_at FROM users ORDER BY id ASC"
            )
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def delete_user(self, username: str) -> bool:
        async with self.connection() as conn:
            cur = await conn.execute("DELETE FROM users WHERE username = ?", (username,))
            await conn.commit()
            return (cur.rowcount or 0) > 0

    async def append_audit_log(
        self, *, actor: str, role: str, action: str, target: str = "", detail: str = ""
    ) -> dict[str, Any]:
        ts = utc_now_iso()
        async with self.connection() as conn:
            cur = await conn.execute(
                "INSERT INTO audit_logs (timestamp, actor, role, action, target, detail) VALUES (?, ?, ?, ?, ?, ?)",
                (ts, actor, role, action, target[:128], detail[:400]),
            )
            await conn.commit()
            row_id = cur.lastrowid
        return {
            "id": row_id,
            "timestamp": ts,
            "actor": actor,
            "role": role,
            "action": action,
            "target": target[:128],
            "detail": detail[:400],
        }

    async def list_audit_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        safe_limit = max(1, min(limit, 500))
        async with self.connection() as conn:
            cur = await conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (safe_limit,))
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def create_sensor(self, *, name: str, vlan: str, api_key_hash: str) -> dict[str, Any]:
        now = utc_now_iso()
        async with self.connection() as conn:
            cur = await conn.execute(
                "INSERT INTO sensors (name, vlan, api_key_hash, created_at) VALUES (?, ?, ?, ?)",
                (name, vlan, api_key_hash, now),
            )
            await conn.commit()
            sid = cur.lastrowid
        return {"id": sid, "name": name, "vlan": vlan, "events_received": 0, "created_at": now}

    async def list_sensors(self) -> list[dict[str, Any]]:
        async with self.connection() as conn:
            cur = await conn.execute(
                "SELECT id, name, vlan, last_seen, events_received, created_at FROM sensors ORDER BY id ASC"
            )
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def authenticate_sensor(self, api_key_hash: str) -> dict[str, Any] | None:
        async with self.connection() as conn:
            cur = await conn.execute(
                "SELECT id, name, vlan, events_received FROM sensors WHERE api_key_hash = ?",
                (api_key_hash,),
            )
            row = await cur.fetchone()
            if row is None:
                return None
            now = utc_now_iso()
            await conn.execute(
                "UPDATE sensors SET last_seen = ?, events_received = events_received + 1 WHERE id = ?",
                (now, row["id"]),
            )
            await conn.commit()
            return dict(row)

    async def delete_sensor(self, sensor_id: int) -> bool:
        async with self.connection() as conn:
            cur = await conn.execute("DELETE FROM sensors WHERE id = ?", (sensor_id,))
            await conn.commit()
            return (cur.rowcount or 0) > 0

    async def purge_old_records(self, retention_days: int) -> dict[str, int]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max(1, retention_days))).isoformat()
        deleted: dict[str, int] = {}
        async with self.connection() as conn:
            for table, col in (
                ("alerts", "timestamp"),
                ("syslog_events", "received_at"),
                ("device_history", "recorded_at"),
                ("snmp_metrics", "timestamp"),
                ("watchdog_pings", "checked_at"),
            ):
                cur = await conn.execute(f"DELETE FROM {table} WHERE {col} < ?", (cutoff,))
                deleted[table] = cur.rowcount or 0
            await conn.commit()
        return deleted

    # --- IOCs, IPAM, Snapshots, Incidents & Playbooks ---
    async def upsert_ioc(
        self, *, indicator: str, kind: str, source: str = "manual", severity: str = "critical"
    ) -> None:
        now = utc_now_iso()
        async with self.connection() as conn:
            await conn.execute(
                """
                INSERT INTO ioc_indicators (indicator, kind, source, severity, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(indicator) DO UPDATE SET
                    source = excluded.source,
                    severity = excluded.severity
                """,
                (indicator, kind, source, severity, now),
            )
            await conn.commit()

    async def list_iocs(self, limit: int = 500) -> list[dict[str, Any]]:
        safe_limit = max(1, min(limit, 5000))
        async with self.connection() as conn:
            cur = await conn.execute(
                "SELECT * FROM ioc_indicators ORDER BY id DESC LIMIT ?", (safe_limit,)
            )
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def delete_ioc(self, ioc_id: int) -> bool:
        async with self.connection() as conn:
            cur = await conn.execute("DELETE FROM ioc_indicators WHERE id = ?", (ioc_id,))
            await conn.commit()
            return (cur.rowcount or 0) > 0

    async def upsert_ipam_reservation(
        self, *, ip: str, hostname: str, mac: str, note: str
    ) -> dict[str, Any]:
        now = utc_now_iso()
        async with self.connection() as conn:
            await conn.execute(
                """
                INSERT INTO ipam_reservations (ip, hostname, mac, note, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    hostname = excluded.hostname,
                    mac = excluded.mac,
                    note = excluded.note
                """,
                (ip, hostname, mac, note, now),
            )
            await conn.commit()
        return {"ip": ip, "hostname": hostname, "mac": mac, "note": note, "created_at": now}

    async def list_ipam_reservations(self) -> list[dict[str, Any]]:
        async with self.connection() as conn:
            cur = await conn.execute("SELECT * FROM ipam_reservations ORDER BY ip ASC")
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def delete_ipam_reservation(self, ip: str) -> bool:
        async with self.connection() as conn:
            cur = await conn.execute("DELETE FROM ipam_reservations WHERE ip = ?", (ip,))
            await conn.commit()
            return (cur.rowcount or 0) > 0

    async def insert_config_snapshot(
        self, *, name: str, sha256: str, content: str
    ) -> dict[str, Any]:
        now = utc_now_iso()
        async with self.connection() as conn:
            cur = await conn.execute(
                "INSERT INTO config_snapshots (name, sha256, content, created_at) VALUES (?, ?, ?, ?)",
                (name, sha256, content, now),
            )
            await conn.execute(
                "DELETE FROM config_snapshots WHERE id NOT IN (SELECT id FROM config_snapshots ORDER BY id DESC LIMIT 100)"
            )
            await conn.commit()
            sid = cur.lastrowid
        return {"id": sid, "name": name, "sha256": sha256, "content": content, "created_at": now}

    async def list_config_snapshots(self, limit: int = 30) -> list[dict[str, Any]]:
        safe_limit = max(1, min(limit, 100))
        async with self.connection() as conn:
            cur = await conn.execute(
                "SELECT * FROM config_snapshots ORDER BY id DESC LIMIT ?", (safe_limit,)
            )
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def upsert_incident_for_source(
        self, *, source_ip: str, title: str, severity: str
    ) -> dict[str, Any]:
        now = utc_now_iso()
        async with self.connection() as conn:
            cur = await conn.execute(
                "SELECT * FROM incidents WHERE source_ip = ? AND status != 'resolved' ORDER BY id DESC LIMIT 1",
                (source_ip,),
            )
            existing = await cur.fetchone()
            if existing:
                new_cnt = int(existing["alert_count"]) + 1
                await conn.execute(
                    "UPDATE incidents SET alert_count = ?, updated_at = ?, severity = ? WHERE id = ?",
                    (new_cnt, now, severity, existing["id"]),
                )
                await conn.commit()
                inc_id = int(existing["id"])
            else:
                cur_ins = await conn.execute(
                    """
                    INSERT INTO incidents (title, source_ip, severity, status, alert_count, notes, created_at, updated_at)
                    VALUES (?, ?, ?, 'open', 1, '', ?, ?)
                    """,
                    (title, source_ip, severity, now, now),
                )
                await conn.commit()
                inc_id = int(cur_ins.lastrowid or 0)
            cur_get = await conn.execute("SELECT * FROM incidents WHERE id = ?", (inc_id,))
            row = await cur_get.fetchone()
        return dict(row) if row else {}

    async def list_incidents(self, limit: int = 100) -> list[dict[str, Any]]:
        safe_limit = max(1, min(limit, 300))
        async with self.connection() as conn:
            cur = await conn.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (safe_limit,))
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def update_incident(
        self, incident_id: int, *, status: str | None = None, notes: str | None = None
    ) -> dict[str, Any] | None:
        now = utc_now_iso()
        async with self.connection() as conn:
            cur = await conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
            row = await cur.fetchone()
            if row is None:
                return None
            new_status = status if status is not None else row["status"]
            new_notes = notes if notes is not None else row["notes"]
            await conn.execute(
                "UPDATE incidents SET status = ?, notes = ?, updated_at = ? WHERE id = ?",
                (new_status, new_notes, now, incident_id),
            )
            await conn.commit()
            cur2 = await conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
            updated = await cur2.fetchone()
        return dict(updated) if updated else None

    async def create_playbook(
        self, *, name: str, trigger_severity: str, trigger_detector: str, action_type: str
    ) -> dict[str, Any]:
        now = utc_now_iso()
        async with self.connection() as conn:
            cur = await conn.execute(
                """
                INSERT INTO playbooks (name, trigger_severity, trigger_detector, action_type, enabled, created_at)
                VALUES (?, ?, ?, ?, 1, ?)
                """,
                (name, trigger_severity, trigger_detector, action_type, now),
            )
            await conn.commit()
            pid = cur.lastrowid
        return {
            "id": pid,
            "name": name,
            "trigger_severity": trigger_severity,
            "trigger_detector": trigger_detector,
            "action_type": action_type,
            "enabled": 1,
            "created_at": now,
        }

    async def list_playbooks(self) -> list[dict[str, Any]]:
        async with self.connection() as conn:
            cur = await conn.execute("SELECT * FROM playbooks ORDER BY id ASC")
            rows = await cur.fetchall()
        return [{**dict(r), "enabled": bool(r["enabled"])} for r in rows]

    async def toggle_playbook(self, playbook_id: int, enabled: bool) -> bool:
        async with self.connection() as conn:
            cur = await conn.execute(
                "UPDATE playbooks SET enabled = ? WHERE id = ?", (int(enabled), playbook_id)
            )
            await conn.commit()
            return (cur.rowcount or 0) > 0

    async def delete_playbook(self, playbook_id: int) -> bool:
        async with self.connection() as conn:
            cur = await conn.execute("DELETE FROM playbooks WHERE id = ?", (playbook_id,))
            await conn.commit()
            return (cur.rowcount or 0) > 0
