"""Async SQLite database manager with strict parameterized queries."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
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
    latency_ms REAL,
    open_ports_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'online',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

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
    ) -> None:
        now = utc_now_iso()
        ports_json = json.dumps(open_ports, ensure_ascii=False)
        async with self.connection() as conn:
            await conn.execute(
                """
                INSERT INTO devices (ip, mac, vendor, hostname, latency_ms, open_ports_json, status, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    mac = CASE WHEN excluded.mac != '' THEN excluded.mac ELSE devices.mac END,
                    vendor = CASE WHEN excluded.vendor != 'Unknown' THEN excluded.vendor ELSE devices.vendor END,
                    hostname = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE devices.hostname END,
                    latency_ms = excluded.latency_ms,
                    open_ports_json = excluded.open_ports_json,
                    status = excluded.status,
                    last_seen = excluded.last_seen
                """,
                (ip, mac, vendor, hostname, latency_ms, ports_json, status, now, now),
            )
            await conn.commit()

    async def mark_devices_offline_except(self, online_ips: set[str]) -> None:
        async with self.connection() as conn:
            if not online_ips:
                await conn.execute("UPDATE devices SET status = 'offline'")
            else:
                placeholders = ",".join("?" for _ in online_ips)
                await conn.execute(
                    f"UPDATE devices SET status = 'offline' WHERE ip NOT IN ({placeholders})",
                    tuple(online_ips),
                )
            await conn.commit()

    async def list_devices(self, limit: int = 512) -> list[dict[str, Any]]:
        safe_limit = max(1, min(limit, 2048))
        async with self.connection() as conn:
            cursor = await conn.execute(
                """
                SELECT ip, mac, vendor, hostname, latency_ms, open_ports_json, status, first_seen, last_seen
                FROM devices
                ORDER BY status DESC, last_seen DESC
                LIMIT ?
                """,
                (safe_limit,),
            )
            rows = await cursor.fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
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

    # --- SNMP Targets & Metrics ---
    async def list_snmp_targets(self) -> list[dict[str, Any]]:
        async with self.connection() as conn:
            cursor = await conn.execute(
                "SELECT id, name, host, community, port, enabled, created_at FROM snmp_targets ORDER BY id ASC"
            )
            rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def create_snmp_target(
        self, *, name: str, host: str, community: str = "public", port: int = 161
    ) -> dict[str, Any]:
        now = utc_now_iso()
        async with self.connection() as conn:
            cursor = await conn.execute(
                """
                INSERT INTO snmp_targets (name, host, community, port, enabled, created_at)
                VALUES (?, ?, ?, ?, 1, ?)
                """,
                (name, host, community, port, now),
            )
            await conn.commit()
            target_id = cursor.lastrowid
        return {
            "id": target_id,
            "name": name,
            "host": host,
            "community": community,
            "port": port,
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
            # Keep metrics table bounded to recent 2000 rows to prevent unbounded growth
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
        # Return chronological order for charting
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
