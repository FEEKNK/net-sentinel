"""SNMPv2c & Local Host NIC Bandwidth Monitoring."""

from __future__ import annotations

import time
from typing import Any

import psutil

from app.db.database import Database


OID_IF_IN_OCTETS_1 = "1.3.6.1.2.1.2.2.1.10.1"
OID_IF_OUT_OCTETS_1 = "1.3.6.1.2.1.2.2.1.16.1"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"


class SnmpMonitor:
    """Samples local NIC throughput and optional SNMPv2c router/switch targets."""

    def __init__(self, db: Database) -> None:
        self.db = db
        self._last_local: tuple[float, int, int] | None = None
        self._last_snmp: dict[int, tuple[float, int, int]] = {}
        self.target_status: dict[int, dict[str, Any]] = {}

        # Prime psutil cpu_percent so subsequent non-blocking calls return meaningful deltas
        psutil.cpu_percent(interval=None)

    async def poll_once(self) -> list[dict[str, Any]]:
        """Sample local NIC and all enabled SNMP targets, persisting metrics to SQLite."""
        saved_metrics: list[dict[str, Any]] = []

        # 1) Local host NIC + CPU/RAM (always real OS counters)
        local_metric = await self._sample_local_host()
        if local_metric is not None:
            saved_metrics.append(local_metric)

        # 2) Configured SNMPv2c targets
        targets = await self.db.list_snmp_targets()
        for target in targets:
            if not target.get("enabled", 1):
                continue
            metric = await self._poll_snmp_target(target)
            if metric is not None:
                saved_metrics.append(metric)

        return saved_metrics

    async def _sample_local_host(self) -> dict[str, Any] | None:
        now = time.monotonic()
        counters = psutil.net_io_counters()
        cpu_pct = round(float(psutil.cpu_percent(interval=None)), 1)
        mem_pct = round(float(psutil.virtual_memory().percent), 1)

        in_bps = 0.0
        out_bps = 0.0
        if self._last_local is not None:
            prev_ts, prev_recv, prev_sent = self._last_local
            dt = max(0.1, now - prev_ts)
            delta_in = max(0, counters.bytes_recv - prev_recv)
            delta_out = max(0, counters.bytes_sent - prev_sent)
            in_bps = round((delta_in * 8.0) / dt, 1)
            out_bps = round((delta_out * 8.0) / dt, 1)

        self._last_local = (now, counters.bytes_recv, counters.bytes_sent)

        return await self.db.insert_snmp_metric(
            target_id=None,
            target_name="Local Host NIC",
            cpu_pct=cpu_pct,
            mem_pct=mem_pct,
            in_bps=in_bps,
            out_bps=out_bps,
            source_type="local_nic",
        )

    async def _poll_snmp_target(self, target: dict[str, Any]) -> dict[str, Any] | None:
        target_id = int(target["id"])
        host = str(target["host"])
        port = int(target.get("port", 161))
        community = str(target.get("community", "public"))
        target_name = str(target["name"])

        try:
            from pysnmp.hlapi.v3arch.asyncio import (  # type: ignore
                CommunityData,
                ContextData,
                ObjectIdentity,
                ObjectType,
                SnmpEngine,
                UdpTransportTarget,
                get_cmd,
            )

            engine = SnmpEngine()
            transport = await UdpTransportTarget.create((host, port), timeout=1.5, retries=0)
            error_indication, error_status, _, var_binds = await get_cmd(
                engine,
                CommunityData(community, mpModel=1),
                transport,
                ContextData(),
                ObjectType(ObjectIdentity(OID_SYS_NAME)),
                ObjectType(ObjectIdentity(OID_IF_IN_OCTETS_1)),
                ObjectType(ObjectIdentity(OID_IF_OUT_OCTETS_1)),
            )
            if error_indication or error_status:
                err_msg = str(error_indication or error_status)
                self.target_status[target_id] = {"status": "error", "message": err_msg}
                return None

            sys_name = str(var_binds[0][1]) if len(var_binds) > 0 else target_name
            in_octets = int(var_binds[1][1]) if len(var_binds) > 1 else 0
            out_octets = int(var_binds[2][1]) if len(var_binds) > 2 else 0

            now = time.monotonic()
            in_bps = 0.0
            out_bps = 0.0
            prev = self._last_snmp.get(target_id)
            if prev is not None:
                prev_ts, prev_in, prev_out = prev
                dt = max(0.1, now - prev_ts)
                if in_octets >= prev_in:
                    in_bps = round(((in_octets - prev_in) * 8.0) / dt, 1)
                if out_octets >= prev_out:
                    out_bps = round(((out_octets - prev_out) * 8.0) / dt, 1)
            self._last_snmp[target_id] = (now, in_octets, out_octets)
            self.target_status[target_id] = {"status": "online", "sys_name": sys_name}

            return await self.db.insert_snmp_metric(
                target_id=target_id,
                target_name=target_name,
                cpu_pct=None,
                mem_pct=None,
                in_bps=in_bps,
                out_bps=out_bps,
                source_type="snmp_v2c",
            )
        except Exception as exc:
            self.target_status[target_id] = {"status": "error", "message": str(exc)}
            return None
