"""SNMPv2c & Local Host NIC Bandwidth Monitoring."""

from __future__ import annotations

import time
from typing import Any

import psutil

from app.db.database import Database


OID_IF_DESCR_BASE = "1.3.6.1.2.1.2.2.1.2"
OID_IF_IN_BASE = "1.3.6.1.2.1.2.2.1.10"
OID_IF_OUT_BASE = "1.3.6.1.2.1.2.2.1.16"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_LLDP_REM_SYS_NAME_1 = "1.0.8802.1.1.2.1.4.1.1.9.0.1.1"
OID_LLDP_REM_PORT_ID_1 = "1.0.8802.1.1.2.1.4.1.1.7.0.1.1"


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
        snmp_version = str(target.get("snmp_version", "v2c"))
        v3_username = str(target.get("v3_username", ""))
        v3_auth_key = str(target.get("v3_auth_key", ""))
        v3_priv_key = str(target.get("v3_priv_key", ""))
        target_name = str(target["name"])

        try:
            from pysnmp.hlapi.v3arch.asyncio import (  # type: ignore
                CommunityData,
                ContextData,
                ObjectIdentity,
                ObjectType,
                SnmpEngine,
                UdpTransportTarget,
                UsmUserData,
                get_cmd,
                usmAesCfb128Protocol,
                usmHMACSHAAuthProtocol,
            )

            engine = SnmpEngine()
            transport = await UdpTransportTarget.create((host, port), timeout=1.5, retries=0)
            if snmp_version == "v3" and v3_username:
                auth_data = UsmUserData(
                    v3_username,
                    authKey=v3_auth_key or None,
                    privKey=v3_priv_key or None,
                    authProtocol=usmHMACSHAAuthProtocol if v3_auth_key else None,
                    privProtocol=usmAesCfb128Protocol if v3_priv_key else None,
                )
            else:
                auth_data = CommunityData(community, mpModel=1)

            # Query sysName + interfaces 1..4 + LLDP neighbor hint
            var_oids = [
                ObjectType(ObjectIdentity(OID_SYS_NAME)),
                ObjectType(ObjectIdentity(OID_LLDP_REM_SYS_NAME_1)),
                ObjectType(ObjectIdentity(OID_LLDP_REM_PORT_ID_1)),
            ]
            for idx in (1, 2, 3, 4):
                var_oids.append(ObjectType(ObjectIdentity(f"{OID_IF_DESCR_BASE}.{idx}")))
                var_oids.append(ObjectType(ObjectIdentity(f"{OID_IF_IN_BASE}.{idx}")))
                var_oids.append(ObjectType(ObjectIdentity(f"{OID_IF_OUT_BASE}.{idx}")))

            error_indication, error_status, _, var_binds = await get_cmd(
                engine,
                auth_data,
                transport,
                ContextData(),
                *var_oids,
            )
            if error_indication or error_status:
                err_msg = str(error_indication or error_status)
                self.target_status[target_id] = {"status": "error", "message": err_msg}
                return None

            sys_name = str(var_binds[0][1]) if len(var_binds) > 0 else target_name
            lldp_sys = str(var_binds[1][1]) if len(var_binds) > 1 else ""
            lldp_port = str(var_binds[2][1]) if len(var_binds) > 2 else ""
            interfaces: list[dict[str, Any]] = []
            total_in = 0
            total_out = 0
            for i, idx in enumerate((1, 2, 3, 4)):
                base = 3 + i * 3
                if base + 2 >= len(var_binds):
                    break
                descr = str(var_binds[base][1])
                in_raw = var_binds[base + 1][1]
                out_raw = var_binds[base + 2][1]
                try:
                    in_val = int(in_raw)
                    out_val = int(out_raw)
                except (ValueError, TypeError):
                    continue
                total_in += in_val
                total_out += out_val
                interfaces.append({"index": idx, "name": descr, "in_octets": in_val, "out_octets": out_val})

            now = time.monotonic()
            in_bps = 0.0
            out_bps = 0.0
            prev = self._last_snmp.get(target_id)
            if prev is not None:
                prev_ts, prev_in, prev_out = prev
                dt = max(0.1, now - prev_ts)
                if total_in >= prev_in:
                    in_bps = round(((total_in - prev_in) * 8.0) / dt, 1)
                if total_out >= prev_out:
                    out_bps = round(((total_out - prev_out) * 8.0) / dt, 1)
            self._last_snmp[target_id] = (now, total_in, total_out)
            lldp_neighbors = (
                [{"system": lldp_sys, "port": lldp_port}]
                if lldp_sys and "No Such" not in lldp_sys
                else []
            )
            self.target_status[target_id] = {
                "status": "online",
                "sys_name": sys_name,
                "interfaces": interfaces,
                "lldp_neighbors": lldp_neighbors,
            }

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
