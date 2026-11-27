"""Network Engineering APIs: IPAM Subnet Grid, SNMP Traps, NetFlow v5, and Config Drift."""

from __future__ import annotations

import difflib
import hashlib
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.api.deps import AppServices, get_services
from app.config import settings
from app.core.scanner import validate_subnet
from app.platform.base import validate_ip_address


router = APIRouter(prefix="/api/network", tags=["network"])


class ReserveIpRequest(BaseModel):
    ip: str = Field(..., min_length=3, max_length=64)
    hostname: str = Field(default="", max_length=64)
    mac: str = Field(default="", max_length=32)
    note: str = Field(default="", max_length=120)


class CreateSnapshotRequest(BaseModel):
    name: str = Field(default="Manual Snapshot", min_length=1, max_length=64)


@router.get("/ipam")
async def get_ipam_grid(
    cidr: str = Query(default=""),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    target_cidr = cidr.strip() or services.capabilities.default_subnet
    try:
        network = validate_subnet(target_cidr, max_prefix=22)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    devices = await services.db.list_devices(limit=1024)
    dev_map = {d["ip"]: d for d in devices}
    reservations = await services.db.list_ipam_reservations()
    res_map = {r["ip"]: r for r in reservations}

    hosts = [str(ip) for ip in network.hosts()][:256]
    slots: list[dict[str, Any]] = []
    counts = {"online": 0, "offline": 0, "reserved": 0, "free": 0}

    for ip in hosts:
        dev = dev_map.get(ip)
        res = res_map.get(ip)
        if dev and dev["status"] == "online":
            state = "online"
        elif res:
            state = "reserved"
        elif dev:
            state = "offline"
        else:
            state = "free"
        counts[state] += 1
        slots.append(
            {
                "ip": ip,
                "state": state,
                "hostname": (res["hostname"] if res and res["hostname"] else (dev.get("custom_name") or dev.get("hostname", "") if dev else "")),
                "mac": (res["mac"] if res and res["mac"] else (dev.get("mac", "") if dev else "")),
                "note": res["note"] if res else "",
            }
        )

    total = max(1, len(slots))
    used = counts["online"] + counts["offline"] + counts["reserved"]
    return {
        "cidr": str(network),
        "utilization_pct": round((used / total) * 100, 1),
        "counts": counts,
        "slots": slots,
        "reservations": reservations,
    }


@router.post("/ipam/reserve")
async def reserve_ip(
    payload: ReserveIpRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    try:
        safe_ip = validate_ip_address(payload.ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return await services.db.upsert_ipam_reservation(
        ip=safe_ip,
        hostname=payload.hostname.strip(),
        mac=payload.mac.strip().upper(),
        note=payload.note.strip(),
    )


@router.delete("/ipam/reserve")
async def release_reservation(
    ip: str = Query(..., min_length=3, max_length=64),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    try:
        safe_ip = validate_ip_address(ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    deleted = await services.db.delete_ipam_reservation(safe_ip)
    return {"deleted": deleted, "ip": safe_ip}


@router.get("/traps")
async def get_snmp_traps(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    return {
        "status": services.trap_receiver.status(),
        "traps": list(services.trap_receiver.recent_traps),
    }


@router.post("/traps/start")
async def start_snmp_traps(
    port: int = Query(default=1162, ge=1024, le=65535),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    return await services.trap_receiver.start(port=port)


@router.post("/traps/stop")
async def stop_snmp_traps(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    return services.trap_receiver.stop()


@router.get("/netflow")
async def get_netflow(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    return services.netflow_collector.get_summary()


@router.post("/netflow/start")
async def start_netflow(
    port: int = Query(default=2055, ge=1024, le=65535),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    return await services.netflow_collector.start(port=port)


@router.post("/netflow/stop")
async def stop_netflow(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    return services.netflow_collector.stop()


@router.get("/snapshots")
async def list_snapshots(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    snaps = await services.db.list_config_snapshots(limit=30)
    return {"snapshots": snaps}


@router.post("/snapshots")
async def create_snapshot(
    payload: CreateSnapshotRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    rules_text = (
        settings.snort_rules_path.read_text(encoding="utf-8")
        if settings.snort_rules_path.exists()
        else ""
    )
    bundle = {
        "policy": services.blocker.get_policy_state(),
        "safety": services.safety_manager.get_state(),
        "ids_tuning": services.ids_engine.get_tuning(),
        "rules": rules_text,
    }
    serialized = json.dumps(bundle, indent=2, ensure_ascii=False, sort_keys=True)
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return await services.db.insert_config_snapshot(
        name=payload.name.strip(), sha256=digest, content=serialized
    )


@router.get("/snapshots/diff")
async def diff_snapshots(
    a_id: int = Query(...),
    b_id: int = Query(...),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    snaps = {s["id"]: s for s in await services.db.list_config_snapshots(limit=50)}
    snap_a = snaps.get(a_id)
    snap_b = snaps.get(b_id)
    if not snap_a or not snap_b:
        raise HTTPException(status_code=404, detail="Snapshot ID not found")
    diff_lines = list(
        difflib.unified_diff(
            snap_a["content"].splitlines(),
            snap_b["content"].splitlines(),
            fromfile=f"#{a_id} ({snap_a['name']})",
            tofile=f"#{b_id} ({snap_b['name']})",
            lineterm="",
        )
    )
    return {
        "drifted": snap_a["sha256"] != snap_b["sha256"],
        "diff": "\n".join(diff_lines) if diff_lines else "(No changes)",
    }
