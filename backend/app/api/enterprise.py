"""Enterprise & Hospital Governance API (Safety Profiles, Medical Exclusions, Audit Trail, Multi-VLAN Sensors, Suricata)."""

from __future__ import annotations

import hashlib
import secrets
from typing import Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field

from app.api.deps import AppServices, get_services
from app.core.suricata_parser import parse_suricata_eve_lines


router = APIRouter(prefix="/api/enterprise", tags=["enterprise"])


class UpdateSafetyRequest(BaseModel):
    profile: Literal["standard", "enterprise", "hospital_safe"] | None = None
    privacy_mode: bool | None = None
    retention_days: int | None = Field(default=None, ge=1, le=3650)


class ExclusionCidrRequest(BaseModel):
    cidr: str = Field(..., min_length=3, max_length=48)


class CreateSensorRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=64)
    vlan: str = Field(default="", max_length=48)


class SuricataImportRequest(BaseModel):
    ndjson: str = Field(..., min_length=2, max_length=1_000_000)


class SensorIngestPayload(BaseModel):
    devices: list[dict[str, Any]] = Field(default_factory=list)
    suricata_eve_ndjson: str = Field(default="", max_length=1_000_000)


def _hash_sensor_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


@router.get("/safety")
async def get_safety_state(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    return services.safety_manager.get_state()


@router.put("/safety")
async def update_safety_state(
    payload: UpdateSafetyRequest,
    x_netsentinel_token: str | None = Header(default=None),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    if not services.auth_manager.has_min_role(x_netsentinel_token, "admin"):
        raise HTTPException(status_code=403, detail="Admin role required")
    actor = services.auth_manager.get_actor(x_netsentinel_token) or {"username": "local-admin", "role": "admin"}
    updated = await services.safety_manager.update_settings(
        profile=payload.profile,
        privacy_mode=payload.privacy_mode,
        retention_days=payload.retention_days,
    )
    if updated["is_hospital_safe"]:
        await services.blocker.set_policy(dry_run=True, auto_block_enabled=False)
    await services.db.append_audit_log(
        actor=actor["username"],
        role=actor["role"],
        action="update_safety_profile",
        detail=f"profile={updated['profile']}, privacy={updated['privacy_mode']}, retention={updated['retention_days']}d",
    )
    return updated


@router.post("/exclusions")
async def add_exclusion_cidr(
    payload: ExclusionCidrRequest,
    x_netsentinel_token: str | None = Header(default=None),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    if not services.auth_manager.has_min_role(x_netsentinel_token, "admin"):
        raise HTTPException(status_code=403, detail="Admin role required")
    try:
        cidrs = await services.safety_manager.add_excluded_cidr(payload.cidr)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    actor = services.auth_manager.get_actor(x_netsentinel_token) or {"username": "local-admin", "role": "admin"}
    await services.db.append_audit_log(
        actor=actor["username"],
        role=actor["role"],
        action="add_excluded_vlan",
        target=payload.cidr,
    )
    return {"excluded_cidrs": cidrs}


@router.delete("/exclusions")
async def remove_exclusion_cidr(
    cidr: str = Query(..., min_length=3, max_length=48),
    x_netsentinel_token: str | None = Header(default=None),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    if not services.auth_manager.has_min_role(x_netsentinel_token, "admin"):
        raise HTTPException(status_code=403, detail="Admin role required")
    try:
        cidrs = await services.safety_manager.remove_excluded_cidr(cidr)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"excluded_cidrs": cidrs}


@router.post("/retention/purge")
async def purge_old_logs(
    confirm: bool = Query(default=False),
    x_netsentinel_token: str | None = Header(default=None),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    if not services.auth_manager.has_min_role(x_netsentinel_token, "admin"):
        raise HTTPException(status_code=403, detail="Admin role required")
    if not confirm:
        raise HTTPException(status_code=400, detail="Confirmation required (confirm=true)")
    deleted = await services.db.purge_old_records(services.safety_manager.retention_days)
    actor = services.auth_manager.get_actor(x_netsentinel_token) or {"username": "local-admin", "role": "admin"}
    await services.db.append_audit_log(
        actor=actor["username"],
        role=actor["role"],
        action="purge_retention_logs",
        detail=f"days={services.safety_manager.retention_days}",
    )
    return {"retention_days": services.safety_manager.retention_days, "deleted": deleted}


@router.get("/audit-logs")
async def get_audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    return {"logs": await services.db.list_audit_logs(limit=limit)}


@router.get("/sensors")
async def list_sensors(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    return {"sensors": await services.db.list_sensors()}


@router.post("/sensors")
async def register_sensor(
    payload: CreateSensorRequest,
    x_netsentinel_token: str | None = Header(default=None),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    if not services.auth_manager.has_min_role(x_netsentinel_token, "admin"):
        raise HTTPException(status_code=403, detail="Admin role required")
    raw_key = f"ns_sensor_{secrets.token_urlsafe(24)}"
    sensor = await services.db.create_sensor(
        name=payload.name.strip(),
        vlan=payload.vlan.strip(),
        api_key_hash=_hash_sensor_key(raw_key),
    )
    actor = services.auth_manager.get_actor(x_netsentinel_token) or {"username": "local-admin", "role": "admin"}
    await services.db.append_audit_log(
        actor=actor["username"],
        role=actor["role"],
        action="register_vlan_sensor",
        target=sensor["name"],
    )
    return {**sensor, "api_key": raw_key}


@router.delete("/sensors/{sensor_id}")
async def delete_sensor(
    sensor_id: int,
    confirm: bool = Query(default=False),
    x_netsentinel_token: str | None = Header(default=None),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    if not services.auth_manager.has_min_role(x_netsentinel_token, "admin"):
        raise HTTPException(status_code=403, detail="Admin role required")
    if not confirm:
        raise HTTPException(status_code=400, detail="Confirmation required (confirm=true)")
    if not await services.db.delete_sensor(sensor_id):
        raise HTTPException(status_code=404, detail="Sensor not found")
    return {"deleted": True, "id": sensor_id}


@router.post("/suricata/import")
async def import_suricata_eve(
    payload: SuricataImportRequest,
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    parsed = parse_suricata_eve_lines(payload.ndjson)
    inserted = 0
    for alert in parsed["alerts"]:
        saved = await services.db.insert_alert(**alert)
        await services.hub.broadcast("alert", saved)
        inserted += 1
    return {
        "alerts_imported": inserted,
        "dns_found": len(parsed["dns"]),
        "errors": parsed["errors"],
    }


@router.post("/sensors/ingest")
async def remote_sensor_ingest(
    payload: SensorIngestPayload,
    x_sensor_key: str | None = Header(default=None),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    if not x_sensor_key:
        raise HTTPException(status_code=401, detail="X-Sensor-Key header required")
    sensor = await services.db.authenticate_sensor(_hash_sensor_key(x_sensor_key.strip()))
    if sensor is None:
        raise HTTPException(status_code=401, detail="Invalid sensor API key")

    devices_upserted = 0
    for dev in payload.devices[:256]:
        ip = str(dev.get("ip", "")).strip()
        if not ip:
            continue
        await services.db.upsert_device(
            ip=ip,
            mac=str(dev.get("mac", "")),
            vendor=str(dev.get("vendor", "Unknown")),
            hostname=str(dev.get("hostname", "")),
            latency_ms=dev.get("latency_ms"),
            open_ports=dev.get("open_ports") or [],
            status=str(dev.get("status", "online")),
            os_guess=str(dev.get("os_guess", "Unknown")),
        )
        devices_upserted += 1

    alerts_imported = 0
    if payload.suricata_eve_ndjson:
        parsed = parse_suricata_eve_lines(payload.suricata_eve_ndjson)
        for alert in parsed["alerts"][:200]:
            saved = await services.db.insert_alert(**alert)
            await services.hub.broadcast("alert", saved)
            alerts_imported += 1

    return {
        "sensor": sensor["name"],
        "devices_upserted": devices_upserted,
        "alerts_imported": alerts_imported,
    }
