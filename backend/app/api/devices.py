"""IP/Subnet scanning, trusted devices, uptime history, Wake-on-LAN, and schedule endpoints."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.api.deps import AppServices, get_services
from app.core.risk import calculate_device_risk
from app.core.scanner import parse_port_spec, validate_subnet
from app.core.wol import send_wake_on_lan
from app.platform.base import validate_ip_address


router = APIRouter(prefix="/api/devices", tags=["devices"])


class ScanRequest(BaseModel):
    cidr: str = Field(..., min_length=3, max_length=32)
    scan_ports: bool = True
    port_spec: str | None = Field(default=None, max_length=120)
    scan_udp: bool = False


class UpdateDeviceRequest(BaseModel):
    custom_name: str | None = Field(default=None, max_length=64)
    trusted: bool | None = None
    device_type: str | None = Field(default=None, max_length=24)


class WakeOnLanRequest(BaseModel):
    mac: str | None = Field(default=None, max_length=32)
    confirm: bool = False


class ScheduleUpdateRequest(BaseModel):
    enabled: bool | None = None
    interval_seconds: int | None = Field(default=None, ge=30, le=3600)
    cidr: str | None = Field(default=None, min_length=3, max_length=32)
    scan_ports: bool | None = None


@router.get("")
async def list_devices(
    limit: int = Query(default=256, ge=1, le=1024),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    devices = await services.db.list_devices(limit=limit)
    alert_counts = await services.db.count_alerts_by_source_ip()
    enriched = [
        {
            **d,
            **calculate_device_risk(d, recent_alert_count=alert_counts.get(d["ip"], 0)),
        }
        for d in devices
    ]
    return {
        "devices": enriched,
        "online_count": sum(1 for d in enriched if d.get("status") == "online"),
        "total_count": len(enriched),
        "default_subnet": services.capabilities.default_subnet,
        "schedule": asdict(services.scan_schedule),
    }


@router.get("/schedule")
async def get_scan_schedule(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    return asdict(services.scan_schedule)


@router.put("/schedule")
async def update_scan_schedule(
    payload: ScheduleUpdateRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    sched = services.scan_schedule
    if payload.cidr is not None:
        try:
            net = validate_subnet(payload.cidr, max_prefix=services.scanner.max_prefix)
            sched.cidr = str(net)
            await services.db.set_setting("auto_scan_cidr", sched.cidr)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    if payload.enabled is not None:
        sched.enabled = payload.enabled
        await services.db.set_setting("auto_scan_enabled", sched.enabled)
    if payload.interval_seconds is not None:
        sched.interval_seconds = payload.interval_seconds
        await services.db.set_setting("auto_scan_interval_seconds", sched.interval_seconds)
    if payload.scan_ports is not None:
        sched.scan_ports = payload.scan_ports
        await services.db.set_setting("auto_scan_ports", sched.scan_ports)
    return asdict(sched)


@router.post("/scan")
async def scan_subnet(
    payload: ScanRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    try:
        validate_subnet(payload.cidr, max_prefix=services.scanner.max_prefix)
        if payload.port_spec:
            parse_port_spec(payload.port_spec)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if services.scanner.is_scanning:
        raise HTTPException(status_code=409, detail="A subnet scan is already in progress")

    async def on_progress(event: dict[str, Any]) -> None:
        await services.hub.broadcast("scan_progress", event)

    try:
        summary = await services.scanner.scan_subnet(
            payload.cidr,
            scan_ports=payload.scan_ports,
            port_spec=payload.port_spec,
            scan_udp=payload.scan_udp,
            on_progress=on_progress,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return summary


@router.post("/quick-check")
async def quick_health_check(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    """1-Click Guided Health Check: scans default subnet, polls bandwidth, and checks internet watchdog."""
    if services.scanner.is_scanning:
        raise HTTPException(status_code=409, detail="A subnet scan is already in progress")

    scan_res = await services.scanner.scan_subnet(
        services.capabilities.default_subnet, scan_ports=True
    )
    watchdog_res = await services.watchdog.check_once()
    metrics = await services.snmp_monitor.poll_once()
    for m in metrics:
        await services.hub.broadcast("snmp_metric", m)

    return {
        "scan": scan_res,
        "watchdog": watchdog_res,
        "metrics_sampled": len(metrics),
    }


@router.patch("/{ip}")
async def update_device(
    ip: str, payload: UpdateDeviceRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    try:
        safe_ip = validate_ip_address(ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    updated = await services.db.update_device_metadata(
        safe_ip,
        custom_name=payload.custom_name,
        trusted=payload.trusted,
        device_type=payload.device_type,
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="Device not found")
    await services.hub.broadcast("device_updated", updated)
    return updated


@router.get("/{ip}/history")
async def get_device_history(
    ip: str,
    limit: int = Query(default=60, ge=1, le=240),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    try:
        safe_ip = validate_ip_address(ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    history = await services.db.get_device_history(safe_ip, limit=limit)
    return {"ip": safe_ip, "history": history}


@router.post("/{ip}/wol")
async def wake_device(
    ip: str, payload: WakeOnLanRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    if not payload.confirm:
        raise HTTPException(
            status_code=400,
            detail="Confirmation required (confirm=true) to send Wake-on-LAN Magic Packet",
        )
    try:
        safe_ip = validate_ip_address(ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    device = await services.db.get_device(safe_ip)
    mac = (payload.mac or (device["mac"] if device else "")).strip()
    if not mac:
        raise HTTPException(status_code=400, detail="No MAC address known for this device")

    try:
        result = send_wake_on_lan(mac, target_ip=safe_ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"sent": True, **result}
