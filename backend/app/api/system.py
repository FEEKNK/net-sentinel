"""System status, sniffer control, and live packet buffer endpoints."""

from __future__ import annotations

import asyncio
import base64
from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field

from app.api.deps import AppServices, get_services
from app.platform.base import validate_ip_address


router = APIRouter(prefix="/api/system", tags=["system"])


class PcapAnalyzeRequest(BaseModel):
    filename: str = Field(..., min_length=1, max_length=128)
    base64_data: str = Field(..., min_length=8, max_length=7_500_000)


class WatchdogConfigRequest(BaseModel):
    enabled: bool | None = None
    target_ip: str | None = Field(default=None, max_length=64)


class ThreatIntelKeyRequest(BaseModel):
    api_key: str = Field(..., max_length=160)


class ThreatIntelCheckRequest(BaseModel):
    ip: str = Field(..., min_length=3, max_length=64)


@router.get("/status")
async def get_system_status(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    db_ok = await services.db.healthcheck()
    alert_counts = await services.db.count_alerts()
    return {
        "db_healthy": db_ok,
        "capabilities": asdict(services.capabilities),
        "sniffer": services.sniffer.status(),
        "syslog": services.syslog_server.status(),
        "scanner_busy": services.scanner.is_scanning,
        "policy": services.blocker.get_policy_state(),
        "alert_counts": alert_counts,
        "rules_loaded": len(services.ids_engine.rules),
        "rule_errors": len(services.ids_engine.rule_errors),
        "lock_enabled": services.auth_manager.enabled,
    }


@router.post("/sniffer/start")
async def start_sniffer(
    interface: str | None = None, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    loop = asyncio.get_running_loop()
    clean_iface = interface.strip() if interface else None
    status = services.sniffer.start(loop=loop, interface=clean_iface)
    await services.hub.broadcast("sniffer_status", status)
    return status


@router.post("/sniffer/stop")
async def stop_sniffer(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    status = services.sniffer.stop()
    await services.hub.broadcast("sniffer_status", status)
    return status


@router.get("/packets")
async def get_recent_packets(
    limit: int = Query(default=60, ge=1, le=300),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    items = list(services.sniffer.recent_packets)[-limit:]
    items.reverse()
    return {"packets": items, "total_captured": services.sniffer.status()["packet_count"]}


@router.get("/telemetry")
async def get_traffic_telemetry(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    return services.sniffer.get_telemetry()


@router.get("/pcap/export")
async def export_pcap(services: AppServices = Depends(get_services)) -> Response:
    pcap_data = services.sniffer.export_pcap_bytes()
    return Response(
        content=pcap_data,
        media_type="application/vnd.tcpdump.pcap",
        headers={
            "Content-Disposition": 'attachment; filename="netsentinel-capture.pcap"'
        },
    )


@router.post("/pcap/analyze")
async def analyze_uploaded_pcap(
    payload: PcapAnalyzeRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    try:
        raw = base64.b64decode(payload.base64_data, validate=True)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid base64 PCAP payload") from exc
    if len(raw) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="PCAP file exceeds 5 MB limit")
    try:
        return await asyncio.to_thread(
            services.sniffer.analyze_pcap_bytes,
            raw,
            rules=services.ids_engine.rules,
            home_nets=services.ids_engine.home_nets,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/follow-stream")
async def follow_tcp_stream(
    src_ip: str = Query(...),
    src_port: int = Query(..., ge=1, le=65535),
    dst_ip: str = Query(...),
    dst_port: int = Query(..., ge=1, le=65535),
    services: AppServices = Depends(get_services),
) -> dict[str, str]:
    try:
        s_ip = validate_ip_address(src_ip)
        d_ip = validate_ip_address(dst_ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return services.ids_engine.follow_tcp_stream(s_ip, src_port, d_ip, dst_port)


@router.get("/syslog")
async def get_syslog(
    limit: int = Query(default=100, ge=1, le=500),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    events = await services.db.list_syslog_events(limit=limit)
    return {"status": services.syslog_server.status(), "events": events}


@router.post("/syslog/start")
async def start_syslog(
    port: int = Query(default=5140, ge=1024, le=65535),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    return await services.syslog_server.start(port=port)


@router.post("/syslog/stop")
async def stop_syslog(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    return services.syslog_server.stop()


@router.get("/watchdog")
async def get_watchdog(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    pings = await services.db.list_watchdog_pings(limit=40)
    return {
        "enabled": services.watchdog.enabled,
        "target_ip": services.watchdog.target_ip,
        "pings": pings,
    }


@router.put("/watchdog")
async def update_watchdog(
    payload: WatchdogConfigRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    try:
        cfg = await services.watchdog.set_config(
            enabled=payload.enabled, target_ip=payload.target_ip
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return cfg


@router.post("/watchdog/check")
async def check_watchdog_now(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    return await services.watchdog.check_once()


@router.get("/threat-intel")
async def get_threat_intel_status(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    return services.threat_intel.get_status()


@router.put("/threat-intel")
async def set_threat_intel_key(
    payload: ThreatIntelKeyRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    return await services.threat_intel.set_api_key(payload.api_key)


@router.post("/threat-intel/check")
async def check_threat_intel_ip(
    payload: ThreatIntelCheckRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    try:
        return await services.threat_intel.check_ip(payload.ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
