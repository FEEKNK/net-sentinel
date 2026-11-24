"""System status, sniffer control, and live packet buffer endpoints."""

from __future__ import annotations

import asyncio
from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, Query

from app.api.deps import AppServices, get_services


router = APIRouter(prefix="/api/system", tags=["system"])


@router.get("/status")
async def get_system_status(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    db_ok = await services.db.healthcheck()
    alert_counts = await services.db.count_alerts()
    return {
        "db_healthy": db_ok,
        "capabilities": asdict(services.capabilities),
        "sniffer": services.sniffer.status(),
        "scanner_busy": services.scanner.is_scanning,
        "policy": services.blocker.get_policy_state(),
        "alert_counts": alert_counts,
        "rules_loaded": len(services.ids_engine.rules),
        "rule_errors": len(services.ids_engine.rule_errors),
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
