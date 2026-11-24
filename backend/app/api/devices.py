"""IP/Subnet scanning and discovered devices endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.api.deps import AppServices, get_services
from app.core.scanner import validate_subnet


router = APIRouter(prefix="/api/devices", tags=["devices"])


class ScanRequest(BaseModel):
    cidr: str = Field(..., min_length=3, max_length=32)
    scan_ports: bool = True


@router.get("")
async def list_devices(
    limit: int = Query(default=256, ge=1, le=1024),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    devices = await services.db.list_devices(limit=limit)
    return {
        "devices": devices,
        "online_count": sum(1 for d in devices if d.get("status") == "online"),
        "total_count": len(devices),
        "default_subnet": services.capabilities.default_subnet,
    }


@router.post("/scan")
async def scan_subnet(
    payload: ScanRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    try:
        validate_subnet(payload.cidr, max_prefix=services.scanner.max_prefix)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if services.scanner.is_scanning:
        raise HTTPException(status_code=409, detail="A subnet scan is already in progress")

    async def on_progress(event: dict[str, Any]) -> None:
        await services.hub.broadcast("scan_progress", event)

    summary = await services.scanner.scan_subnet(
        payload.cidr, scan_ports=payload.scan_ports, on_progress=on_progress
    )
    return summary
