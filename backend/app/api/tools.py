"""Diagnostic & Network Admin Tools endpoints (Process sockets, Wi-Fi, Traceroute, Speedtest, HTTP/SSL)."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.api.deps import AppServices, get_services
from app.core.diagnostics import run_speed_test, run_traceroute, validate_diagnostic_target
from app.core.http_monitor import check_http_target, validate_monitor_url
from app.core.process_net import list_process_connections
from app.core.wifi_analyzer import analyze_wifi


router = APIRouter(prefix="/api/tools", tags=["tools"])


class TracerouteRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=128)
    max_hops: int = Field(default=15, ge=1, le=30)


class CreateMonitorRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    url: str = Field(..., min_length=8, max_length=256)


@router.get("/process-connections")
async def get_process_connections(
    limit: int = Query(default=150, ge=1, le=500),
) -> dict[str, Any]:
    return await asyncio.to_thread(list_process_connections, limit=limit)


@router.get("/wifi")
async def get_wifi_analysis() -> dict[str, Any]:
    return await analyze_wifi()


@router.post("/traceroute")
async def traceroute_target(payload: TracerouteRequest) -> dict[str, Any]:
    try:
        validate_diagnostic_target(payload.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return await run_traceroute(payload.target, max_hops=payload.max_hops)


@router.post("/speedtest")
async def speedtest() -> dict[str, Any]:
    return await run_speed_test()


@router.get("/monitors")
async def list_monitors(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    monitors = await services.db.list_http_monitors()
    return {"monitors": monitors}


@router.post("/monitors")
async def create_monitor(
    payload: CreateMonitorRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    try:
        safe_url = validate_monitor_url(payload.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        created = await services.db.create_http_monitor(
            name=payload.name.strip(), url=safe_url
        )
    except Exception as exc:
        if "UNIQUE" in str(exc).upper():
            raise HTTPException(status_code=409, detail="Monitor URL already exists") from exc
        raise
    return created


@router.post("/monitors/{monitor_id}/check")
async def check_monitor_now(
    monitor_id: int, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    mon = await services.db.get_http_monitor(monitor_id)
    if mon is None:
        raise HTTPException(status_code=404, detail="Monitor not found")
    res = await check_http_target(mon["url"])
    updated = await services.db.update_http_monitor_check(monitor_id, **res)
    return updated or mon


@router.delete("/monitors/{monitor_id}")
async def delete_monitor(
    monitor_id: int,
    confirm: bool = Query(default=False),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    if not confirm:
        raise HTTPException(
            status_code=400, detail="Confirmation required: pass confirm=true to delete monitor"
        )
    deleted = await services.db.delete_http_monitor(monitor_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Monitor not found")
    return {"deleted": True, "id": monitor_id}
