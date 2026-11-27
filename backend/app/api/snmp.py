"""SNMP targets and bandwidth/health metrics endpoints."""

from __future__ import annotations

import re
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.api.deps import AppServices, get_services


router = APIRouter(prefix="/api/snmp", tags=["snmp"])

SAFE_HOST_RE = re.compile(r"^[a-zA-Z0-9.\-:]{1,128}$")


class CreateSnmpTargetRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    host: str = Field(..., min_length=1, max_length=128)
    community: str = Field(default="public", min_length=1, max_length=64)
    port: int = Field(default=161, ge=1, le=65535)
    snmp_version: Literal["v2c", "v3"] = "v2c"
    v3_username: str = Field(default="", max_length=64)
    v3_auth_key: str = Field(default="", max_length=128)
    v3_priv_key: str = Field(default="", max_length=128)


@router.get("/metrics")
async def get_metrics(
    limit: int = Query(default=60, ge=1, le=300),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    metrics = await services.db.list_snmp_metrics(limit=limit)
    return {"metrics": metrics}


@router.post("/poll")
async def poll_now(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    sampled = await services.snmp_monitor.poll_once()
    for metric in sampled:
        await services.hub.broadcast("snmp_metric", metric)
    return {"sampled_count": len(sampled), "metrics": sampled}


@router.get("/targets")
async def list_targets(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    targets = await services.db.list_snmp_targets()
    enriched = []
    for t in targets:
        safe_row = {k: v for k, v in t.items() if k not in ("v3_auth_key", "v3_priv_key")}
        safe_row["runtime"] = services.snmp_monitor.target_status.get(
            int(t["id"]), {"status": "idle"}
        )
        enriched.append(safe_row)
    return {"targets": enriched}


@router.post("/targets")
async def create_target(
    payload: CreateSnmpTargetRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    host = payload.host.strip()
    if not SAFE_HOST_RE.match(host):
        raise HTTPException(status_code=400, detail="Invalid SNMP host format")
    try:
        created = await services.db.create_snmp_target(
            name=payload.name.strip(),
            host=host,
            community=payload.community.strip(),
            port=payload.port,
            snmp_version=payload.snmp_version,
            v3_username=payload.v3_username.strip(),
            v3_auth_key=payload.v3_auth_key.strip(),
            v3_priv_key=payload.v3_priv_key.strip(),
        )
    except Exception as exc:
        if "UNIQUE" in str(exc).upper():
            raise HTTPException(status_code=409, detail="SNMP target host already exists") from exc
        raise
    return created


@router.delete("/targets/{target_id}")
async def delete_target(
    target_id: int,
    confirm: bool = Query(default=False),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    if not confirm:
        raise HTTPException(
            status_code=400, detail="Confirmation required: pass confirm=true to delete target"
        )
    deleted = await services.db.delete_snmp_target(target_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="SNMP target not found")
    return {"deleted": True, "id": target_id}
