"""Firewall Active Response, policy, and whitelist endpoints."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.api.deps import AppServices, get_services


router = APIRouter(prefix="/api/firewall", tags=["firewall"])


class PolicyUpdateRequest(BaseModel):
    dry_run: bool | None = None
    auto_block_enabled: bool | None = None
    auto_block_threshold: Literal["high", "critical"] | None = None
    confirm: bool = False


class BlockIpRequest(BaseModel):
    ip: str = Field(..., min_length=3, max_length=64)
    reason: str = Field(default="Manual block from NetSentinel UI", min_length=1, max_length=200)
    confirm: bool = False


class WhitelistRequest(BaseModel):
    ip: str = Field(..., min_length=3, max_length=64)


@router.get("/status")
async def get_firewall_status(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    blocked = await services.db.list_blocked_ips(active_only=False)
    return {
        "policy": services.blocker.get_policy_state(),
        "blocked_ips": blocked,
        "active_count": sum(1 for b in blocked if b["active"]),
    }


@router.put("/policy")
async def update_policy(
    payload: PolicyUpdateRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    # Enforce server-side confirmation when enabling live firewall enforcement
    enabling_live = (payload.dry_run is False) or (payload.auto_block_enabled is True)
    if enabling_live and not payload.confirm:
        raise HTTPException(
            status_code=400,
            detail="Confirmation required (confirm=true) before enabling live firewall enforcement",
        )
    updated = await services.blocker.set_policy(
        dry_run=payload.dry_run,
        auto_block_enabled=payload.auto_block_enabled,
        auto_block_threshold=payload.auto_block_threshold,
    )
    await services.hub.broadcast("policy_updated", updated)
    return updated


@router.post("/block")
async def block_ip(
    payload: BlockIpRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    if not payload.confirm:
        raise HTTPException(
            status_code=400,
            detail="Confirmation required (confirm=true) to block an IP address",
        )
    try:
        result = await services.blocker.block_ip(payload.ip, reason=payload.reason.strip())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if result["status"] == "whitelist_skipped":
        raise HTTPException(status_code=403, detail=result["message"])
    await services.hub.broadcast("firewall_updated", result)
    return result


@router.post("/unblock")
async def unblock_ip(
    payload: BlockIpRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    if not payload.confirm:
        raise HTTPException(
            status_code=400,
            detail="Confirmation required (confirm=true) to unblock an IP address",
        )
    try:
        result = await services.blocker.unblock_ip(payload.ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await services.hub.broadcast("firewall_updated", result)
    return result


@router.post("/whitelist")
async def add_whitelist(
    payload: WhitelistRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    try:
        protected = await services.blocker.add_whitelist_ip(payload.ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"protected_ips": protected, "policy": services.blocker.get_policy_state()}


@router.delete("/whitelist")
async def remove_whitelist(
    ip: str = Query(..., min_length=3, max_length=64),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    try:
        protected = await services.blocker.remove_whitelist_ip(ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"protected_ips": protected, "policy": services.blocker.get_policy_state()}
