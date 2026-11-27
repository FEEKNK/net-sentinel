"""IDS alerts, simulation triggers, and alert log endpoints."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.api.deps import AppServices, get_services
from app.core.ids_engine import PacketEvent
from app.platform.base import validate_ip_address


router = APIRouter(prefix="/api/alerts", tags=["alerts"])


class SimulateRequest(BaseModel):
    attack_type: Literal[
        "port_scan",
        "syn_flood",
        "arp_spoof",
        "bruteforce",
        "dns_tunnel",
        "icmp_flood",
        "dhcp_rogue",
        "snort_telnet",
        "snort_sqli",
    ]
    attacker_ip: str = Field(default="203.0.113.55", min_length=3, max_length=64)
    target_ip: str = Field(default="192.168.1.10", min_length=3, max_length=64)


@router.get("")
async def list_alerts(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    severity: str = Query(default="all"),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    alerts = await services.db.list_alerts(limit=limit, offset=offset, severity=severity)
    counts = await services.db.count_alerts()
    return {"alerts": alerts, "counts": counts}


@router.delete("")
async def clear_alerts(
    confirm: bool = Query(default=False),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    if not confirm:
        raise HTTPException(
            status_code=400,
            detail="Confirmation required: pass confirm=true to permanently clear alerts",
        )
    deleted = await services.db.clear_alerts()
    await services.hub.broadcast("alerts_cleared", {"deleted": deleted})
    return {"deleted": deleted}


@router.post("/simulate")
async def simulate_attack(
    payload: SimulateRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    try:
        safe_attacker = validate_ip_address(payload.attacker_ip)
        safe_target = validate_ip_address(payload.target_ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    result = await services.ids_engine.simulate_attack(
        payload.attack_type, attacker_ip=safe_attacker, target_ip=safe_target
    )
    # Record representative synthetic packet in buffer for transparency
    services.sniffer.record_synthetic_packet(
        PacketEvent(
            timestamp=0.0,
            protocol="arp" if payload.attack_type == "arp_spoof" else "tcp",
            src_ip=safe_attacker,
            dst_ip=safe_target,
            src_port=55123,
            dst_port=23 if payload.attack_type == "snort_telnet" else 80,
            tcp_flags="PA" if payload.attack_type.startswith("snort") else "S",
            payload=(
                "GET /items?id=1 UNION SELECT username,password FROM users HTTP/1.1"
                if payload.attack_type == "snort_sqli"
                else f"SIMULATED_TRAFFIC:{payload.attack_type}"
            ),
            length=128,
        )
    )
    return result
