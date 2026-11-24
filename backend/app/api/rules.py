"""Snort rules inspection and live hot-reload endpoints."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.api.deps import AppServices, get_services
from app.config import settings
from app.core.snort_parser import parse_snort_rules


router = APIRouter(prefix="/api/rules", tags=["rules"])


class UpdateRulesRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=262_144)
    confirm: bool = False


@router.get("")
async def get_rules(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    rules_path = settings.snort_rules_path
    content = rules_path.read_text(encoding="utf-8") if rules_path.exists() else ""
    parsed_rules = [
        {
            **asdict(r),
            "severity": r.severity,
        }
        for r in services.ids_engine.rules
    ]
    return {
        "path": str(rules_path),
        "content": content,
        "rules": parsed_rules,
        "errors": services.ids_engine.rule_errors,
    }


@router.put("")
async def update_rules(
    payload: UpdateRulesRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    if not payload.confirm:
        raise HTTPException(
            status_code=400,
            detail="Confirmation required: pass confirm=true to save and reload Snort rules",
        )
    if len(payload.content.encode("utf-8")) > settings.max_rules_file_bytes:
        raise HTTPException(status_code=413, detail="Rules content exceeds maximum allowed size")

    preview = parse_snort_rules(payload.content)
    if preview.errors and not preview.rules:
        raise HTTPException(
            status_code=400,
            detail={"message": "No valid Snort rules found", "errors": preview.errors},
        )

    rules_path = settings.snort_rules_path
    rules_path.parent.mkdir(parents=True, exist_ok=True)
    rules_path.write_text(payload.content, encoding="utf-8")
    reload_info = services.ids_engine.load_rules_text(payload.content)
    return {"saved": True, **reload_info}
