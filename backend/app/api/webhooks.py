"""Discord and Telegram Webhook notification settings and test endpoints."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.api.deps import AppServices, get_services


router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])


class UpdateWebhookRequest(BaseModel):
    enabled: bool | None = None
    min_severity: Literal["low", "medium", "high", "critical"] | None = None
    discord_webhook_url: str | None = Field(default=None, max_length=300)
    telegram_bot_token: str | None = Field(default=None, max_length=160)
    telegram_chat_id: str | None = Field(default=None, max_length=64)
    enterprise_webhook_url: str | None = Field(default=None, max_length=300)
    smtp_host: str | None = Field(default=None, max_length=128)
    smtp_port: int | None = Field(default=None, ge=1, le=65535)
    smtp_to: str | None = Field(default=None, max_length=128)


@router.get("")
async def get_webhook_status(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    return services.notifier.get_public_status()


@router.put("")
async def update_webhook_settings(
    payload: UpdateWebhookRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    try:
        return await services.notifier.update_settings(
            enabled=payload.enabled,
            min_severity=payload.min_severity,
            discord_webhook_url=payload.discord_webhook_url,
            telegram_bot_token=payload.telegram_bot_token,
            telegram_chat_id=payload.telegram_chat_id,
            enterprise_webhook_url=payload.enterprise_webhook_url,
            smtp_host=payload.smtp_host,
            smtp_port=payload.smtp_port,
            smtp_to=payload.smtp_to,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/test")
async def test_webhook(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    sample_alert = {
        "severity": "high",
        "title": "NetSentinel Webhook Test Notification",
        "source_ip": "127.0.0.1",
        "dest_ip": services.capabilities.default_subnet,
        "description": "ทดสอบการแจ้งเตือนจากระบบ NetSentinel เชื่อมต่อสำเร็จแล้ว",
        "action_taken": "test_notification",
    }
    result = await services.notifier.notify_alert(sample_alert, force=True)
    return {**result, "status": services.notifier.get_public_status()}
