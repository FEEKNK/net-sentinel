"""Discord and Telegram Webhook alert dispatcher with strict SSRF & secret masking."""

from __future__ import annotations

import ipaddress
import smtplib
import time
from email.message import EmailMessage
from typing import Any
from urllib.parse import urlparse

import httpx

from app.db.database import Database


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
ALLOWED_DISCORD_HOSTS = {"discord.com", "discordapp.com"}


def validate_enterprise_webhook_url(url: str) -> str:
    """Validate HTTPS webhook URL for MS Teams / Slack / Ticketing without SSRF to localhost/metadata."""
    cleaned = url.strip()
    if not cleaned:
        return ""
    parsed = urlparse(cleaned)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Enterprise webhook URL must use https://")
    host = parsed.hostname.lower()
    if host in ("localhost", "127.0.0.1", "::1") or host == "169.254.169.254":
        raise ValueError("Webhook host cannot target localhost or metadata endpoints")
    try:
        addr = ipaddress.ip_address(host)
        if addr.is_loopback or addr.is_link_local:
            raise ValueError("Loopback or link-local addresses are not allowed")
    except ValueError as exc:
        if "not allowed" in str(exc):
            raise
    return cleaned


def validate_discord_webhook_url(url: str) -> str:
    """Strictly allow only official HTTPS Discord webhook URLs to prevent SSRF."""
    cleaned = url.strip()
    if not cleaned:
        return ""
    parsed = urlparse(cleaned)
    if parsed.scheme != "https" or (parsed.hostname or "").lower() not in ALLOWED_DISCORD_HOSTS:
        raise ValueError("Discord Webhook URL must use https://discord.com/api/webhooks/...")
    if not parsed.path.startswith("/api/webhooks/"):
        raise ValueError("Invalid Discord webhook path")
    return cleaned


def validate_telegram_token(token: str) -> str:
    """Validate basic Telegram Bot API token format (digits:secret)."""
    cleaned = token.strip()
    if not cleaned:
        return ""
    if ":" not in cleaned or any(ch.isspace() for ch in cleaned):
        raise ValueError("Invalid Telegram Bot Token format")
    return cleaned


def mask_secret(value: str) -> str:
    """Mask webhook URL or token before returning to the UI."""
    if not value:
        return ""
    if len(value) <= 12:
        return "****"
    return f"{value[:18]}...****{value[-4:]}"


class WebhookNotifier:
    """Rate-limited, non-blocking alert forwarder for Discord and Telegram."""

    def __init__(self, db: Database, min_interval_seconds: float = 5.0) -> None:
        self.db = db
        self.min_interval_seconds = min_interval_seconds
        self.enabled: bool = False
        self.min_severity: str = "high"
        self.discord_webhook_url: str = ""
        self.telegram_bot_token: str = ""
        self.telegram_chat_id: str = ""
        self.enterprise_webhook_url: str = ""
        self.smtp_host: str = ""
        self.smtp_port: int = 587
        self.smtp_to: str = ""
        self.last_error: str | None = None
        self.last_sent_at: float = 0.0

    async def load_settings(self) -> None:
        self.enabled = bool(await self.db.get_setting("webhook_enabled", False))
        sev = await self.db.get_setting("webhook_min_severity", "high")
        if sev in SEVERITY_RANK:
            self.min_severity = sev
        self.discord_webhook_url = str(await self.db.get_setting("webhook_discord_url", "") or "")
        self.telegram_bot_token = str(await self.db.get_setting("webhook_telegram_token", "") or "")
        self.telegram_chat_id = str(await self.db.get_setting("webhook_telegram_chat_id", "") or "")
        self.enterprise_webhook_url = str(await self.db.get_setting("webhook_enterprise_url", "") or "")
        self.smtp_host = str(await self.db.get_setting("smtp_host", "") or "")
        self.smtp_port = int(await self.db.get_setting("smtp_port", 587) or 587)
        self.smtp_to = str(await self.db.get_setting("smtp_to", "") or "")

    async def update_settings(
        self,
        *,
        enabled: bool | None = None,
        min_severity: str | None = None,
        discord_webhook_url: str | None = None,
        telegram_bot_token: str | None = None,
        telegram_chat_id: str | None = None,
        enterprise_webhook_url: str | None = None,
        smtp_host: str | None = None,
        smtp_port: int | None = None,
        smtp_to: str | None = None,
    ) -> dict[str, Any]:
        if enabled is not None:
            self.enabled = enabled
            await self.db.set_setting("webhook_enabled", enabled)
        if min_severity is not None:
            if min_severity not in SEVERITY_RANK:
                raise ValueError("min_severity must be one of low, medium, high, critical")
            self.min_severity = min_severity
            await self.db.set_setting("webhook_min_severity", min_severity)
        if discord_webhook_url is not None:
            safe_url = validate_discord_webhook_url(discord_webhook_url)
            self.discord_webhook_url = safe_url
            await self.db.set_setting("webhook_discord_url", safe_url)
        if telegram_bot_token is not None:
            safe_token = validate_telegram_token(telegram_bot_token)
            self.telegram_bot_token = safe_token
            await self.db.set_setting("webhook_telegram_token", safe_token)
        if telegram_chat_id is not None:
            self.telegram_chat_id = telegram_chat_id.strip()
            await self.db.set_setting("webhook_telegram_chat_id", self.telegram_chat_id)
        if enterprise_webhook_url is not None:
            safe_ent = validate_enterprise_webhook_url(enterprise_webhook_url)
            self.enterprise_webhook_url = safe_ent
            await self.db.set_setting("webhook_enterprise_url", safe_ent)
        if smtp_host is not None:
            self.smtp_host = smtp_host.strip()
            await self.db.set_setting("smtp_host", self.smtp_host)
        if smtp_port is not None:
            self.smtp_port = max(1, min(int(smtp_port), 65535))
            await self.db.set_setting("smtp_port", self.smtp_port)
        if smtp_to is not None:
            self.smtp_to = smtp_to.strip()
            await self.db.set_setting("smtp_to", self.smtp_to)
        return self.get_public_status()

    def get_public_status(self) -> dict[str, Any]:
        """Return webhook status with secrets strictly masked."""
        return {
            "enabled": self.enabled,
            "min_severity": self.min_severity,
            "discord_configured": bool(self.discord_webhook_url),
            "discord_masked": mask_secret(self.discord_webhook_url),
            "telegram_configured": bool(self.telegram_bot_token and self.telegram_chat_id),
            "telegram_chat_id": self.telegram_chat_id,
            "telegram_token_masked": mask_secret(self.telegram_bot_token),
            "enterprise_configured": bool(self.enterprise_webhook_url),
            "enterprise_masked": mask_secret(self.enterprise_webhook_url),
            "smtp_configured": bool(self.smtp_host and self.smtp_to),
            "smtp_host": self.smtp_host,
            "smtp_to": self.smtp_to,
            "last_error": self.last_error,
        }

    async def notify_alert(self, alert: dict[str, Any], *, force: bool = False) -> dict[str, Any]:
        """Send alert to configured Discord/Telegram endpoints respecting severity & rate limit."""
        if not force and not self.enabled:
            return {"sent": False, "reason": "disabled"}

        sev = str(alert.get("severity", "low")).lower()
        if not force and SEVERITY_RANK.get(sev, 1) < SEVERITY_RANK.get(self.min_severity, 3):
            return {"sent": False, "reason": "below_threshold"}

        now = time.monotonic()
        if not force and (now - self.last_sent_at) < self.min_interval_seconds:
            return {"sent": False, "reason": "rate_limited"}

        if (
            not self.discord_webhook_url
            and not self.enterprise_webhook_url
            and not (self.telegram_bot_token and self.telegram_chat_id)
            and not (self.smtp_host and self.smtp_to)
        ):
            return {"sent": False, "reason": "no_targets_configured"}

        self.last_sent_at = now
        text = (
            f"[NetSentinel | {sev.upper()}] {alert.get('title', 'Alert')}\n"
            f"Source: {alert.get('source_ip', '-')}"
            f"{' -> ' + str(alert.get('dest_ip')) if alert.get('dest_ip') else ''}\n"
            f"Detail: {alert.get('description', '')}\n"
            f"Action: {alert.get('action_taken', 'logged')}"
        )

        delivered: list[str] = []
        errors: list[str] = []

        async with httpx.AsyncClient(timeout=4.0) as client:
            if self.discord_webhook_url:
                try:
                    resp = await client.post(self.discord_webhook_url, json={"content": text[:1900]})
                    if resp.status_code < 300:
                        delivered.append("discord")
                    else:
                        errors.append(f"Discord HTTP {resp.status_code}")
                except Exception as exc:
                    errors.append(f"Discord error: {exc}")

            if self.enterprise_webhook_url:
                try:
                    resp = await client.post(
                        self.enterprise_webhook_url,
                        json={
                            "text": text[:1900],
                            "title": alert.get("title", "NetSentinel Alert"),
                            "severity": sev,
                            "source_ip": alert.get("source_ip", ""),
                        },
                    )
                    if resp.status_code < 300:
                        delivered.append("enterprise_webhook")
                    else:
                        errors.append(f"Enterprise Webhook HTTP {resp.status_code}")
                except Exception as exc:
                    errors.append(f"Enterprise Webhook error: {exc}")

            if self.telegram_bot_token and self.telegram_chat_id:
                try:
                    tg_url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
                    resp = await client.post(
                        tg_url,
                        json={"chat_id": self.telegram_chat_id, "text": text[:3900]},
                    )
                    if resp.status_code < 300:
                        delivered.append("telegram")
                    else:
                        errors.append(f"Telegram HTTP {resp.status_code}")
                except Exception as exc:
                    errors.append(f"Telegram error: {exc}")

        if self.smtp_host and self.smtp_to:
            try:
                import asyncio

                await asyncio.to_thread(_send_smtp_sync, self.smtp_host, self.smtp_port, self.smtp_to, text)
                delivered.append("smtp")
            except Exception as exc:
                errors.append(f"SMTP error: {exc}")

        self.last_error = "; ".join(errors) if errors else None
        return {"sent": len(delivered) > 0, "delivered": delivered, "errors": errors}


def _send_smtp_sync(host: str, port: int, recipient: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = "[NetSentinel] Security Alert Notification"
    msg["From"] = "netsentinel@localhost"
    msg["To"] = recipient
    msg.set_content(body)
    with smtplib.SMTP(host, port, timeout=4.0) as server:
        server.send_message(msg)
