"""HTTP / HTTPS Uptime & SSL Certificate Expiration Monitor."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx


def validate_monitor_url(raw_url: str) -> str:
    """Allow http/https URLs while rejecting credentials and cloud metadata SSRF."""
    cleaned = raw_url.strip()
    parsed = urlparse(cleaned)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Monitor URL must start with http:// or https://")
    if parsed.username or parsed.password:
        raise ValueError("Embedded credentials in URL are not allowed")
    host = parsed.hostname.lower()
    if host == "169.254.169.254" or host.endswith(".internal"):
        raise ValueError("Metadata endpoints cannot be monitored")
    try:
        addr = ipaddress.ip_address(host)
        if addr.is_link_local:
            raise ValueError("Link-local metadata addresses are not allowed")
    except ValueError as exc:
        if "not allowed" in str(exc):
            raise
    return cleaned


def _inspect_ssl_sync(hostname: str, port: int) -> tuple[int | None, str]:
    """Read TLS peer certificate expiry days and issuer without rejecting self-signed LAN certs."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=3.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        if not cert:
            return None, ""
        not_after = cert.get("notAfter")
        days_left: int | None = None
        if isinstance(not_after, str):
            exp_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (exp_dt - datetime.now(timezone.utc)).days
        issuer_parts = cert.get("issuer") or ()
        issuer_cn = ""
        for rdn in issuer_parts:
            for k, v in rdn:
                if k in ("organizationName", "commonName"):
                    issuer_cn = str(v)
        return days_left, issuer_cn
    except Exception:
        return None, ""


async def check_http_target(url: str) -> dict[str, Any]:
    """Check HTTP status code, latency, and HTTPS SSL expiration days."""
    safe_url = validate_monitor_url(url)
    parsed = urlparse(safe_url)
    started = time.perf_counter()
    status_code: int | None = None
    latency_ms: float | None = None
    error_msg: str | None = None
    ssl_days: int | None = None
    ssl_issuer = ""

    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
            resp = await client.get(safe_url)
            status_code = resp.status_code
            latency_ms = round((time.perf_counter() - started) * 1000, 1)
    except Exception as exc:
        error_msg = str(exc)[:200]

    if parsed.scheme == "https" and parsed.hostname:
        port = parsed.port or 443
        ssl_days, ssl_issuer = await asyncio.to_thread(_inspect_ssl_sync, parsed.hostname, port)

    return {
        "status_code": status_code,
        "latency_ms": latency_ms,
        "ssl_days_remaining": ssl_days,
        "ssl_issuer": ssl_issuer,
        "last_error": error_msg,
    }
