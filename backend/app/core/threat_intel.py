"""Optional Threat Intelligence lookup (AbuseIPDB) with strict public-IP & SSRF guards."""

from __future__ import annotations

import ipaddress
import time
from typing import Any

import httpx

from app.core.notifier import mask_secret
from app.db.database import Database
from app.platform.base import validate_ip_address


ABUSEIPDB_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"


class ThreatIntelClient:
    """Checks public IP reputation via AbuseIPDB with local TTL caching."""

    def __init__(self, db: Database) -> None:
        self.db = db
        self.api_key: str = ""
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}

    async def load_settings(self) -> None:
        self.api_key = str(await self.db.get_setting("abuseipdb_api_key", "") or "")

    async def set_api_key(self, api_key: str) -> dict[str, Any]:
        cleaned = api_key.strip()
        self.api_key = cleaned
        await self.db.set_setting("abuseipdb_api_key", cleaned)
        return self.get_status()

    def get_status(self) -> dict[str, Any]:
        return {
            "configured": bool(self.api_key),
            "key_masked": mask_secret(self.api_key),
            "cached_count": len(self._cache),
        }

    async def check_ip(self, raw_ip: str) -> dict[str, Any]:
        safe_ip = validate_ip_address(raw_ip)
        addr = ipaddress.ip_address(safe_ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
            raise ValueError("Threat Intel reputation check only applies to public IP addresses")

        now = time.monotonic()
        cached = self._cache.get(safe_ip)
        if cached and (now - cached[0]) < 3600:
            return {**cached[1], "cached": True}

        if not self.api_key:
            raise ValueError("AbuseIPDB API key is not configured")

        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                ABUSEIPDB_ENDPOINT,
                params={"ipAddress": safe_ip, "maxAgeInDays": "90"},
                headers={"Key": self.api_key, "Accept": "application/json"},
            )
            if resp.status_code >= 400:
                raise RuntimeError(f"AbuseIPDB returned HTTP {resp.status_code}")
            payload = resp.json().get("data", {})

        result = {
            "ip": safe_ip,
            "abuse_confidence_score": payload.get("abuseConfidenceScore", 0),
            "country_code": payload.get("countryCode", ""),
            "isp": payload.get("isp", ""),
            "domain": payload.get("domain", ""),
            "total_reports": payload.get("totalReports", 0),
            "is_tor": bool(payload.get("isTor", False)),
            "cached": False,
        }
        if len(self._cache) >= 256:
            oldest = next(iter(self._cache))
            del self._cache[oldest]
        self._cache[safe_ip] = (now, result)
        return result
