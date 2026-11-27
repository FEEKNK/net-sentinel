"""Indicators of Compromise (IOC) IP & Domain matcher with O(1) lookup."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from app.db.database import Database


DOMAIN_RE = re.compile(r"^[a-zA-Z0-9.-]{3,253}$")


def parse_ioc_line(raw_line: str) -> tuple[str, str] | None:
    """Parse a single IOC line into (normalized_indicator, 'ip' | 'domain')."""
    line = raw_line.split("#", 1)[0].strip().lower()
    if not line:
        return None
    # Support comma-separated indicator,note format
    token = line.split(",", 1)[0].strip()
    if not token:
        return None
    try:
        ip = str(ipaddress.ip_address(token))
        return ip, "ip"
    except ValueError:
        if "." in token and DOMAIN_RE.match(token) and not token.startswith("."):
            return token.rstrip("."), "domain"
    return None


class IOCMatcher:
    """Maintains an in-memory O(1) cache backed by SQLite ioc_indicators table."""

    def __init__(self, db: Database) -> None:
        self.db = db
        self.ips: set[str] = set()
        self.domains: set[str] = set()

    async def reload(self) -> dict[str, int]:
        rows = await self.db.list_iocs(limit=5000)
        self.ips = {r["indicator"] for r in rows if r["kind"] == "ip"}
        self.domains = {r["indicator"] for r in rows if r["kind"] == "domain"}
        return {"ips": len(self.ips), "domains": len(self.domains)}

    async def import_text(
        self, raw_text: str, *, source: str = "manual", severity: str = "critical"
    ) -> dict[str, Any]:
        added = 0
        invalid = 0
        for raw_line in raw_text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parsed = parse_ioc_line(line)
            if parsed is None:
                invalid += 1
                continue
            indicator, kind = parsed
            await self.db.upsert_ioc(
                indicator=indicator, kind=kind, source=source, severity=severity
            )
            added += 1
        counts = await self.reload()
        return {"imported": added, "invalid": invalid, **counts}

    def match_packet(
        self, *, src_ip: str, dst_ip: str, dns_query: str = ""
    ) -> tuple[str, str] | None:
        """Return (matched_indicator, kind) if packet touches a known IOC."""
        if dst_ip in self.ips:
            return dst_ip, "ip"
        if src_ip in self.ips:
            return src_ip, "ip"
        if dns_query:
            clean_dom = dns_query.strip().lower().rstrip(".")
            if clean_dom in self.domains:
                return clean_dom, "domain"
            # Check parent domains too (e.g. sub.evil.com -> evil.com)
            parts = clean_dom.split(".")
            for i in range(1, len(parts) - 1):
                parent = ".".join(parts[i:])
                if parent in self.domains:
                    return parent, "domain"
        return None
