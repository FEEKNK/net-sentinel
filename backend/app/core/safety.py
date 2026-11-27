"""Enterprise & Hospital Safety Profiles, Protected VLAN Exclusions, and PDPA/PHI Privacy Mode."""

from __future__ import annotations

import ipaddress
from typing import Any, Literal

from app.db.database import Database


SafetyProfile = Literal["standard", "enterprise", "hospital_safe"]


class SafetyPolicyManager:
    """Enforces deployment profile guardrails (Hospital passive mode, VLAN exclusions, PDPA)."""

    def __init__(self, db: Database) -> None:
        self.db = db
        self.profile: SafetyProfile = "standard"
        self.excluded_cidrs: list[str] = []
        self.privacy_mode: bool = False
        self.retention_days: int = 90

    async def load_settings(self) -> None:
        prof = await self.db.get_setting("safety_profile", "standard")
        if prof in ("standard", "enterprise", "hospital_safe"):
            self.profile = prof
        saved_cidrs = await self.db.get_setting("excluded_cidrs", [])
        if isinstance(saved_cidrs, list):
            self.excluded_cidrs = [str(c) for c in saved_cidrs if self._is_valid_cidr(str(c))]
        self.privacy_mode = bool(await self.db.get_setting("privacy_mode", False))
        ret = await self.db.get_setting("retention_days", 90)
        if isinstance(ret, int) and 1 <= ret <= 3650:
            self.retention_days = ret

    @staticmethod
    def _is_valid_cidr(raw: str) -> bool:
        try:
            ipaddress.ip_network(raw.strip(), strict=False)
            return True
        except ValueError:
            return False

    @property
    def is_hospital_safe(self) -> bool:
        return self.profile == "hospital_safe"

    async def update_settings(
        self,
        *,
        profile: SafetyProfile | None = None,
        privacy_mode: bool | None = None,
        retention_days: int | None = None,
    ) -> dict[str, Any]:
        if profile is not None:
            if profile not in ("standard", "enterprise", "hospital_safe"):
                raise ValueError("Invalid safety profile")
            self.profile = profile
            await self.db.set_setting("safety_profile", profile)
            # In Hospital Safe mode, automatically enforce PDPA privacy mode too
            if profile == "hospital_safe" and privacy_mode is None:
                self.privacy_mode = True
                await self.db.set_setting("privacy_mode", True)

        if privacy_mode is not None:
            self.privacy_mode = privacy_mode
            await self.db.set_setting("privacy_mode", privacy_mode)

        if retention_days is not None:
            if retention_days < 1 or retention_days > 3650:
                raise ValueError("retention_days must be between 1 and 3650")
            self.retention_days = retention_days
            await self.db.set_setting("retention_days", retention_days)

        return self.get_state()

    async def add_excluded_cidr(self, raw_cidr: str) -> list[str]:
        net = ipaddress.ip_network(raw_cidr.strip(), strict=False)
        norm = str(net)
        if norm not in self.excluded_cidrs:
            self.excluded_cidrs.append(norm)
            await self.db.set_setting("excluded_cidrs", self.excluded_cidrs)
        return list(self.excluded_cidrs)

    async def remove_excluded_cidr(self, raw_cidr: str) -> list[str]:
        norm = str(ipaddress.ip_network(raw_cidr.strip(), strict=False))
        self.excluded_cidrs = [c for c in self.excluded_cidrs if c != norm]
        await self.db.set_setting("excluded_cidrs", self.excluded_cidrs)
        return list(self.excluded_cidrs)

    def overlaps_excluded_cidr(self, target_cidr: str) -> str | None:
        """Return matching excluded CIDR if target_cidr overlaps a protected medical/critical VLAN."""
        target_net = ipaddress.ip_network(target_cidr.strip(), strict=False)
        for ex in self.excluded_cidrs:
            ex_net = ipaddress.ip_network(ex, strict=False)
            if target_net.version == ex_net.version and target_net.overlaps(ex_net):
                return ex
        return None

    def is_ip_in_excluded_cidr(self, ip: str) -> str | None:
        """Return matching excluded CIDR if a single IP belongs to a protected VLAN."""
        addr = ipaddress.ip_address(ip.strip())
        for ex in self.excluded_cidrs:
            ex_net = ipaddress.ip_network(ex, strict=False)
            if addr.version == ex_net.version and addr in ex_net:
                return ex
        return None

    def sanitize_payload(self, payload: str) -> str:
        """Redact packet payload under PDPA/PHI Header-Only Privacy Mode."""
        if self.privacy_mode and payload:
            return "[REDACTED: PDPA/PHI Header-Only Mode]"
        return payload

    def get_state(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "is_hospital_safe": self.is_hospital_safe,
            "privacy_mode": self.privacy_mode,
            "retention_days": self.retention_days,
            "excluded_cidrs": list(self.excluded_cidrs),
        }
