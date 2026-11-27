"""Active Response / Auto-Block manager with strict whitelist and Dry-Run safety."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from app.db.database import Database
from app.platform.base import FirewallAdapter, validate_ip_address


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class ActiveResponseBlocker:
    """Evaluates IDS alerts and executes safe, reversible firewall blocks."""

    def __init__(
        self,
        *,
        db: Database,
        firewall: FirewallAdapter,
        protected_ips: set[str],
        whitelist_ips: set[str] | None = None,
        dry_run: bool = True,
        auto_block_enabled: bool = False,
        auto_block_threshold: str = "critical",
        block_ttl_seconds: int = 3600,
        safety_manager: Any | None = None,
    ) -> None:
        self.db = db
        self.firewall = firewall
        self.safety_manager = safety_manager
        self.protected_ips: set[str] = {"127.0.0.1", "::1"} | {
            validate_ip_address(ip) for ip in protected_ips if ip
        }
        self.whitelist_ips: set[str] = {
            validate_ip_address(ip) for ip in (whitelist_ips or set()) if ip
        }
        self.dry_run = dry_run
        self.auto_block_enabled = auto_block_enabled
        self.auto_block_threshold = auto_block_threshold.lower()
        self.block_ttl_seconds = max(60, block_ttl_seconds)

    async def load_persisted_policy(self) -> None:
        """Load persisted policy flags from SQLite if present."""
        saved_dry = await self.db.get_setting("dry_run")
        if isinstance(saved_dry, bool):
            self.dry_run = saved_dry
        saved_auto = await self.db.get_setting("auto_block_enabled")
        if isinstance(saved_auto, bool):
            self.auto_block_enabled = saved_auto
        saved_thresh = await self.db.get_setting("auto_block_threshold")
        if saved_thresh in ("high", "critical"):
            self.auto_block_threshold = saved_thresh
        saved_wl = await self.db.get_setting("whitelist_ips")
        if isinstance(saved_wl, list):
            clean: set[str] = set()
            for item in saved_wl:
                try:
                    clean.add(validate_ip_address(str(item)))
                except ValueError:
                    continue
            self.whitelist_ips = clean

    def is_whitelisted(self, ip: str) -> bool:
        """Return True if IP is protected (loopback, host, gateway), excluded VLAN, or user-whitelisted."""
        safe_ip = validate_ip_address(ip)
        if safe_ip in self.protected_ips or safe_ip in self.whitelist_ips:
            return True
        if self.safety_manager is not None and self.safety_manager.is_ip_in_excluded_cidr(safe_ip):
            return True
        return False

    async def set_policy(
        self,
        *,
        dry_run: bool | None = None,
        auto_block_enabled: bool | None = None,
        auto_block_threshold: str | None = None,
    ) -> dict[str, Any]:
        if dry_run is not None:
            self.dry_run = dry_run
            await self.db.set_setting("dry_run", dry_run)
        if auto_block_enabled is not None:
            self.auto_block_enabled = auto_block_enabled
            await self.db.set_setting("auto_block_enabled", auto_block_enabled)
        if auto_block_threshold in ("high", "critical"):
            self.auto_block_threshold = auto_block_threshold
            await self.db.set_setting("auto_block_threshold", auto_block_threshold)
        return self.get_policy_state()

    async def add_whitelist_ip(self, raw_ip: str) -> list[str]:
        safe_ip = validate_ip_address(raw_ip)
        self.whitelist_ips.add(safe_ip)
        await self.db.set_setting("whitelist_ips", sorted(self.whitelist_ips))
        return self.list_all_protected()

    async def remove_whitelist_ip(self, raw_ip: str) -> list[str]:
        safe_ip = validate_ip_address(raw_ip)
        if safe_ip in self.protected_ips:
            raise ValueError(f"{safe_ip} is a system-protected IP (host/gateway/loopback) and cannot be removed")
        self.whitelist_ips.discard(safe_ip)
        await self.db.set_setting("whitelist_ips", sorted(self.whitelist_ips))
        return self.list_all_protected()

    def list_all_protected(self) -> list[str]:
        return sorted(self.protected_ips | self.whitelist_ips)

    def get_policy_state(self) -> dict[str, Any]:
        return {
            "dry_run": self.dry_run,
            "auto_block_enabled": self.auto_block_enabled,
            "auto_block_threshold": self.auto_block_threshold,
            "block_ttl_seconds": self.block_ttl_seconds,
            "firewall_backend": self.firewall.backend_name,
            "system_protected_ips": sorted(self.protected_ips),
            "custom_whitelist_ips": sorted(self.whitelist_ips),
        }

    async def evaluate_alert(self, *, source_ip: str, severity: str, title: str) -> str:
        """Auto-block source IP if policy allows and severity meets threshold."""
        if self.safety_manager is not None and self.safety_manager.is_hospital_safe:
            return "logged_passive_hospital_mode"
        if not self.auto_block_enabled:
            return "logged"
        thresh_rank = SEVERITY_RANK.get(self.auto_block_threshold, 4)
        sev_rank = SEVERITY_RANK.get(severity.lower(), 1)
        if sev_rank < thresh_rank:
            return "logged"
        result = await self.block_ip(source_ip, reason=f"Auto-Block ({severity}): {title}")
        return str(result["status"])

    async def block_ip(self, raw_ip: str, *, reason: str) -> dict[str, Any]:
        """Block an IP (or record a Dry-Run block) after strict validation and whitelist check."""
        safe_ip = validate_ip_address(raw_ip)
        if self.is_whitelisted(safe_ip):
            return {
                "status": "whitelist_skipped",
                "ip": safe_ip,
                "message": f"Refused to block protected/whitelisted IP {safe_ip}",
            }

        expires_at = (
            datetime.now(timezone.utc) + timedelta(seconds=self.block_ttl_seconds)
        ).isoformat()

        if self.dry_run or (self.safety_manager is not None and self.safety_manager.is_hospital_safe):
            record = await self.db.upsert_blocked_ip(
                ip=safe_ip,
                reason=reason,
                expires_at=expires_at,
                is_dry_run=True,
                active=True,
            )
            return {
                "status": "dry_run_blocked",
                "ip": safe_ip,
                "message": f"[DRY-RUN] Would block {safe_ip} via {self.firewall.backend_name}",
                "record": record,
            }

        cmd_res = await self.firewall.block_ip(safe_ip)
        if not cmd_res.success:
            return {
                "status": "block_failed",
                "ip": safe_ip,
                "message": cmd_res.message,
            }

        record = await self.db.upsert_blocked_ip(
            ip=safe_ip,
            reason=reason,
            expires_at=expires_at,
            is_dry_run=False,
            active=True,
        )
        return {
            "status": "blocked",
            "ip": safe_ip,
            "message": f"Blocked {safe_ip} via {self.firewall.backend_name}",
            "record": record,
        }

    async def unblock_ip(self, raw_ip: str) -> dict[str, Any]:
        """Unblock an IP from firewall (if enforced) and mark inactive in SQLite."""
        safe_ip = validate_ip_address(raw_ip)
        rows = await self.db.list_blocked_ips(active_only=True)
        existing = next((r for r in rows if r["ip"] == safe_ip), None)

        if existing and not existing["is_dry_run"]:
            cmd_res = await self.firewall.unblock_ip(safe_ip)
            if not cmd_res.success:
                return {"status": "unblock_failed", "ip": safe_ip, "message": cmd_res.message}

        await self.db.deactivate_blocked_ip(safe_ip)
        return {"status": "unblocked", "ip": safe_ip, "message": f"Unblocked {safe_ip}"}

    async def expire_stale_blocks(self) -> int:
        """Expire TTL-elapsed blocks automatically."""
        now = datetime.now(timezone.utc)
        rows = await self.db.list_blocked_ips(active_only=True)
        expired_count = 0
        for row in rows:
            exp_raw = row.get("expires_at")
            if not exp_raw:
                continue
            try:
                exp_dt = datetime.fromisoformat(exp_raw)
            except ValueError:
                continue
            if now >= exp_dt:
                res = await self.unblock_ip(row["ip"])
                if res["status"] == "unblocked":
                    expired_count += 1
        return expired_count
