"""Tests for ActiveResponseBlocker safety guardrails, whitelist, and injection prevention."""

from pathlib import Path

import pytest

from app.core.blocker import ActiveResponseBlocker
from app.db.database import Database
from app.platform.base import CommandResult, FirewallAdapter, validate_ip_address


class RecordingFirewall(FirewallAdapter):
    backend_name = "recording"

    def __init__(self) -> None:
        self.blocked: list[str] = []
        self.unblocked: list[str] = []

    async def block_ip(self, ip: str) -> CommandResult:
        self.blocked.append(ip)
        return CommandResult(success=True, message="blocked")

    async def unblock_ip(self, ip: str) -> CommandResult:
        self.unblocked.append(ip)
        return CommandResult(success=True, message="unblocked")


@pytest.mark.parametrize(
    "bad_ip",
    [
        "",
        "   ",
        "192.168.1.1; calc.exe",
        "192.168.1.1 && whoami",
        "$(whoami)",
        "999.999.999.999",
    ],
)
def test_validate_ip_rejects_injection_and_malformed_inputs(bad_ip: str) -> None:
    with pytest.raises(ValueError):
        validate_ip_address(bad_ip)


async def test_whitelist_prevents_blocking_loopback_and_gateway(tmp_path: Path) -> None:
    db = Database(tmp_path / "blocker.db")
    await db.initialize()
    fw = RecordingFirewall()
    blocker = ActiveResponseBlocker(
        db=db,
        firewall=fw,
        protected_ips={"192.168.1.1", "192.168.1.50"},
        whitelist_ips={"8.8.8.8"},
        dry_run=False,
    )

    for safe in ("127.0.0.1", "::1", "192.168.1.1", "192.168.1.50", "8.8.8.8"):
        res = await blocker.block_ip(safe, reason="test")
        assert res["status"] == "whitelist_skipped"

    assert fw.blocked == []

    with pytest.raises(ValueError):
        await blocker.remove_whitelist_ip("192.168.1.1")


async def test_dry_run_vs_live_enforcement(tmp_path: Path) -> None:
    db = Database(tmp_path / "blocker2.db")
    await db.initialize()
    fw = RecordingFirewall()
    blocker = ActiveResponseBlocker(
        db=db,
        firewall=fw,
        protected_ips={"192.168.1.1"},
        dry_run=True,
    )

    dry_res = await blocker.block_ip("203.0.113.10", reason="test dry")
    assert dry_res["status"] == "dry_run_blocked"
    assert fw.blocked == []

    await blocker.set_policy(dry_run=False)
    live_res = await blocker.block_ip("203.0.113.11", reason="test live")
    assert live_res["status"] == "blocked"
    assert fw.blocked == ["203.0.113.11"]

    unblock_res = await blocker.unblock_ip("203.0.113.11")
    assert unblock_res["status"] == "unblocked"
    assert fw.unblocked == ["203.0.113.11"]
