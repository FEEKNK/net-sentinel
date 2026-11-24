"""Tests for Behavioral IDS Detectors, Snort Matching, and Cooldown."""

import ipaddress
from pathlib import Path

from app.core.blocker import ActiveResponseBlocker
from app.core.ids_engine import IDSEngine, PacketEvent
from app.db.database import Database
from app.platform.base import CommandResult, FirewallAdapter


class DummyFirewall(FirewallAdapter):
    backend_name = "dummy"

    async def block_ip(self, ip: str) -> CommandResult:
        return CommandResult(success=True, message="ok")

    async def unblock_ip(self, ip: str) -> CommandResult:
        return CommandResult(success=True, message="ok")


async def _make_engine(tmp_path: Path) -> tuple[IDSEngine, Database]:
    db = Database(tmp_path / "ids_test.db")
    await db.initialize()
    blocker = ActiveResponseBlocker(
        db=db,
        firewall=DummyFirewall(),
        protected_ips={"192.168.1.1"},
        dry_run=True,
        auto_block_enabled=True,
        auto_block_threshold="critical",
    )
    engine = IDSEngine(
        db=db,
        blocker=blocker,
        home_nets=[ipaddress.IPv4Network("192.168.1.0/24")],
        port_scan_threshold=5,
        syn_flood_threshold=30,
        cooldown_seconds=30.0,
    )
    engine.load_rules_text(
        'alert tcp any any -> any 23 (msg:"Telnet"; sid:1001; priority:2;)\n'
        'alert tcp any any -> any 80 (msg:"SQLi"; content:"UNION SELECT"; nocase; sid:1002; priority:1;)'
    )
    return engine, db


async def test_port_scan_and_cooldown(tmp_path: Path) -> None:
    engine, db = await _make_engine(tmp_path)
    res = await engine.simulate_attack("port_scan")
    assert res["alerts_triggered"] == 1
    assert res["alerts"][0]["detector_type"] == "behavioral_port_scan"

    # Immediate repeat within cooldown should be suppressed
    res2 = await engine.simulate_attack("port_scan")
    assert res2["alerts_triggered"] == 0

    stored = await db.list_alerts()
    assert len(stored) == 1


async def test_syn_flood_triggers_dry_run_auto_block(tmp_path: Path) -> None:
    engine, db = await _make_engine(tmp_path)
    res = await engine.simulate_attack("syn_flood", attacker_ip="198.51.100.77")
    assert res["alerts_triggered"] == 1
    assert res["alerts"][0]["severity"] == "critical"
    assert res["alerts"][0]["action_taken"] == "dry_run_blocked"

    blocked = await db.list_blocked_ips(active_only=True)
    assert len(blocked) == 1
    assert blocked[0]["ip"] == "198.51.100.77"
    assert blocked[0]["is_dry_run"] is True


async def test_arp_spoof_detector(tmp_path: Path) -> None:
    engine, _ = await _make_engine(tmp_path)
    res = await engine.simulate_attack("arp_spoof", target_ip="192.168.1.1")
    assert res["alerts_triggered"] == 1
    assert res["alerts"][0]["detector_type"] == "behavioral_arp_spoof"


async def test_snort_sqli_simulation(tmp_path: Path) -> None:
    engine, _ = await _make_engine(tmp_path)
    res = await engine.simulate_attack("snort_sqli")
    assert res["alerts_triggered"] == 1
    assert res["alerts"][0]["rule_sid"] == 1002
    assert res["alerts"][0]["detector_type"] == "snort_rule"


async def test_non_syn_ack_packets_do_not_trigger_syn_flood(tmp_path: Path) -> None:
    engine, _ = await _make_engine(tmp_path)
    for i in range(15):
        alerts = await engine.process_packet(
            PacketEvent(
                timestamp=100.0 + i * 0.01,
                protocol="tcp",
                src_ip="203.0.113.99",
                dst_ip="192.168.1.10",
                src_port=50000 + i,
                dst_port=443,
                tcp_flags="SA",
            )
        )
        assert alerts == []
