"""Tests for PCRE rules, TCP stream reassembly, OS fingerprint, Syslog, Threat Intel, Auth Lock, and PCAP upload."""

import base64
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.core.blocker import ActiveResponseBlocker
from app.core.ids_engine import IDSEngine, PacketEvent
from app.core.scanner import estimate_os, parse_port_spec
from app.core.sniffer import PacketSniffer
from app.core.snort_parser import parse_snort_rules
from app.core.syslog_server import parse_syslog_datagram
from app.core.threat_intel import ThreatIntelClient
from app.db.database import Database
from app.main import create_app
from app.platform.base import CommandResult, FirewallAdapter


class DummyFw(FirewallAdapter):
    backend_name = "dummy"

    async def block_ip(self, ip: str) -> CommandResult:
        return CommandResult(success=True, message="ok")

    async def unblock_ip(self, ip: str) -> CommandResult:
        return CommandResult(success=True, message="ok")


def test_pcre_rule_parsing_and_invalid_regex() -> None:
    res = parse_snort_rules(
        'alert tcp any any -> any 80 (msg:"Regex SQLi"; pcre:"/union\\s+select/i"; sid:3001; priority:1;)\n'
        'alert tcp any any -> any 80 (msg:"Broken"; pcre:"/[unclosed/"; sid:3002;)\n'
    )
    assert len(res.rules) == 1
    assert res.rules[0].pcre is not None
    assert len(res.errors) == 1


async def test_tcp_stream_reassembly_catches_split_payload(tmp_path: Path) -> None:
    db = Database(tmp_path / "stream.db")
    await db.initialize()
    blocker = ActiveResponseBlocker(db=db, firewall=DummyFw(), protected_ips=set())
    engine = IDSEngine(db=db, blocker=blocker)
    engine.load_rules_text(
        'alert tcp any any -> any 80 (msg:"Split SQLi"; pcre:"/union\\s+select/i"; sid:3003; priority:1;)'
    )

    p1 = PacketEvent(
        timestamp=10.0,
        protocol="tcp",
        src_ip="203.0.113.20",
        dst_ip="192.168.1.10",
        src_port=45000,
        dst_port=80,
        tcp_flags="PA",
        payload="GET /?q=1 UNION ",
    )
    p2 = PacketEvent(
        timestamp=10.1,
        protocol="tcp",
        src_ip="203.0.113.20",
        dst_ip="192.168.1.10",
        src_port=45000,
        dst_port=80,
        tcp_flags="PA",
        payload="SELECT password FROM users",
    )

    assert await engine.process_packet(p1) == []
    alerts = await engine.process_packet(p2)
    assert len(alerts) == 1
    assert alerts[0]["rule_sid"] == 3003

    stream = engine.follow_tcp_stream("203.0.113.20", 45000, "192.168.1.10", 80)
    assert "UNION SELECT password" in stream["client_to_server"]


def test_port_spec_os_fingerprint_and_syslog_parser() -> None:
    assert parse_port_spec("22,80,8000-8002") == [22, 80, 8000, 8001, 8002]
    with pytest.raises(ValueError):
        parse_port_spec("99999")

    assert estimate_os(128, [], "Intel") == "Windows"
    assert estimate_os(64, [], "Intel") == "Linux / macOS / Mobile"
    assert estimate_os(None, [], "Apple") == "macOS / iOS"

    sev, fac, msg = parse_syslog_datagram(b"<131>Interface eth0 link down")
    assert sev == "error"
    assert fac == "fac-16"
    assert msg == "Interface eth0 link down"


async def test_threat_intel_rejects_private_ip(tmp_path: Path) -> None:
    db = Database(tmp_path / "ti.db")
    await db.initialize()
    ti = ThreatIntelClient(db=db)
    await ti.set_api_key("test_secret_key_1234567890")
    assert ti.get_status()["configured"] is True
    assert "1234567890" not in ti.get_status()["key_masked"]

    with pytest.raises(ValueError):
        await ti.check_ip("192.168.1.1")


def test_dashboard_passcode_lock_and_pcap_upload(tmp_path: Path) -> None:
    rules_file = tmp_path / "test.rules"
    rules_file.write_text(
        'alert tcp any any -> any 80 (msg:"SQLi"; pcre:"/union\\s+select/i"; sid:9002; priority:1;)\n',
        encoding="utf-8",
    )
    cfg = Settings(db_path=tmp_path / "ent.db", snort_rules_path=rules_file, dry_run=True)

    with TestClient(create_app(cfg)) as client:
        # 1) PCAP upload & analyze
        sniffer = client.app.state.services.sniffer  # type: ignore[attr-defined]
        sniffer.record_synthetic_packet(
            PacketEvent(
                timestamp=1700000001.0,
                protocol="tcp",
                src_ip="203.0.113.88",
                dst_ip="192.168.1.10",
                src_port=44444,
                dst_port=80,
                tcp_flags="PA",
                payload="GET /?id=1 UNION SELECT * FROM users",
                length=120,
            )
        )
        pcap_bytes = sniffer.export_pcap_bytes()
        b64 = base64.b64encode(pcap_bytes).decode("ascii")
        analyze = client.post(
            "/api/system/pcap/analyze", json={"filename": "cap.pcap", "base64_data": b64}
        )
        assert analyze.status_code == 200
        assert analyze.json()["packet_count"] >= 1
        assert len(analyze.json()["matched_rules"]) >= 1

        # Reject invalid PCAP header
        bad_pcap = client.post(
            "/api/system/pcap/analyze",
            json={"filename": "bad.pcap", "base64_data": base64.b64encode(b"not a pcap file at all!!").decode("ascii")},
        )
        assert bad_pcap.status_code == 400

        # 2) Passcode lock end-to-end
        setup = client.post("/api/auth/setup", json={"passcode": "my-secret-pass"})
        assert setup.status_code == 200
        token = setup.json()["token"]

        # Unauthenticated request must return 401
        unauth = client.get("/api/system/status")
        assert unauth.status_code == 401

        # Authenticated request must succeed 200
        auth_ok = client.get("/api/system/status", headers={"X-NetSentinel-Token": token})
        assert auth_ok.status_code == 200

        # Disable passcode cleanly
        dis = client.post(
            "/api/auth/disable",
            json={"passcode": "my-secret-pass"},
            headers={"X-NetSentinel-Token": token},
        )
        assert dis.status_code == 200
        assert client.get("/api/system/status").status_code == 200
