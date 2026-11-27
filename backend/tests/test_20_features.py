"""Comprehensive tests for the 20 Expansion Features (Detectors, Network Engineering, SOC, Compliance, 360° Timeline)."""

import socket
import struct
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.core.blocker import ActiveResponseBlocker
from app.core.ids_engine import IDSEngine, PacketEvent, shannon_entropy
from app.core.ioc_matcher import IOCMatcher
from app.core.netflow_collector import (
    NETFLOW_V5_HEADER_FMT,
    NETFLOW_V5_RECORD_FMT,
    NetFlowCollector,
    parse_netflow_v5_packet,
)
from app.core.notifier import WebhookNotifier, validate_enterprise_webhook_url
from app.core.playbooks import PlaybookEngine
from app.core.snmp_traps import parse_snmp_trap_payload
from app.db.database import Database
from app.main import create_app
from app.platform.base import CommandResult, FirewallAdapter


class DummyFirewall(FirewallAdapter):
    backend_name = "dummy"

    async def block_ip(self, ip: str) -> CommandResult:
        return CommandResult(success=True, message="ok")

    async def unblock_ip(self, ip: str) -> CommandResult:
        return CommandResult(success=True, message="ok")


def _build_client(tmp_path: Path) -> TestClient:
    rules_file = tmp_path / "rules.rules"
    rules_file.write_text(
        'alert tcp any any -> any 23 (msg:"Telnet Test"; sid:9001; priority:2;)\n',
        encoding="utf-8",
    )
    cfg = Settings(
        db_path=tmp_path / "feat20.db",
        snort_rules_path=rules_file,
        dry_run=True,
        auto_block_enabled=False,
    )
    return TestClient(create_app(cfg))


async def test_phase1_detectors_and_ioc_matching(tmp_path: Path) -> None:
    db = Database(tmp_path / "p1.db")
    await db.initialize()
    blocker = ActiveResponseBlocker(
        db=db,
        firewall=DummyFirewall(),
        protected_ips={"192.168.1.1"},
        dry_run=True,
    )
    ioc = IOCMatcher(db=db)
    await ioc.import_text("198.51.100.77\nbad-c2.example\n# comment\ninvalid_token", source="test_feed")

    engine = IDSEngine(
        db=db,
        blocker=blocker,
        trusted_dhcp_servers={"192.168.1.1"},
        ioc_matcher=ioc,
        bruteforce_threshold=4,
        icmp_flood_threshold=4,
        icmp_oversize_bytes=200,
    )

    # 1) Shannon entropy + DNS Tunneling
    assert shannon_entropy("a9f2k8q7m4z1x6v5c3b9n2l8p0w4r7t6") > 3.7
    dns_alerts = await engine.process_packet(
        PacketEvent(
            timestamp=100.0,
            protocol="udp",
            src_ip="192.168.1.50",
            dst_ip="8.8.8.8",
            dst_port=53,
            dns_query="a9f2k8q7m4z1x6v5c3b9n2l8p0w4r7t6.tunnel.example.com",
        )
    )
    assert any(a["detector_type"] == "behavioral_dns_tunnel" for a in dns_alerts)

    # 2) Brute force SSH threshold
    bf_alerts = []
    for i in range(4):
        res = await engine.process_packet(
            PacketEvent(
                timestamp=101.0 + i * 0.1,
                protocol="tcp",
                src_ip="203.0.113.20",
                dst_ip="192.168.1.10",
                src_port=40000 + i,
                dst_port=22,
                tcp_flags="S",
            )
        )
        bf_alerts.extend(res)
    assert any(a["detector_type"] == "behavioral_bruteforce" for a in bf_alerts)

    # 3) ICMP oversize + flood
    icmp_alerts = []
    for i in range(4):
        res = await engine.process_packet(
            PacketEvent(
                timestamp=105.0 + i * 0.1,
                protocol="icmp",
                src_ip="203.0.113.21",
                dst_ip="192.168.1.10",
                length=512,
            )
        )
        icmp_alerts.extend(res)
    det_types = {a["detector_type"] for a in icmp_alerts}
    assert "behavioral_icmp_tunnel" in det_types
    assert "behavioral_icmp_flood" in det_types

    # 4) DHCP Rogue Server
    dhcp_alerts = await engine.process_packet(
        PacketEvent(
            timestamp=110.0,
            protocol="udp",
            src_ip="192.168.1.222",
            dst_ip="255.255.255.255",
            src_port=67,
            dst_port=68,
        )
    )
    assert any(a["detector_type"] == "behavioral_dhcp_rogue" for a in dhcp_alerts)

    # 5) IOC Match on subdomain and IP
    ioc_alerts = await engine.process_packet(
        PacketEvent(
            timestamp=112.0,
            protocol="udp",
            src_ip="192.168.1.60",
            dst_ip="198.51.100.77",
            dst_port=53,
            dns_query="beacon.bad-c2.example",
        )
    )
    assert any(a["detector_type"] == "ioc_match" for a in ioc_alerts)

    # 6) IP-MAC conflict detection in Database
    first = await db.upsert_device(
        ip="192.168.1.99",
        mac="AA:BB:CC:DD:EE:01",
        vendor="",
        hostname="host-a",
        latency_ms=1.5,
        open_ports=[],
        status="online",
    )
    assert first["mac_conflict"] is False
    second = await db.upsert_device(
        ip="192.168.1.99",
        mac="AA:BB:CC:DD:EE:99",
        vendor="",
        hostname="host-a",
        latency_ms=1.5,
        open_ports=[],
        status="online",
    )
    assert second["mac_conflict"] is True
    assert second["previous_mac"] == "AA:BB:CC:DD:EE:01"


def test_netflow_v5_and_snmp_trap_parsers() -> None:
    # NetFlow v5 Header + 1 TCP flow record
    header = struct.pack(NETFLOW_V5_HEADER_FMT, 5, 1, 1000, 1700000000, 0, 1, 0, 0, 0)
    src_raw = struct.unpack("!I", socket.inet_aton("192.168.1.10"))[0]
    dst_raw = struct.unpack("!I", socket.inet_aton("8.8.8.8"))[0]
    rec = struct.pack(
        NETFLOW_V5_RECORD_FMT,
        src_raw,
        dst_raw,
        0,
        1,
        2,
        12,
        1440,
        10,
        20,
        54321,
        443,
        0,
        0,
        6,  # TCP
        0,
        0,
        0,
        24,
        24,
        0,
    )
    flows = parse_netflow_v5_packet(header + rec, exporter_ip="192.168.1.1")
    assert len(flows) == 1
    assert flows[0]["src_ip"] == "192.168.1.10"
    assert flows[0]["dst_ip"] == "8.8.8.8"
    assert flows[0]["protocol"] == "TCP"
    assert flows[0]["bytes"] == 1440

    collector = NetFlowCollector()
    collector._handle_packet(header + rec, "192.168.1.1")
    summary = collector.get_summary()
    assert summary["status"]["flow_count"] == 1
    assert summary["top_conversations"][0]["bytes"] == 1440

    trap = parse_snmp_trap_payload(b"\x30\x20public\x04\x0blinkDown port3", "192.168.1.2")
    assert trap["source_ip"] == "192.168.1.2"
    assert "linkDown" in trap["summary"]


def test_enterprise_webhook_ssrf_validation() -> None:
    assert validate_enterprise_webhook_url("") == ""
    assert (
        validate_enterprise_webhook_url("https://hooks.example.org/webhook/123")
        == "https://hooks.example.org/webhook/123"
    )
    with pytest.raises(ValueError):
        validate_enterprise_webhook_url("http://hooks.example.org/insecure")
    with pytest.raises(ValueError):
        validate_enterprise_webhook_url("https://127.0.0.1/admin")
    with pytest.raises(ValueError):
        validate_enterprise_webhook_url("https://localhost/internal")


async def test_playbook_engine_auto_incident_and_dry_run_block(tmp_path: Path) -> None:
    db = Database(tmp_path / "pb.db")
    await db.initialize()
    blocker = ActiveResponseBlocker(
        db=db,
        firewall=DummyFirewall(),
        protected_ips={"192.168.1.1"},
        dry_run=True,
        auto_block_enabled=True,
        auto_block_threshold="critical",
    )
    notifier = WebhookNotifier(db=db)
    pb_engine = PlaybookEngine(db=db, blocker=blocker, notifier=notifier)

    await db.create_playbook(
        name="Auto Incident on Critical",
        trigger_severity="critical",
        trigger_detector="any",
        action_type="create_incident",
    )
    actions = await pb_engine.run_for_alert(
        {
            "source_ip": "198.51.100.88",
            "title": "Critical Intrusion",
            "severity": "critical",
            "detector_type": "ioc_match",
        }
    )
    assert len(actions) == 1
    incidents = await db.list_incidents()
    assert len(incidents) == 1
    assert incidents[0]["source_ip"] == "198.51.100.88"


def test_network_soc_endpoints_and_simulator_workflow(tmp_path: Path) -> None:
    with _build_client(tmp_path) as client:
        # IPAM Grid & Reserve / Release
        res_grid = client.get("/api/network/ipam?cidr=192.168.55.0/24")
        assert res_grid.status_code == 200
        assert len(res_grid.json()["slots"]) == 254

        r_res = client.post(
            "/api/network/ipam/reserve",
            json={"ip": "192.168.55.20", "hostname": "xray-01", "mac": "aa:bb:cc:11:22:33", "note": "ER"},
        )
        assert r_res.status_code == 200
        assert client.get("/api/network/ipam?cidr=192.168.55.0/24").json()["counts"]["reserved"] == 1
        assert client.delete("/api/network/ipam/reserve?ip=192.168.55.20").json()["deleted"] is True

        # IDS Tuning + Config Snapshot & Drift Diff
        snap1 = client.post("/api/network/snapshots", json={"name": "Baseline"}).json()
        tune_res = client.put("/api/soc/ids-tuning", json={"bruteforce_threshold": 25})
        assert tune_res.status_code == 200
        assert tune_res.json()["bruteforce_threshold"] == 25
        snap2 = client.post("/api/network/snapshots", json={"name": "Tuned"}).json()

        diff = client.get(f"/api/network/snapshots/diff?a_id={snap1['id']}&b_id={snap2['id']}").json()
        assert diff["drifted"] is True
        assert "bruteforce_threshold" in diff["diff"]

        # IOC API import + Simulator triggers (bruteforce, dns_tunnel, icmp_flood, dhcp_rogue)
        ioc_res = client.post(
            "/api/soc/iocs/import",
            json={"raw_text": "198.51.100.99\nevil.test", "source": "unit", "severity": "critical"},
        )
        assert ioc_res.status_code == 200
        assert ioc_res.json()["imported"] == 2

        for sim_type in ("bruteforce", "dns_tunnel", "icmp_flood", "dhcp_rogue"):
            sim = client.post(
                "/api/alerts/simulate",
                json={"attack_type": sim_type, "attacker_ip": "198.51.100.50", "target_ip": "192.168.1.10"},
            )
            assert sim.status_code == 200
            assert sim.json()["alerts_triggered"] >= 1

        # Playbook API + Incident update API
        pb = client.post(
            "/api/soc/playbooks",
            json={
                "name": "SOC Case",
                "trigger_severity": "high",
                "trigger_detector": "any",
                "action_type": "create_incident",
            },
        )
        assert pb.status_code == 200
        pb_id = pb.json()["id"]
        assert client.patch(f"/api/soc/playbooks/{pb_id}?enabled=false").json()["enabled"] is False
        assert client.delete(f"/api/soc/playbooks/{pb_id}?confirm=true").json()["deleted"] is True

        # Device 360 Timeline & Compliance Scorecard
        d360 = client.get("/api/soc/device-360/198.51.100.50")
        assert d360.status_code == 200
        assert len(d360.json()["alerts"]) >= 1

        comp = client.get("/api/soc/compliance")
        assert comp.status_code == 200
        body = comp.json()
        assert body["total_checks"] == 7
        assert 0 <= body["score_pct"] <= 100
