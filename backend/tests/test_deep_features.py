"""Tests for Deep Packet Inspector, PCAP export, Top Talkers/DNS/Outbound, Risk Score, and CSV Reports."""

from pathlib import Path

from fastapi.testclient import TestClient

from app.api.reports import sanitize_csv_cell
from app.config import Settings
from app.core.blocker import ActiveResponseBlocker
from app.core.ids_engine import IDSEngine, PacketEvent, format_hex_dump
from app.core.risk import calculate_device_risk
from app.core.sniffer import PacketSniffer
from app.db.database import Database
from app.main import create_app
from app.platform.base import CommandResult, FirewallAdapter


class NoopFirewall(FirewallAdapter):
    backend_name = "noop"

    async def block_ip(self, ip: str) -> CommandResult:
        return CommandResult(success=True, message="ok")

    async def unblock_ip(self, ip: str) -> CommandResult:
        return CommandResult(success=True, message="ok")


def test_risk_score_grades_and_reasons() -> None:
    low_risk = calculate_device_risk(
        {"ip": "192.168.1.5", "trusted": True, "open_ports": [{"port": 443, "service": "HTTPS"}]},
        recent_alert_count=0,
    )
    assert low_risk["risk_grade"] == "A"
    assert low_risk["risk_score"] == 0

    high_risk = calculate_device_risk(
        {
            "ip": "192.168.1.99",
            "trusted": False,
            "open_ports": [{"port": 23, "service": "Telnet"}, {"port": 445, "service": "SMB"}],
        },
        recent_alert_count=2,
    )
    assert high_risk["risk_score"] >= 70
    assert high_risk["risk_grade"] == "F"
    assert len(high_risk["risk_reasons"]) >= 3


def test_hex_dump_and_pcap_export(tmp_path: Path) -> None:
    dump = format_hex_dump(b"GET / HTTP/1.1\r\n")
    assert "47 45 54" in dump
    assert "GET / HTTP/1.1" in dump

    db = Database(tmp_path / "pcap.db")
    blocker = ActiveResponseBlocker(db=db, firewall=NoopFirewall(), protected_ips=set())
    engine = IDSEngine(db=db, blocker=blocker)
    sniffer = PacketSniffer(ids_engine=engine)

    # Inject a DNS query & an outbound public IP packet
    sniffer.record_synthetic_packet(
        PacketEvent(
            timestamp=1700000000.5,
            protocol="udp",
            src_ip="192.168.1.43",
            dst_ip="8.8.8.8",
            src_port=51234,
            dst_port=53,
            dns_query="example.com.",
            payload="dns-query",
            length=74,
        )
    )

    telemetry = sniffer.get_telemetry()
    assert telemetry["total_packets"] == 1
    assert telemetry["protocol_counts"]["UDP"] == 1
    assert telemetry["top_talkers"][0]["ip"] == "192.168.1.43"
    assert telemetry["dns_queries"][0]["domain"] == "example.com"
    assert telemetry["outbound_connections"][0]["dst_ip"] == "8.8.8.8"

    pcap = sniffer.export_pcap_bytes()
    # Libpcap little-endian magic bytes d4 c3 b2 a1
    assert pcap[:4] == b"\xd4\xc3\xb2\xa1"
    assert len(pcap) > 24


def test_csv_formula_injection_sanitization() -> None:
    assert sanitize_csv_cell("=CMD|'/C calc'!A0") == "'=CMD|'/C calc'!A0"
    assert sanitize_csv_cell("+SUM(A1:A2)") == "'+SUM(A1:A2)"
    assert sanitize_csv_cell("normal_host") == "normal_host"


def test_telemetry_pcap_and_reports_api(tmp_path: Path) -> None:
    rules_file = tmp_path / "test.rules"
    rules_file.write_text(
        'alert tcp any any -> any 23 (msg:"Telnet"; sid:9001;)\n'
        'alert tcp any any -> any 80 (msg:"SQLi"; content:"UNION SELECT"; nocase; sid:9002; priority:1;)\n',
        encoding="utf-8",
    )
    cfg = Settings(db_path=tmp_path / "deep_api.db", snort_rules_path=rules_file, dry_run=True)

    with TestClient(create_app(cfg)) as client:
        sim_res = client.post(
            "/api/alerts/simulate",
            json={"attack_type": "snort_sqli", "attacker_ip": "203.0.113.55", "target_ip": "192.168.1.10"},
        )
        assert sim_res.status_code == 200
        assert sim_res.json()["alerts_triggered"] >= 1

        telem = client.get("/api/system/telemetry")
        assert telem.status_code == 200
        assert telem.json()["total_packets"] >= 1

        pcap_res = client.get("/api/system/pcap/export")
        assert pcap_res.status_code == 200
        assert pcap_res.content[:4] == b"\xd4\xc3\xb2\xa1"

        summary_res = client.get("/api/reports/summary")
        assert summary_res.status_code == 200
        assert summary_res.json()["alert_summary"]["total"] >= 1

        csv_res = client.get("/api/reports/export.csv")
        assert csv_res.status_code == 200
        assert "NETSENTINEL DEVICE" in csv_res.text
        assert "NETSENTINEL IDS ALERTS" in csv_res.text
