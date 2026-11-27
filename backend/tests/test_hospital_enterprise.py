"""Tests for Hospital Safe Mode, Medical VLAN Exclusions, PDPA Privacy, Suricata eve.json, RBAC, and Audit Logs."""

from pathlib import Path

from fastapi.testclient import TestClient

from app.config import Settings
from app.core.ids_engine import PacketEvent
from app.core.suricata_parser import parse_suricata_eve_lines
from app.main import create_app


def test_suricata_eve_parser() -> None:
    ndjson = (
        '{"event_type":"alert","src_ip":"203.0.113.5","dest_ip":"192.168.1.10","proto":"TCP","src_port":5555,"dest_port":80,"alert":{"signature":"ET EXPLOIT Test","signature_id":2010001,"category":"Attempted Admin","severity":1}}\n'
        '{"event_type":"dns","src_ip":"192.168.1.25","dns":{"rrname":"bad.example.com"}}\n'
        '{broken json line}\n'
    )
    parsed = parse_suricata_eve_lines(ndjson)
    assert len(parsed["alerts"]) == 1
    assert parsed["alerts"][0]["severity"] == "critical"
    assert parsed["alerts"][0]["rule_sid"] == 2010001
    assert len(parsed["dns"]) == 1
    assert parsed["dns"][0]["domain"] == "bad.example.com"
    assert len(parsed["errors"]) == 1


def test_hospital_safe_mode_exclusions_and_pdpa(tmp_path: Path) -> None:
    rules_file = tmp_path / "test.rules"
    rules_file.write_text('alert tcp any any -> any 23 (msg:"Telnet"; sid:9001;)\n', encoding="utf-8")
    cfg = Settings(db_path=tmp_path / "hosp.db", snort_rules_path=rules_file, dry_run=False)

    with TestClient(create_app(cfg)) as client:
        # 1) Add Medical VLAN exclusion CIDR
        ex = client.post("/api/enterprise/exclusions", json={"cidr": "10.50.0.0/24"})
        assert ex.status_code == 200

        # Scanning excluded VLAN must be forbidden (403)
        scan_blocked = client.post("/api/devices/scan", json={"cidr": "10.50.0.0/24"})
        assert scan_blocked.status_code == 403

        # Blocking IP inside excluded VLAN must be forbidden (403 whitelist)
        blk_blocked = client.post(
            "/api/firewall/block",
            json={"ip": "10.50.0.25", "reason": "test", "confirm": True},
        )
        assert blk_blocked.status_code == 403

        # 2) Enable Hospital Safe Mode -> enforces PDPA privacy mode & forces passive dry-run
        hosp = client.put("/api/enterprise/safety", json={"profile": "hospital_safe"})
        assert hosp.status_code == 200
        assert hosp.json()["is_hospital_safe"] is True
        assert hosp.json()["privacy_mode"] is True

        # Synthetic packet in privacy mode must redact payload
        sniffer = client.app.state.services.sniffer  # type: ignore[attr-defined]
        sniffer.record_synthetic_packet(
            PacketEvent(
                timestamp=1700000000.0,
                protocol="tcp",
                src_ip="192.168.1.10",
                dst_ip="192.168.1.20",
                payload="PATIENT_NAME=JOHN_DOE",
                length=80,
            )
        )
        pkts = client.get("/api/system/packets").json()["packets"]
        assert "[REDACTED" in pkts[0]["preview"]
        assert pkts[0]["hex_dump"] == ""


def test_rbac_roles_audit_and_remote_sensor_ingest(tmp_path: Path) -> None:
    rules_file = tmp_path / "test.rules"
    rules_file.write_text('alert tcp any any -> any 23 (msg:"Telnet"; sid:9001;)\n', encoding="utf-8")
    cfg = Settings(db_path=tmp_path / "rbac.db", snort_rules_path=rules_file, dry_run=True)

    with TestClient(create_app(cfg)) as client:
        # Create Admin and Viewer accounts
        admin_res = client.post(
            "/api/auth/users",
            json={"username": "hosp_admin", "password": "admin-password", "role": "admin"},
        )
        assert admin_res.status_code == 200

        admin_login = client.post(
            "/api/auth/user-login",
            json={"username": "hosp_admin", "password": "admin-password"},
        )
        assert admin_login.status_code == 200
        admin_tok = admin_login.json()["token"]

        viewer_res = client.post(
            "/api/auth/users",
            json={"username": "nurse_viewer", "password": "viewer-password", "role": "viewer"},
            headers={"X-NetSentinel-Token": admin_tok},
        )
        assert viewer_res.status_code == 200

        viewer_tok = client.post(
            "/api/auth/user-login",
            json={"username": "nurse_viewer", "password": "viewer-password"},
        ).json()["token"]

        # Viewer can GET status (200) but cannot mutate (403)
        assert (
            client.get("/api/system/status", headers={"X-NetSentinel-Token": viewer_tok}).status_code
            == 200
        )
        assert (
            client.post(
                "/api/alerts/simulate",
                json={"attack_type": "port_scan"},
                headers={"X-NetSentinel-Token": viewer_tok},
            ).status_code
            == 403
        )

        # Register remote VLAN sensor & ingest Suricata eve.json via X-Sensor-Key
        sen = client.post(
            "/api/enterprise/sensors",
            json={"name": "ICU-Mirror", "vlan": "VLAN-30"},
            headers={"X-NetSentinel-Token": admin_tok},
        )
        assert sen.status_code == 200
        sensor_key = sen.json()["api_key"]

        bad_ingest = client.post(
            "/api/enterprise/sensors/ingest",
            headers={"X-Sensor-Key": "wrong_key"},
            json={"devices": []},
        )
        assert bad_ingest.status_code == 401

        ok_ingest = client.post(
            "/api/enterprise/sensors/ingest",
            headers={"X-Sensor-Key": sensor_key},
            json={
                "devices": [{"ip": "192.168.30.15", "mac": "00:11:32:AA:BB:CC", "vendor": "Synology"}],
                "suricata_eve_ndjson": '{"event_type":"alert","src_ip":"203.0.113.77","dest_ip":"192.168.30.15","proto":"TCP","alert":{"signature":"ET POLICY Medical HL7 Anomaly","signature_id":999001,"severity":2}}',
            },
        )
        assert ok_ingest.status_code == 200
        assert ok_ingest.json()["devices_upserted"] == 1
        assert ok_ingest.json()["alerts_imported"] == 1

        # Audit trail must contain recorded admin actions
        logs = client.get(
            "/api/enterprise/audit-logs", headers={"X-NetSentinel-Token": admin_tok}
        ).json()["logs"]
        assert len(logs) >= 2
