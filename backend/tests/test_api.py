"""Integration & security tests for FastAPI REST endpoints."""

from pathlib import Path

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def _build_client(tmp_path: Path) -> TestClient:
    rules_file = tmp_path / "test.rules"
    rules_file.write_text(
        'alert tcp any any -> any 23 (msg:"Telnet Test"; sid:9001; priority:2;)\n'
        'alert tcp any any -> any 80 (msg:"SQLi Test"; content:"UNION SELECT"; nocase; sid:9002; priority:1;)\n',
        encoding="utf-8",
    )
    cfg = Settings(
        db_path=tmp_path / "api_test.db",
        snort_rules_path=rules_file,
        dry_run=True,
        auto_block_enabled=False,
    )
    app = create_app(cfg)
    return TestClient(app)


def test_system_status_and_security_headers(tmp_path: Path) -> None:
    with _build_client(tmp_path) as client:
        res = client.get(
            "/api/system/status",
            headers={"Origin": "http://localhost:5173"},
        )
        assert res.status_code == 200
        body = res.json()
        assert body["db_healthy"] is True
        assert body["policy"]["dry_run"] is True
        assert body["rules_loaded"] == 2
        assert res.headers["x-content-type-options"] == "nosniff"
        assert res.headers["x-frame-options"] == "DENY"
        assert res.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_confirmation_required_for_destructive_and_live_actions(tmp_path: Path) -> None:
    with _build_client(tmp_path) as client:
        # Turning off dry-run without confirm=true must fail 400
        r1 = client.put("/api/firewall/policy", json={"dry_run": False, "confirm": False})
        assert r1.status_code == 400

        # Blocking without confirm=true must fail 400
        r2 = client.post(
            "/api/firewall/block",
            json={"ip": "203.0.113.10", "reason": "test", "confirm": False},
        )
        assert r2.status_code == 400

        # Clearing alerts without confirm=true must fail 400
        r3 = client.delete("/api/alerts")
        assert r3.status_code == 400

        # Blocking protected loopback IP even with confirm=true must fail 403
        r4 = client.post(
            "/api/firewall/block",
            json={"ip": "127.0.0.1", "reason": "test", "confirm": True},
        )
        assert r4.status_code == 403


def test_simulate_attack_persists_and_clears_alerts(tmp_path: Path) -> None:
    with _build_client(tmp_path) as client:
        sim = client.post(
            "/api/alerts/simulate",
            json={
                "attack_type": "port_scan",
                "attacker_ip": "203.0.113.55",
                "target_ip": "192.168.1.10",
            },
        )
        assert sim.status_code == 200
        assert sim.json()["alerts_triggered"] == 1

        listed = client.get("/api/alerts")
        assert listed.status_code == 200
        assert listed.json()["counts"]["total"] == 1

        cleared = client.delete("/api/alerts?confirm=true")
        assert cleared.status_code == 200
        assert cleared.json()["deleted"] == 1


def test_fail_closed_when_database_unavailable(tmp_path: Path) -> None:
    rules_file = tmp_path / "test.rules"
    rules_file.write_text('alert tcp any any -> any 23 (msg:"Telnet"; sid:9001;)\n', encoding="utf-8")
    cfg = Settings(
        db_path=tmp_path / "api_test.db",
        snort_rules_path=rules_file,
        dry_run=True,
    )
    app = create_app(cfg)
    with TestClient(app, raise_server_exceptions=False) as err_client:
        services = err_client.app.state.services  # type: ignore[attr-defined]
        services.db.db_path = tmp_path / "missing_dir" / "broken.db"
        err_res = err_client.get("/api/alerts")
        assert err_res.status_code == 503
        assert "Database" in err_res.json()["detail"] or "Service" in err_res.json()["detail"]
        assert "Traceback" not in err_res.text
