"""Tests for OUI private MAC detection, Wake-on-LAN, Trust/History, Schedule, and Webhooks."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.core.notifier import mask_secret, validate_discord_webhook_url
from app.core.oui import is_randomized_mac, lookup_vendor
from app.core.wol import build_magic_packet
from app.db.database import Database
from app.main import create_app


def test_oui_and_randomized_mac_detection() -> None:
    assert lookup_vendor("A4:83:E7:11:22:33") == "Apple"
    assert lookup_vendor("7C:9E:BD:AA:BB:CC") == "Espressif IoT"
    # Locally-administered unicast MAC (bit 1 of first byte set, bit 0 clear)
    assert is_randomized_mac("DA:A1:19:11:22:33") is True
    assert lookup_vendor("DA:A1:19:11:22:33") == "Private / Randomized MAC (Mobile)"


def test_wol_magic_packet_and_validation() -> None:
    pkt = build_magic_packet("aa-bb-cc-11-22-33")
    assert len(pkt) == 102
    assert pkt[:6] == b"\xff" * 6
    assert pkt[6:12] == bytes.fromhex("aabbcc112233")

    with pytest.raises(ValueError):
        build_magic_packet("not-a-mac")


def test_webhook_ssrf_and_masking() -> None:
    for bad in (
        "http://127.0.0.1:8000/hook",
        "http://localhost/admin",
        "https://evil.example.com/api/webhooks/123",
        "https://discord.com/other/path",
    ):
        with pytest.raises(ValueError):
            validate_discord_webhook_url(bad)

    ok = validate_discord_webhook_url("https://discord.com/api/webhooks/123456789/secretTokenXYZ")
    assert ok.startswith("https://discord.com/api/webhooks/")
    masked = mask_secret(ok)
    assert "secretTokenXYZ" not in masked
    assert "****" in masked


async def test_device_trust_and_history_persistence(tmp_path: Path) -> None:
    db = Database(tmp_path / "ext.db")
    await db.initialize()

    res = await db.upsert_device(
        ip="192.168.1.88",
        mac="A4:83:E7:01:02:03",
        vendor="Apple",
        hostname="iphone.local",
        latency_ms=12.4,
        open_ports=[],
        status="online",
    )
    assert res["is_new"] is True
    assert res["trusted"] is False

    updated = await db.update_device_metadata(
        "192.168.1.88", custom_name="My iPhone", trusted=True
    )
    assert updated is not None
    assert updated["custom_name"] == "My iPhone"
    assert updated["trusted"] is True

    history = await db.get_device_history("192.168.1.88")
    assert len(history) == 1
    assert history[0]["latency_ms"] == 12.4


def test_extensions_api_endpoints(tmp_path: Path) -> None:
    rules_file = tmp_path / "test.rules"
    rules_file.write_text('alert tcp any any -> any 23 (msg:"Telnet"; sid:9001;)\n', encoding="utf-8")
    cfg = Settings(db_path=tmp_path / "ext_api.db", snort_rules_path=rules_file, dry_run=True)

    with TestClient(create_app(cfg)) as client:
        # Scan localhost first so a device exists, then test PATCH & WoL confirm guard
        scan_res = client.post("/api/devices/scan", json={"cidr": "127.0.0.1/32", "scan_ports": False})
        assert scan_res.status_code == 200

        patch_res = client.patch(
            "/api/devices/127.0.0.1",
            json={"custom_name": "Localhost", "trusted": True},
        )
        assert patch_res.status_code == 200
        assert patch_res.json()["trusted"] is True

        wol_no_confirm = client.post("/api/devices/127.0.0.1/wol", json={"confirm": False})
        assert wol_no_confirm.status_code == 400

        # Update auto-scan schedule (use /32 during test)
        sched = client.put(
            "/api/devices/schedule",
            json={"enabled": True, "interval_seconds": 60, "cidr": "127.0.0.1/32"},
        )
        assert sched.status_code == 200
        assert sched.json()["enabled"] is True
        assert sched.json()["interval_seconds"] == 60

        # Webhook SSRF check & secret masking via API
        bad_wh = client.put(
            "/api/webhooks",
            json={"discord_webhook_url": "http://127.0.0.1:9999/steal"},
        )
        assert bad_wh.status_code == 400

        ok_wh = client.put(
            "/api/webhooks",
            json={
                "enabled": True,
                "min_severity": "critical",
                "discord_webhook_url": "https://discord.com/api/webhooks/111222/myVerySecretToken999",
            },
        )
        assert ok_wh.status_code == 200
        assert ok_wh.json()["discord_configured"] is True
        assert "myVerySecretToken999" not in ok_wh.json()["discord_masked"]
