"""Tests for Process-to-Network, Wi-Fi Analyzer, Traceroute parser, HTTP/SSL validation, and Tools API."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.core.diagnostics import parse_traceroute_output, validate_diagnostic_target
from app.core.http_monitor import validate_monitor_url
from app.core.process_net import list_process_connections
from app.core.wifi_analyzer import (
    parse_windows_wlan_interfaces,
    parse_windows_wlan_networks,
    recommend_clean_24ghz_channel,
)
from app.main import create_app


def test_process_connections_snapshot() -> None:
    res = list_process_connections(limit=20)
    assert "connections" in res
    assert "process_summary" in res


def test_wifi_parsers_and_channel_recommendation() -> None:
    iface_sample = """
    Name                   : Wi-Fi
    State                  : connected
    SSID                   : MyHomeWiFi
    BSSID                  : aa:bb:cc:11:22:33
    Radio type             : 802.11ax
    Channel                : 6
    Receive rate (Mbps)    : 866.7
    Transmit rate (Mbps)   : 780.0
    Signal                 : 92%
    """
    parsed_iface = parse_windows_wlan_interfaces(iface_sample)
    assert parsed_iface["ssid"] == "MyHomeWiFi"
    assert parsed_iface["channel"] == 6
    assert parsed_iface["signal_pct"] == 92

    nets_sample = """
    SSID 1 : NeighborA
        Authentication          : WPA2-Personal
        BSSID 1                 : 11:22:33:44:55:01
            Signal              : 75%
            Channel             : 1
    SSID 2 : NeighborB
        Authentication          : WPA2-Personal
        BSSID 1                 : 11:22:33:44:55:02
            Signal              : 60%
            Channel             : 6
    """
    neighbors = parse_windows_wlan_networks(nets_sample)
    assert len(neighbors) == 2
    assert recommend_clean_24ghz_channel(neighbors) == 11


def test_traceroute_validation_and_parser() -> None:
    assert validate_diagnostic_target("1.1.1.1") == "1.1.1.1"
    assert validate_diagnostic_target("example.com") == "example.com"
    for bad in ("", "1.1.1.1 && calc.exe", "-invalid", "host;ls"):
        with pytest.raises(ValueError):
            validate_diagnostic_target(bad)

    sample = """
      1     2 ms     1 ms     2 ms  192.168.1.1
      2     *        *        *     Request timed out.
      3    11 ms    10 ms    12 ms  1.1.1.1
    """
    hops = parse_traceroute_output(sample)
    assert len(hops) == 3
    assert hops[0]["ip"] == "192.168.1.1"
    assert hops[1]["timed_out"] is True
    assert hops[2]["rtt_ms"] == 11.0


def test_http_monitor_url_ssrf_guards() -> None:
    assert validate_monitor_url("https://example.com") == "https://example.com"
    assert validate_monitor_url("http://192.168.1.1") == "http://192.168.1.1"
    for bad in (
        "ftp://example.com/file",
        "http://user:pass@example.com",
        "http://169.254.169.254/latest/meta-data/",
        "javascript:alert(1)",
    ):
        with pytest.raises(ValueError):
            validate_monitor_url(bad)


def test_tools_api_monitors_and_guards(tmp_path: Path) -> None:
    rules_file = tmp_path / "test.rules"
    rules_file.write_text('alert tcp any any -> any 23 (msg:"Telnet"; sid:9001;)\n', encoding="utf-8")
    cfg = Settings(db_path=tmp_path / "tools.db", snort_rules_path=rules_file, dry_run=True)

    with TestClient(create_app(cfg)) as client:
        proc_res = client.get("/api/tools/process-connections")
        assert proc_res.status_code == 200

        bad_trace = client.post("/api/tools/traceroute", json={"target": "1.1.1.1; whoami"})
        assert bad_trace.status_code == 400

        bad_mon = client.post(
            "/api/tools/monitors",
            json={"name": "Metadata", "url": "http://169.254.169.254/latest"},
        )
        assert bad_mon.status_code == 400

        ok_mon = client.post(
            "/api/tools/monitors",
            json={"name": "Router", "url": "http://192.168.1.1"},
        )
        assert ok_mon.status_code == 200
        mon_id = ok_mon.json()["id"]

        # Delete without confirm must fail 400
        del_no_confirm = client.delete(f"/api/tools/monitors/{mon_id}")
        assert del_no_confirm.status_code == 400

        del_ok = client.delete(f"/api/tools/monitors/{mon_id}?confirm=true")
        assert del_ok.status_code == 200
