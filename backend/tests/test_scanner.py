"""Tests for SubnetScanner CIDR boundaries, OUI lookup, and localhost scan."""

from pathlib import Path

import pytest

from app.core.scanner import SubnetScanner, lookup_vendor, validate_subnet
from app.db.database import Database


def test_validate_subnet_boundaries() -> None:
    net = validate_subnet("192.168.1.15/24", max_prefix=20)
    assert str(net) == "192.168.1.0/24"

    for invalid in ("", "   ", "not-a-cidr", "10.0.0.0/8", "0.0.0.0/0", "::1/128"):
        with pytest.raises(ValueError):
            validate_subnet(invalid, max_prefix=20)


def test_lookup_vendor() -> None:
    assert lookup_vendor("b8-27-eb-11-22-33") == "Raspberry Pi"
    assert lookup_vendor("00:50:56:AA:BB:CC") == "VMware"
    assert lookup_vendor("") == "Unknown"


async def test_scan_localhost_single_ip(tmp_path: Path) -> None:
    db = Database(tmp_path / "scanner.db")
    await db.initialize()
    scanner = SubnetScanner(db=db, max_prefix=20)

    summary = await scanner.scan_subnet("127.0.0.1/32", scan_ports=False)
    assert summary["cidr"] == "127.0.0.1/32"
    assert summary["scanned_hosts"] == 1
    assert summary["online_count"] == 1

    devices = await db.list_devices()
    assert len(devices) == 1
    assert devices[0]["ip"] == "127.0.0.1"
