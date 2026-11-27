"""Windows-specific firewall and network capability adapters."""

from __future__ import annotations

import ctypes
import os
import platform
import subprocess
from pathlib import Path

from app.platform.base import (
    CommandResult,
    FirewallAdapter,
    NetworkHelper,
    PlatformCapabilities,
    detect_local_ipv4_interfaces,
    run_subprocess,
    validate_ip_address,
)


RULE_PREFIX = "NetSentinel_Block_"


class WindowsFirewallAdapter(FirewallAdapter):
    """Windows Defender Firewall adapter using netsh advfirewall without shell=True."""

    backend_name = "windows_netsh"

    async def block_ip(self, ip: str) -> CommandResult:
        safe_ip = validate_ip_address(ip)
        rule_name = f"{RULE_PREFIX}{safe_ip}"
        cmd = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={safe_ip}",
            "enable=yes",
        ]
        return await run_subprocess(cmd)

    async def unblock_ip(self, ip: str) -> CommandResult:
        safe_ip = validate_ip_address(ip)
        rule_name = f"{RULE_PREFIX}{safe_ip}"
        cmd = [
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f"name={rule_name}",
        ]
        return await run_subprocess(cmd)


class WindowsNetworkHelper(NetworkHelper):
    """Detects Windows admin elevation, Npcap driver, and default gateway."""

    def detect_capabilities(self, firewall_backend: str) -> PlatformCapabilities:
        is_admin = False
        try:
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            is_admin = False

        sys_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        npcap_available = (sys_root / "System32" / "Npcap").exists()

        gateway = _detect_windows_gateway()
        iface, subnet, local_ips = detect_local_ipv4_interfaces(gateway_ip=gateway)

        return PlatformCapabilities(
            os_name=f"Windows {platform.release()}",
            is_admin=is_admin,
            firewall_backend=firewall_backend,
            npcap_available=npcap_available,
            default_interface=iface,
            default_subnet=subnet,
            gateway_ip=gateway,
            local_ips=local_ips,
        )


def _detect_windows_gateway() -> str | None:
    try:
        from scapy.all import conf  # type: ignore

        gw = conf.route.route("0.0.0.0")[2]
        if gw and gw != "0.0.0.0":
            return gw
    except Exception:
        pass
    try:
        out = subprocess.check_output(
            ["route", "print", "0.0.0.0"],
            text=True,
            timeout=2,
            stderr=subprocess.DEVNULL,
        )
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                return parts[2]
    except Exception:
        pass
    return None
