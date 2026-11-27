"""Linux-specific firewall and network capability adapters."""

from __future__ import annotations

import ipaddress
import os
import platform
import shutil
import socket
import struct
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


class LinuxFirewallAdapter(FirewallAdapter):
    """Linux firewall adapter using iptables without shell=True."""

    backend_name = "linux_iptables"

    async def block_ip(self, ip: str) -> CommandResult:
        safe_ip = validate_ip_address(ip)
        tool = "ip6tables" if ipaddress.ip_address(safe_ip).version == 6 else "iptables"
        cmd = [tool, "-I", "INPUT", "1", "-s", safe_ip, "-j", "DROP"]
        return await run_subprocess(cmd)

    async def unblock_ip(self, ip: str) -> CommandResult:
        safe_ip = validate_ip_address(ip)
        tool = "ip6tables" if ipaddress.ip_address(safe_ip).version == 6 else "iptables"
        cmd = [tool, "-D", "INPUT", "-s", safe_ip, "-j", "DROP"]
        return await run_subprocess(cmd)


class LinuxNetworkHelper(NetworkHelper):
    """Detects root privilege, libpcap presence, and default gateway on Linux."""

    def detect_capabilities(self, firewall_backend: str) -> PlatformCapabilities:
        is_admin = hasattr(os, "geteuid") and os.geteuid() == 0
        npcap_available = any(
            Path(p).exists()
            for p in (
                "/usr/lib/libpcap.so",
                "/usr/lib/x86_64-linux-gnu/libpcap.so.0.8",
                "/usr/lib/aarch64-linux-gnu/libpcap.so.0.8",
            )
        ) or shutil.which("tcpdump") is not None

        gateway = _detect_linux_gateway()
        iface, subnet, local_ips = detect_local_ipv4_interfaces(gateway_ip=gateway)

        return PlatformCapabilities(
            os_name=f"Linux {platform.release()}",
            is_admin=is_admin,
            firewall_backend=firewall_backend,
            npcap_available=npcap_available,
            default_interface=iface,
            default_subnet=subnet,
            gateway_ip=gateway,
            local_ips=local_ips,
        )


def _detect_linux_gateway() -> str | None:
    route_file = Path("/proc/net/route")
    if not route_file.exists():
        return None
    try:
        for line in route_file.read_text(encoding="utf-8").splitlines()[1:]:
            fields = line.strip().split()
            if len(fields) >= 3 and fields[1] == "00000000":
                gw_int = int(fields[2], 16)
                return socket.inet_ntoa(struct.pack("<L", gw_int))
    except Exception:
        return None
    return None
