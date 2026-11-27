"""Base abstractions and shared validation for cross-platform OS modules."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

import psutil


@dataclass(slots=True)
class CommandResult:
    """Structured result from an OS-level command execution."""

    success: bool
    message: str
    command: list[str] = field(default_factory=list)


@dataclass(slots=True)
class PlatformCapabilities:
    """Runtime OS, privilege, and network capabilities."""

    os_name: str
    is_admin: bool
    firewall_backend: str
    npcap_available: bool
    default_interface: str
    default_subnet: str
    gateway_ip: str | None
    local_ips: list[str] = field(default_factory=list)


def validate_ip_address(raw_ip: str) -> str:
    """Strictly parse and normalize an IP address to prevent command injection."""
    cleaned = raw_ip.strip()
    if not cleaned:
        raise ValueError("IP address cannot be empty")
    parsed = ipaddress.ip_address(cleaned)
    return str(parsed)


def detect_local_ipv4_interfaces(gateway_ip: str | None = None) -> tuple[str, str, list[str]]:
    """Discover primary active IPv4 interface, CIDR subnet, and all local IPs."""
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    local_ips: list[str] = ["127.0.0.1"]
    best_iface = ""
    best_subnet = "192.168.1.0/24"
    fallback_iface = ""
    fallback_subnet = "192.168.1.0/24"

    gw_addr: ipaddress.IPv4Address | None = None
    if gateway_ip:
        try:
            parsed_gw = ipaddress.ip_address(gateway_ip)
            if isinstance(parsed_gw, ipaddress.IPv4Address):
                gw_addr = parsed_gw
        except ValueError:
            gw_addr = None

    for iface, addr_list in addrs.items():
        if_stat = stats.get(iface)
        is_up = bool(if_stat and if_stat.isup)
        for addr in addr_list:
            if addr.family == socket.AF_INET and addr.address:
                ip = addr.address
                if ip not in local_ips:
                    local_ips.append(ip)
                if is_up and not ip.startswith("127.") and not ip.startswith("169.254."):
                    netmask = addr.netmask or "255.255.255.0"
                    try:
                        net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                        if net.prefixlen < 20:
                            net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                    except ValueError:
                        continue

                    if gw_addr is not None and gw_addr in net:
                        best_iface = iface
                        best_subnet = str(net)
                    elif not fallback_iface:
                        fallback_iface = iface
                        fallback_subnet = str(net)

    if best_iface:
        return best_iface, best_subnet, local_ips
    return fallback_iface or "default", fallback_subnet, local_ips


class FirewallAdapter(ABC):
    """Abstract OS firewall adapter."""

    backend_name: str = "abstract"

    @abstractmethod
    async def block_ip(self, ip: str) -> CommandResult:
        """Apply an inbound/outbound block rule for a validated IP address."""

    @abstractmethod
    async def unblock_ip(self, ip: str) -> CommandResult:
        """Remove a previously applied block rule for a validated IP address."""


class NetworkHelper(ABC):
    """Abstract OS privilege and network capability detector."""

    @abstractmethod
    def detect_capabilities(self, firewall_backend: str) -> PlatformCapabilities:
        """Inspect OS privileges, packet capture driver, gateway, and subnet."""


async def run_subprocess(cmd: list[str], timeout: float = 5.0) -> CommandResult:
    """Execute a subprocess safely without a shell and return a CommandResult."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        output = (stdout or stderr).decode("utf-8", errors="replace").strip()
        if proc.returncode == 0:
            return CommandResult(success=True, message=output or "OK", command=cmd)
        return CommandResult(
            success=False,
            message=output or f"Command exited with code {proc.returncode}",
            command=cmd,
        )
    except Exception as exc:
        return CommandResult(success=False, message=str(exc), command=cmd)
