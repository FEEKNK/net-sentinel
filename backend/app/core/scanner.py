"""IP/Subnet Scanner, OUI Vendor Lookup, Latency, and TCP Port Scanner."""

from __future__ import annotations

import asyncio
import ipaddress
import platform
import re
import socket
import subprocess
import time
from typing import Any, Callable, Awaitable

from app.db.database import Database


COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    135: "RPC",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
}

# Offline OUI vendor prefix table for common LAN/home/enterprise devices
OUI_VENDORS: dict[str, str] = {
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "08:00:27": "Oracle VirtualBox",
    "52:54:00": "QEMU/KVM",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "00:1A:2B": "Ayecom / Router",
    "18:D6:C7": "TP-Link",
    "50:C7:BF": "TP-Link",
    "60:32:B1": "TP-Link",
    "B0:BE:76": "TP-Link",
    "04:D4:C4": "ASUS",
    "2C:FD:A1": "ASUS",
    "38:D5:47": "ASUS",
    "00:1B:63": "Apple",
    "3C:15:C2": "Apple",
    "A4:83:E7": "Apple",
    "F0:18:98": "Apple",
    "24:5E:BE": "QNAP",
    "00:11:32": "Synology",
    "18:E8:29": "Ubiquiti",
    "74:83:C2": "Ubiquiti",
    "CC:2D:E0": "MikroTik",
    "48:A9:8A": "MikroTik",
    "00:15:5D": "Microsoft Hyper-V",
    "D8:BB:C1": "Micro-Star (MSI)",
    "A8:A1:59": "ASRock",
    "70:85:C2": "ASRock",
    "00:E0:4C": "Realtek",
    "80:FA:5B": "Clevo / Laptop",
    "98:FA:9B": "Lenovo",
    "00:1E:67": "Intel",
    "3C:97:0E": "Wistron / Lenovo",
    "28:CD:C1": "Raspberry Pi",
    "24:6F:28": "Espressif IoT",
    "30:AE:A4": "Espressif IoT",
}

ARP_LINE_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})"
)


def lookup_vendor(mac: str) -> str:
    """Resolve vendor name from MAC OUI prefix offline."""
    if not mac:
        return "Unknown"
    normalized = mac.strip().upper().replace("-", ":")
    prefix = normalized[:8]
    return OUI_VENDORS.get(prefix, "Unknown")


def validate_subnet(cidr: str, max_prefix: int = 20) -> ipaddress.IPv4Network:
    """Validate IPv4 CIDR and enforce prefix size limit to prevent scan DoS."""
    cleaned = cidr.strip()
    if not cleaned:
        raise ValueError("Subnet CIDR cannot be empty")
    try:
        network = ipaddress.ip_network(cleaned, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR format: {cleaned}") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("Only IPv4 subnets are currently supported for sweeping")
    if network.prefixlen < max_prefix:
        raise ValueError(
            f"Subnet /{network.prefixlen} is too large; minimum allowed prefix is /{max_prefix} (max 4096 hosts)"
        )
    return network


class SubnetScanner:
    """Discovers active hosts in a subnet via ARP/ICMP + TCP port probing."""

    def __init__(self, db: Database, max_prefix: int = 20) -> None:
        self.db = db
        self.max_prefix = max_prefix
        self._scanning = False

    @property
    def is_scanning(self) -> bool:
        return self._scanning

    async def scan_subnet(
        self,
        cidr: str,
        *,
        scan_ports: bool = True,
        on_progress: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    ) -> dict[str, Any]:
        """Sweep the requested subnet and persist discovered hosts in SQLite."""
        network = validate_subnet(cidr, max_prefix=self.max_prefix)
        if self._scanning:
            raise RuntimeError("A subnet scan is already in progress")

        self._scanning = True
        started = time.perf_counter()
        try:
            hosts = [str(ip) for ip in network.hosts()] or [str(network.network_address)]
            if on_progress:
                await on_progress({"event": "scan_started", "cidr": str(network), "total_hosts": len(hosts)})

            # 1) Try fast ARP sweep via Scapy (works with Npcap/libpcap + privileges)
            arp_map = await asyncio.to_thread(_try_scapy_arp_sweep, str(network))

            # 2) Concurrent ICMP ping + fallback ARP table merge
            ping_sem = asyncio.Semaphore(48)
            ping_results = await asyncio.gather(
                *[_ping_host(ip, ping_sem) for ip in hosts]
            )
            os_arp = await asyncio.to_thread(_read_os_arp_cache)

            online_hosts: dict[str, dict[str, Any]] = {}
            for ip, rtt in ping_results:
                mac = arp_map.get(ip) or os_arp.get(ip, "")
                if rtt is not None or ip in arp_map:
                    online_hosts[ip] = {
                        "ip": ip,
                        "mac": mac.upper().replace("-", ":") if mac else "",
                        "latency_ms": round(rtt, 2) if rtt is not None else None,
                    }

            # 3) Resolve hostnames & open TCP ports concurrently
            port_sem = asyncio.Semaphore(64)
            enriched: list[dict[str, Any]] = []

            async def enrich_host(entry: dict[str, Any]) -> dict[str, Any]:
                ip = entry["ip"]
                hostname = await asyncio.to_thread(_resolve_hostname, ip)
                open_ports: list[dict[str, Any]] = []
                if scan_ports:
                    open_ports = await _scan_common_ports(ip, port_sem)
                vendor = lookup_vendor(entry["mac"])
                record = {
                    "ip": ip,
                    "mac": entry["mac"],
                    "vendor": vendor,
                    "hostname": hostname,
                    "latency_ms": entry["latency_ms"],
                    "open_ports": open_ports,
                    "status": "online",
                }
                await self.db.upsert_device(**record)
                return record

            if online_hosts:
                enriched = await asyncio.gather(
                    *[enrich_host(info) for info in online_hosts.values()]
                )

            await self.db.mark_devices_offline_except(set(online_hosts.keys()))

            duration_ms = round((time.perf_counter() - started) * 1000, 1)
            summary = {
                "cidr": str(network),
                "scanned_hosts": len(hosts),
                "online_count": len(enriched),
                "duration_ms": duration_ms,
                "devices": enriched,
            }
            if on_progress:
                await on_progress({"event": "scan_completed", **summary})
            return summary
        finally:
            self._scanning = False


def _try_scapy_arp_sweep(cidr: str) -> dict[str, str]:
    """Attempt Layer-2 ARP sweep with Scapy; returns empty dict if unavailable."""
    try:
        from scapy.all import ARP, Ether, srp  # type: ignore

        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
        answered, _ = srp(packet, timeout=1.5, verbose=0)
        return {str(rcv.psrc): str(rcv.hwsrc).upper() for _, rcv in answered}
    except Exception:
        return {}


def _read_os_arp_cache() -> dict[str, str]:
    """Read OS ARP cache (`arp -a`) as a lightweight MAC fallback."""
    try:
        out = subprocess.check_output(["arp", "-a"], text=True, timeout=2, stderr=subprocess.DEVNULL)
        result: dict[str, str] = {}
        for match in ARP_LINE_RE.finditer(out):
            ip, mac = match.groups()
            if mac.lower() != "ff-ff-ff-ff-ff-ff" and mac.lower() != "ff:ff:ff:ff:ff:ff":
                result[ip] = mac.upper().replace("-", ":")
        return result
    except Exception:
        return {}


async def _ping_host(ip: str, sem: asyncio.Semaphore) -> tuple[str, float | None]:
    """Ping a single IP using OS ping without shell=True."""
    async with sem:
        is_win = platform.system().lower() == "windows"
        cmd = ["ping", "-n", "1", "-w", "450", ip] if is_win else ["ping", "-c", "1", "-W", "1", ip]
        started = time.perf_counter()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=1.2)
            elapsed = (time.perf_counter() - started) * 1000
            if proc.returncode == 0:
                text = stdout.decode("utf-8", errors="replace")
                m = re.search(r"time[=<]\s*([\d.]+)\s*ms", text, re.IGNORECASE)
                rtt = float(m.group(1)) if m else elapsed
                return ip, rtt
        except Exception:
            pass
        return ip, None


def _resolve_hostname(ip: str) -> str:
    try:
        socket.setdefaulttimeout(0.5)
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return ""


async def _scan_common_ports(ip: str, sem: asyncio.Semaphore) -> list[dict[str, Any]]:
    """Probe common TCP ports concurrently using non-blocking sockets."""

    async def probe(port: int, service: str) -> dict[str, Any] | None:
        async with sem:
            try:
                conn = asyncio.open_connection(ip, port)
                _, writer = await asyncio.wait_for(conn, timeout=0.35)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return {"port": port, "service": service}
            except Exception:
                return None

    results = await asyncio.gather(*[probe(p, svc) for p, svc in COMMON_PORTS.items()])
    return [r for r in results if r is not None]
