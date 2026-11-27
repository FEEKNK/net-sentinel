"""IP/Subnet Scanner, OUI Vendor Lookup, mDNS/NetBIOS Discovery, and Port Scanner."""

from __future__ import annotations

import asyncio
import ipaddress
import platform
import re
import socket
import ssl
import struct
import subprocess
import time
from typing import Any, Awaitable, Callable

from app.core.oui import lookup_vendor
from app.db.database import Database


COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    104: "DICOM-Medical",
    135: "RPC",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    2575: "HL7-Medical",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    11112: "DICOM-TLS",
}

ARP_LINE_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})"
)


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


UDP_COMMON_PORTS: dict[int, str] = {
    53: "DNS-UDP",
    123: "NTP-UDP",
    161: "SNMP-UDP",
    1900: "SSDP-UDP",
}


def parse_port_spec(spec: str | None) -> list[int]:
    """Parse comma-separated ports and ranges (e.g. '22,80,8000-8010'), capped at 200 ports."""
    if not spec or not spec.strip():
        return list(COMMON_PORTS.keys())
    ports: list[int] = []
    seen: set[int] = set()
    for part in spec.split(","):
        token = part.strip()
        if not token:
            continue
        if "-" in token:
            start_s, end_s = token.split("-", 1)
            start = int(start_s)
            end = int(end_s)
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {token}")
            for p in range(start, end + 1):
                if p not in seen:
                    seen.add(p)
                    ports.append(p)
                    if len(ports) >= 200:
                        return ports
        else:
            p = int(token)
            if p < 1 or p > 65535:
                raise ValueError(f"Invalid port number: {p}")
            if p not in seen:
                seen.add(p)
                ports.append(p)
                if len(ports) >= 200:
                    return ports
    if not ports:
        raise ValueError("No valid ports specified")
    return ports


def estimate_os(ttl: int | None, open_ports: list[dict[str, Any]], vendor: str) -> str:
    """Estimate target OS from ICMP TTL, service banners, and open ports."""
    banners = " ".join(str(p.get("banner", "")) for p in open_ports).lower()
    ports = {int(p.get("port", 0)) for p in open_ports}

    if "windows" in banners or "microsoft-iis" in banners or 3389 in ports or 135 in ports:
        return "Windows"
    if "ubuntu" in banners or "debian" in banners:
        return "Linux (Ubuntu/Debian)"
    if "mikrotik" in banners or "routeros" in vendor.lower() or "mikrotik" in vendor.lower():
        return "RouterOS / Network"
    if "apple" in vendor.lower():
        return "macOS / iOS"
    if ttl is not None:
        if ttl <= 64:
            return "Linux / macOS / Mobile"
        if ttl <= 128:
            return "Windows"
        return "Network Appliance / Router"
    return "Unknown"


class SubnetScanner:
    """Discovers active hosts in a subnet via ARP/ICMP + TCP port probing."""

    def __init__(
        self,
        db: Database,
        max_prefix: int = 20,
        on_rogue_device: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
        on_ip_conflict: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
        safety_manager: Any | None = None,
    ) -> None:
        self.db = db
        self.max_prefix = max_prefix
        self.on_rogue_device = on_rogue_device
        self.on_ip_conflict = on_ip_conflict
        self.safety_manager = safety_manager
        self._scanning = False

    @property
    def is_scanning(self) -> bool:
        return self._scanning

    async def scan_subnet(
        self,
        cidr: str,
        *,
        scan_ports: bool = True,
        port_spec: str | None = None,
        scan_udp: bool = False,
        on_progress: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    ) -> dict[str, Any]:
        """Sweep the requested subnet and persist discovered hosts in SQLite."""
        network = validate_subnet(cidr, max_prefix=self.max_prefix)
        if self.safety_manager is not None:
            overlap = self.safety_manager.overlaps_excluded_cidr(str(network))
            if overlap:
                raise PermissionError(
                    f"Scan blocked: {network} overlaps protected/medical exclusion VLAN {overlap}"
                )
            if self.safety_manager.is_hospital_safe:
                # Hospital Safe Mode disables intrusive port/banner probing automatically
                scan_ports = False
                scan_udp = False
        target_ports = parse_port_spec(port_spec) if scan_ports else []
        if self._scanning:
            raise RuntimeError("A subnet scan is already in progress")

        self._scanning = True
        started = time.perf_counter()
        try:
            hosts = [str(ip) for ip in network.hosts()] or [str(network.network_address)]
            if on_progress:
                await on_progress({"event": "scan_started", "cidr": str(network), "total_hosts": len(hosts)})

            # 1) Try fast ARP sweep + SSDP discovery in parallel with ICMP ping
            arp_map = await asyncio.to_thread(_try_scapy_arp_sweep, str(network))
            ssdp_map = await asyncio.to_thread(_discover_ssdp_devices)

            # 2) Concurrent ICMP ping (extracting RTT & TTL) + fallback ARP table merge
            ping_sem = asyncio.Semaphore(48)
            ping_results = await asyncio.gather(
                *[_ping_host(ip, ping_sem) for ip in hosts]
            )
            os_arp = await asyncio.to_thread(_read_os_arp_cache)

            online_hosts: dict[str, dict[str, Any]] = {}
            for ip, rtt, ttl in ping_results:
                mac = arp_map.get(ip) or os_arp.get(ip, "")
                if rtt is not None or ip in arp_map or ip in ssdp_map:
                    online_hosts[ip] = {
                        "ip": ip,
                        "mac": mac.upper().replace("-", ":") if mac else "",
                        "latency_ms": round(rtt, 2) if rtt is not None else None,
                        "ttl": ttl,
                    }

            # 3) Resolve hostnames (rDNS + NetBIOS + mDNS + SSDP) & open ports concurrently
            port_sem = asyncio.Semaphore(64)
            enriched: list[dict[str, Any]] = []

            async def enrich_host(entry: dict[str, Any]) -> dict[str, Any]:
                ip = entry["ip"]
                hostname = await asyncio.to_thread(_resolve_hostname, ip)
                if not hostname and ip in ssdp_map:
                    hostname = ssdp_map[ip]
                open_ports: list[dict[str, Any]] = []
                if scan_ports and target_ports:
                    open_ports = await _scan_tcp_ports(ip, target_ports, port_sem)
                if scan_udp:
                    udp_ports = await _scan_udp_ports(ip)
                    open_ports.extend(udp_ports)
                vendor = lookup_vendor(entry["mac"])
                os_guess = estimate_os(entry.get("ttl"), open_ports, vendor)
                record = {
                    "ip": ip,
                    "mac": entry["mac"],
                    "vendor": vendor,
                    "hostname": hostname,
                    "os_guess": os_guess,
                    "latency_ms": entry["latency_ms"],
                    "open_ports": open_ports,
                    "status": "online",
                }
                state = await self.db.upsert_device(**record)
                if (
                    state.get("mac_conflict")
                    and self.on_ip_conflict is not None
                ):
                    await self.on_ip_conflict(
                        {
                            "ip": ip,
                            "new_mac": entry["mac"],
                            "previous_mac": state.get("previous_mac", ""),
                        }
                    )
                if (
                    state.get("is_new")
                    and not state.get("trusted")
                    and ip != "127.0.0.1"
                    and self.on_rogue_device is not None
                ):
                    await self.on_rogue_device(record)
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


async def _ping_host(ip: str, sem: asyncio.Semaphore) -> tuple[str, float | None, int | None]:
    """Ping a single IP using OS ping without shell=True, extracting RTT and TTL."""
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
                ttl_m = re.search(r"ttl\s*=\s*(\d+)", text, re.IGNORECASE)
                ttl = int(ttl_m.group(1)) if ttl_m else None
                return ip, rtt, ttl
        except Exception:
            pass
        return ip, None, None


def _discover_ssdp_devices() -> dict[str, str]:
    """Send UPnP SSDP M-SEARCH multicast probe to learn Smart TV / Router / Printer info."""
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode("ascii")
    found: dict[str, str] = {}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.6)
            sock.sendto(msg, ("239.255.255.250", 1900))
            deadline = time.monotonic() + 0.65
            while time.monotonic() < deadline:
                try:
                    data, addr = sock.recvfrom(2048)
                    ip = addr[0]
                    if ip in found:
                        continue
                    text = data.decode("utf-8", errors="ignore")
                    srv = re.search(r"^SERVER:\s*(.+)$", text, re.IGNORECASE | re.MULTILINE)
                    if srv:
                        found[ip] = f"UPnP ({srv.group(1).strip()[:40]})"
                except socket.timeout:
                    break
    except Exception:
        return {}
    return found


def _resolve_hostname(ip: str) -> str:
    """Resolve hostname via Reverse DNS, NetBIOS Node Status (137), and mDNS PTR (5353)."""
    try:
        socket.setdefaulttimeout(0.4)
        name, _, _ = socket.gethostbyaddr(ip)
        if name:
            return name
    except Exception:
        pass

    nb_name = _query_netbios_name(ip)
    if nb_name:
        return nb_name

    mdns_name = _query_mdns_name(ip)
    if mdns_name:
        return mdns_name
    return ""


def _query_netbios_name(ip: str) -> str:
    """Send a lightweight NetBIOS NBSTAT query (UDP 137) to resolve Windows/Samba computer names."""
    query = (
        b"\x13\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
        b"\x00\x21\x00\x01"
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.25)
            sock.sendto(query, (ip, 137))
            data, _ = sock.recvfrom(1024)
            if len(data) < 57:
                return ""
            num_names = data[56]
            offset = 57
            for _ in range(min(num_names, 16)):
                if offset + 18 > len(data):
                    break
                raw_name = data[offset : offset + 15].decode("ascii", errors="ignore").strip()
                suffix = data[offset + 15]
                flags = struct.unpack(">H", data[offset + 16 : offset + 18])[0]
                is_group = bool(flags & 0x8000)
                if raw_name and not is_group and suffix in (0x00, 0x20):
                    return raw_name
                offset += 18
    except Exception:
        return ""
    return ""


def _query_mdns_name(ip: str) -> str:
    """Send a unicast mDNS PTR query (UDP 5353) for `.in-addr.arpa` friendly `.local` names."""
    try:
        octets = ipaddress.IPv4Address(ip).reverse_pointer.split(".")
        qname = b"".join(bytes([len(part)]) + part.encode("ascii") for part in octets) + b"\x00"
        packet = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x0c\x00\x01"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.25)
            sock.sendto(packet, (ip, 5353))
            data, _ = sock.recvfrom(1024)
            match = re.search(rb"([a-zA-Z0-9_-]{2,40})\x05local", data)
            if match:
                return f"{match.group(1).decode('ascii', errors='ignore')}.local"
    except Exception:
        return ""
    return ""


async def _grab_banner(
    ip: str, port: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> str:
    """Safely extract a short printable service banner without blocking."""
    try:
        if port in (80, 8000, 8080):
            writer.write(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(512), timeout=0.35)
            text = raw.decode("utf-8", errors="ignore")
            for line in text.splitlines():
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()[:80]
            first = text.splitlines()[0].strip() if text.splitlines() else ""
            return first[:80]
        if port in (21, 22, 25):
            raw = await asyncio.wait_for(reader.read(256), timeout=0.35)
            cleaned = "".join(ch for ch in raw.decode("utf-8", errors="ignore") if 32 <= ord(ch) <= 126)
            return cleaned.strip()[:80]
    except Exception:
        return ""
    return ""


async def _probe_tls_version(ip: str, port: int) -> str:
    """Probe TLS protocol version on HTTPS ports without rejecting self-signed certs."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = asyncio.open_connection(ip, port, ssl=ctx)
        _, writer = await asyncio.wait_for(conn, timeout=0.5)
        ssl_obj = writer.get_extra_info("ssl_object")
        ver = ssl_obj.version() if ssl_obj else "TLS"
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return str(ver or "TLS")
    except Exception:
        return ""


async def _scan_tcp_ports(
    ip: str, target_ports: list[int], sem: asyncio.Semaphore
) -> list[dict[str, Any]]:
    """Probe target TCP ports concurrently and grab lightweight service banners."""

    async def probe(port: int) -> dict[str, Any] | None:
        service = COMMON_PORTS.get(port, f"TCP-{port}")
        async with sem:
            try:
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=0.35)
                banner = await _grab_banner(ip, port, reader, writer)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                if not banner and port in (443, 8443):
                    banner = await _probe_tls_version(ip, port)
                entry: dict[str, Any] = {"port": port, "service": service}
                if banner:
                    entry["banner"] = banner
                return entry
            except Exception:
                return None

    results = await asyncio.gather(*[probe(p) for p in target_ports])
    return [r for r in results if r is not None]


async def _scan_udp_ports(ip: str) -> list[dict[str, Any]]:
    """Lightweight UDP service probe for NTP (123) and SNMP (161)."""
    found: list[dict[str, Any]] = []

    def _probe_ntp_sync() -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(0.35)
                s.sendto(b"\x1b" + 47 * b"\0", (ip, 123))
                data, _ = s.recvfrom(64)
                return len(data) >= 48
        except Exception:
            return False

    if await asyncio.to_thread(_probe_ntp_sync):
        found.append({"port": 123, "service": "NTP-UDP", "banner": "UDP Responder"})
    return found
