"""Live Packet Sniffer backed by Scapy with PCAP export, Top Talkers, DNS, and Outbound tracking."""

from __future__ import annotations

import asyncio
import io
import ipaddress
import struct
import threading
import time
from collections import defaultdict, deque
from typing import Any, Awaitable, Callable

from app.core.ids_engine import IDSEngine, PacketEvent
from app.core.snort_parser import SnortRule, match_rule


def _is_public_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_unspecified
        )
    except ValueError:
        return False


def _synthetic_to_ethernet_bytes(pkt: PacketEvent) -> bytes:
    """Build valid Ethernet+IPv4+(TCP/UDP/ICMP) raw bytes via Scapy for PCAP export."""
    try:
        from scapy.all import Ether, ICMP, IP, Raw, TCP, UDP  # type: ignore

        proto = pkt.protocol.lower()
        payload = pkt.payload.encode("utf-8", errors="ignore")
        if proto == "tcp":
            l4 = TCP(sport=pkt.src_port or 12345, dport=pkt.dst_port or 80, flags=pkt.tcp_flags or "S")
        elif proto == "udp":
            l4 = UDP(sport=pkt.src_port or 12345, dport=pkt.dst_port or 53)
        else:
            l4 = ICMP()
        frame = Ether() / IP(src=pkt.src_ip or "127.0.0.1", dst=pkt.dst_ip or "127.0.0.1") / l4
        if payload:
            frame = frame / Raw(load=payload)
        return bytes(frame)
    except Exception:
        return b""


class PacketSniffer:
    """Manages background Scapy sniffing, telemetry stats, DNS logs, and PCAP export."""

    def __init__(
        self,
        *,
        ids_engine: IDSEngine,
        buffer_size: int = 300,
        on_packet: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
        safety_manager: Any | None = None,
    ) -> None:
        self.ids_engine = ids_engine
        self.safety_manager = safety_manager
        self.recent_packets: deque[dict[str, Any]] = deque(maxlen=buffer_size)
        self.recent_raw_frames: deque[tuple[float, bytes]] = deque(maxlen=buffer_size)
        self.on_packet = on_packet

        self._running = False
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._interface: str | None = None
        self._last_error: str | None = None
        self._packet_count: int = 0

        # Telemetry metrics (bounded collections)
        self.protocol_counts: dict[str, int] = defaultdict(int)
        self._talkers: dict[str, dict[str, Any]] = {}
        self._dns_queries: deque[dict[str, Any]] = deque(maxlen=150)
        self._outbound_flows: dict[tuple[str, int | None, str], dict[str, Any]] = {}

    def status(self) -> dict[str, Any]:
        return {
            "running": self._running,
            "interface": self._interface or "auto",
            "packet_count": self._packet_count,
            "buffered_count": len(self.recent_packets),
            "last_error": self._last_error,
        }

    def start(self, loop: asyncio.AbstractEventLoop, interface: str | None = None) -> dict[str, Any]:
        """Start background packet capture thread if not already running."""
        if self._running:
            return self.status()

        self._loop = loop
        self._interface = interface
        self._stop_event.clear()
        self._last_error = None
        self._running = True

        self._thread = threading.Thread(
            target=self._capture_loop, name="NetSentinelSniffer", daemon=True
        )
        self._thread.start()
        return self.status()

    def stop(self) -> dict[str, Any]:
        """Signal sniffer thread to stop gracefully."""
        self._stop_event.set()
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.5)
        self._thread = None
        return self.status()

    def record_synthetic_packet(self, pkt: PacketEvent) -> None:
        """Record a synthetic packet in buffer, telemetry, and PCAP ring."""
        if not pkt.raw_bytes:
            pkt.raw_bytes = _synthetic_to_ethernet_bytes(pkt)
        self._record_packet_metrics(pkt)

    def get_telemetry(self) -> dict[str, Any]:
        """Return Top Talkers, Protocol Distribution, DNS queries, and Outbound Connections."""
        top_talkers = sorted(
            self._talkers.values(), key=lambda t: t["bytes_total"], reverse=True
        )[:12]
        outbound = sorted(
            self._outbound_flows.values(), key=lambda f: f["bytes_total"], reverse=True
        )[:25]
        return {
            "total_packets": self._packet_count,
            "protocol_counts": dict(self.protocol_counts),
            "top_talkers": top_talkers,
            "dns_queries": list(reversed(self._dns_queries))[:50],
            "outbound_connections": outbound,
        }

    def export_pcap_bytes(self) -> bytes:
        """Export buffered Ethernet frames as a standard libpcap (.pcap) file for Wireshark."""
        frames = list(self.recent_raw_frames)
        # Standard libpcap Global Header (little-endian, LINKTYPE_ETHERNET=1, snaplen=65535)
        global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        chunks = [global_header]
        for ts, raw in frames:
            if not raw:
                continue
            clipped = raw[:65535]
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            pkt_hdr = struct.pack("<IIII", sec, usec, len(clipped), len(clipped))
            chunks.append(pkt_hdr)
            chunks.append(clipped)
        return b"".join(chunks)

    def analyze_pcap_bytes(
        self, data: bytes, *, rules: list[SnortRule] | None = None, home_nets: list[ipaddress.IPv4Network] | None = None
    ) -> dict[str, Any]:
        """Parse an uploaded .pcap/.pcapng file (max 2000 packets) and extract telemetry + rule matches."""
        if len(data) < 24:
            raise ValueError("Uploaded file is too small to be a valid PCAP")
        magic = data[:4]
        if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"):
            raise ValueError("Unsupported file format: expected .pcap or .pcapng")

        from scapy.utils import rdpcap  # type: ignore

        packets = rdpcap(io.BytesIO(data), count=2000)
        proto_counts: dict[str, int] = defaultdict(int)
        talkers: dict[str, dict[str, Any]] = {}
        dns_list: list[dict[str, Any]] = []
        outbound_map: dict[tuple[str, int | None, str], dict[str, Any]] = {}
        summaries: list[dict[str, Any]] = []
        matched_rules: list[dict[str, Any]] = []
        nets = home_nets or [ipaddress.IPv4Network("192.168.0.0/16")]

        for scapy_pkt in packets:
            pkt = _scapy_to_packet_event(scapy_pkt)
            if pkt is None:
                continue
            proto = pkt.protocol.upper()
            proto_counts[proto] += 1
            if pkt.src_ip:
                t = talkers.setdefault(pkt.src_ip, {"ip": pkt.src_ip, "packets": 0, "bytes_total": 0})
                t["packets"] += 1
                t["bytes_total"] += pkt.length
            if pkt.dns_query:
                dns_list.append({"src_ip": pkt.src_ip, "domain": pkt.dns_query.rstrip(".")})
            if pkt.dst_ip and _is_public_ip(pkt.dst_ip):
                k = (pkt.dst_ip, pkt.dst_port, proto)
                f = outbound_map.setdefault(
                    k, {"dst_ip": pkt.dst_ip, "dst_port": pkt.dst_port, "protocol": proto, "packets": 0, "bytes_total": 0}
                )
                f["packets"] += 1
                f["bytes_total"] += pkt.length
            if len(summaries) < 120:
                summaries.append(pkt.to_summary())
            for rule in rules or []:
                if match_rule(
                    rule,
                    protocol=pkt.protocol,
                    src_ip=pkt.src_ip,
                    src_port=pkt.src_port,
                    dst_ip=pkt.dst_ip,
                    dst_port=pkt.dst_port,
                    payload=pkt.payload,
                    home_nets=nets,
                ):
                    if len(matched_rules) < 100:
                        matched_rules.append(
                            {
                                "sid": rule.sid,
                                "msg": rule.msg,
                                "severity": rule.severity,
                                "src_ip": pkt.src_ip,
                                "dst_ip": pkt.dst_ip,
                                "dst_port": pkt.dst_port,
                            }
                        )

        return {
            "packet_count": len(packets),
            "protocol_counts": dict(proto_counts),
            "top_talkers": sorted(talkers.values(), key=lambda x: x["bytes_total"], reverse=True)[:10],
            "dns_queries": dns_list[:50],
            "outbound_connections": sorted(outbound_map.values(), key=lambda x: x["bytes_total"], reverse=True)[:25],
            "matched_rules": matched_rules,
            "packets": summaries,
        }

    def _record_packet_metrics(self, pkt: PacketEvent) -> dict[str, Any]:
        ts = pkt.timestamp or time.time()
        pkt.timestamp = ts
        self._packet_count += 1
        if self.safety_manager is not None and self.safety_manager.privacy_mode:
            # Redact sensitive payload & DNS strings before buffering under PDPA/PHI mode
            pkt.payload = self.safety_manager.sanitize_payload(pkt.payload)
            pkt.raw_bytes = b""
            if pkt.dns_query:
                pkt.dns_query = "[REDACTED]"
        summary = pkt.to_summary()
        if self.safety_manager is not None and self.safety_manager.privacy_mode:
            summary["hex_dump"] = ""
        self.recent_packets.append(summary)
        if pkt.raw_bytes:
            self.recent_raw_frames.append((ts, pkt.raw_bytes[:2048]))

        proto = pkt.protocol.upper()
        self.protocol_counts[proto] += 1

        if pkt.src_ip:
            if len(self._talkers) >= 1024 and pkt.src_ip not in self._talkers:
                oldest = next(iter(self._talkers))
                del self._talkers[oldest]
            entry = self._talkers.get(pkt.src_ip)
            if entry is None:
                entry = {"ip": pkt.src_ip, "packets": 0, "bytes_total": 0, "last_seen": ts}
                self._talkers[pkt.src_ip] = entry
            entry["packets"] += 1
            entry["bytes_total"] += max(0, pkt.length)
            entry["last_seen"] = ts

        if pkt.dns_query:
            self._dns_queries.append(
                {
                    "timestamp": ts,
                    "src_ip": pkt.src_ip,
                    "domain": pkt.dns_query.rstrip("."),
                }
            )

        if pkt.dst_ip and _is_public_ip(pkt.dst_ip):
            key = (pkt.dst_ip, pkt.dst_port, proto)
            if len(self._outbound_flows) >= 512 and key not in self._outbound_flows:
                oldest = next(iter(self._outbound_flows))
                del self._outbound_flows[oldest]
            flow = self._outbound_flows.get(key)
            if flow is None:
                flow = {
                    "dst_ip": pkt.dst_ip,
                    "dst_port": pkt.dst_port,
                    "protocol": proto,
                    "packets": 0,
                    "bytes_total": 0,
                    "sources": [],
                    "last_seen": ts,
                }
                self._outbound_flows[key] = flow
            flow["packets"] += 1
            flow["bytes_total"] += max(0, pkt.length)
            flow["last_seen"] = ts
            if pkt.src_ip and pkt.src_ip not in flow["sources"] and len(flow["sources"]) < 8:
                flow["sources"].append(pkt.src_ip)

        return summary

    def _capture_loop(self) -> None:
        try:
            from scapy.all import sniff  # type: ignore

            kwargs: dict[str, Any] = {
                "prn": self._handle_scapy_packet,
                "store": False,
                "stop_filter": lambda _: self._stop_event.is_set(),
                "timeout": 2,
            }
            if self._interface:
                kwargs["iface"] = self._interface

            while not self._stop_event.is_set():
                sniff(**kwargs)
        except PermissionError:
            self._last_error = "Insufficient privileges for raw packet capture (run as Admin/sudo)"
            self._running = False
        except Exception as exc:
            self._last_error = f"Packet capture unavailable: {exc}"
            self._running = False

    def _handle_scapy_packet(self, scapy_pkt: Any) -> None:
        pkt = _scapy_to_packet_event(scapy_pkt)
        if pkt is None:
            return
        summary = self._record_packet_metrics(pkt)

        if self._loop and not self._loop.is_closed():
            self._loop.call_soon_threadsafe(
                asyncio.create_task, self._dispatch_async(pkt, summary)
            )

    async def _dispatch_async(self, pkt: PacketEvent, summary: dict[str, Any]) -> None:
        await self.ids_engine.process_packet(pkt)
        if self.on_packet:
            await self.on_packet(summary)


def _scapy_to_packet_event(scapy_pkt: Any) -> PacketEvent | None:
    try:
        from scapy.all import ARP, DNS, DNSQR, ICMP, IP, Raw, TCP, UDP  # type: ignore
    except Exception:
        return None

    now = time.time()
    raw_bytes = bytes(scapy_pkt)[:2048]
    length = len(scapy_pkt)

    if ARP in scapy_pkt:
        arp = scapy_pkt[ARP]
        return PacketEvent(
            timestamp=now,
            protocol="arp",
            src_ip=str(arp.psrc),
            dst_ip=str(arp.pdst),
            arp_op=int(arp.op),
            arp_psrc=str(arp.psrc),
            arp_hwsrc=str(arp.hwsrc),
            length=length,
            raw_bytes=raw_bytes,
        )

    if IP not in scapy_pkt:
        return None

    ip_layer = scapy_pkt[IP]
    ttl = int(ip_layer.ttl) if hasattr(ip_layer, "ttl") else None
    payload_text = ""
    if Raw in scapy_pkt:
        raw_payload = bytes(scapy_pkt[Raw].load)[:256]
        payload_text = raw_payload.decode("utf-8", errors="ignore")

    dns_query = ""
    if DNS in scapy_pkt and DNSQR in scapy_pkt:
        try:
            qname = scapy_pkt[DNSQR].qname
            if isinstance(qname, bytes):
                dns_query = qname.decode("utf-8", errors="ignore")
            else:
                dns_query = str(qname)
        except Exception:
            dns_query = ""

    if TCP in scapy_pkt:
        tcp = scapy_pkt[TCP]
        return PacketEvent(
            timestamp=now,
            protocol="tcp",
            src_ip=str(ip_layer.src),
            dst_ip=str(ip_layer.dst),
            src_port=int(tcp.sport),
            dst_port=int(tcp.dport),
            tcp_flags=str(tcp.flags),
            payload=payload_text,
            length=length,
            ttl=ttl,
            dns_query=dns_query,
            raw_bytes=raw_bytes,
        )

    if UDP in scapy_pkt:
        udp = scapy_pkt[UDP]
        return PacketEvent(
            timestamp=now,
            protocol="udp",
            src_ip=str(ip_layer.src),
            dst_ip=str(ip_layer.dst),
            src_port=int(udp.sport),
            dst_port=int(udp.dport),
            payload=payload_text,
            length=length,
            ttl=ttl,
            dns_query=dns_query,
            raw_bytes=raw_bytes,
        )

    if ICMP in scapy_pkt:
        return PacketEvent(
            timestamp=now,
            protocol="icmp",
            src_ip=str(ip_layer.src),
            dst_ip=str(ip_layer.dst),
            payload=payload_text,
            length=length,
            ttl=ttl,
            raw_bytes=raw_bytes,
        )

    return PacketEvent(
        timestamp=now,
        protocol="ip",
        src_ip=str(ip_layer.src),
        dst_ip=str(ip_layer.dst),
        payload=payload_text,
        length=length,
        ttl=ttl,
        raw_bytes=raw_bytes,
    )
