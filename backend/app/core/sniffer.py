"""Live Packet Sniffer backed by Scapy with bounded live buffer."""

from __future__ import annotations

import asyncio
import threading
import time
from collections import deque
from typing import Any, Awaitable, Callable

from app.core.ids_engine import IDSEngine, PacketEvent


class PacketSniffer:
    """Manages background Scapy sniffing and bridges packets into asyncio IDSEngine."""

    def __init__(
        self,
        *,
        ids_engine: IDSEngine,
        buffer_size: int = 300,
        on_packet: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    ) -> None:
        self.ids_engine = ids_engine
        self.recent_packets: deque[dict[str, Any]] = deque(maxlen=buffer_size)
        self.on_packet = on_packet

        self._running = False
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._interface: str | None = None
        self._last_error: str | None = None
        self._packet_count: int = 0

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
        """Record a synthetic packet in the live buffer for learning transparency."""
        summary = pkt.to_summary()
        self._packet_count += 1
        self.recent_packets.append(summary)

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
        self._packet_count += 1
        summary = pkt.to_summary()
        self.recent_packets.append(summary)

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
        from scapy.all import ARP, ICMP, IP, Raw, TCP, UDP  # type: ignore
    except Exception:
        return None

    now = time.time()
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
        )

    if IP not in scapy_pkt:
        return None

    ip_layer = scapy_pkt[IP]
    payload_text = ""
    if Raw in scapy_pkt:
        raw_bytes = bytes(scapy_pkt[Raw].load)[:256]
        payload_text = raw_bytes.decode("utf-8", errors="ignore")

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
        )

    if ICMP in scapy_pkt:
        return PacketEvent(
            timestamp=now,
            protocol="icmp",
            src_ip=str(ip_layer.src),
            dst_ip=str(ip_layer.dst),
            payload=payload_text,
            length=length,
        )

    return PacketEvent(
        timestamp=now,
        protocol="ip",
        src_ip=str(ip_layer.src),
        dst_ip=str(ip_layer.dst),
        payload=payload_text,
        length=length,
    )
