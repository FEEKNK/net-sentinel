"""Async UDP NetFlow v5 Collector (port 2055) for Router/Switch Flow Telemetry."""

from __future__ import annotations

import asyncio
import socket
import struct
from collections import deque
from typing import Any


NETFLOW_V5_HEADER_FMT = "!HHIIIIBBH"
NETFLOW_V5_HEADER_SIZE = struct.calcsize(NETFLOW_V5_HEADER_FMT)
NETFLOW_V5_RECORD_FMT = "!IIIHHIIIIHHBBBBHHBBH"
NETFLOW_V5_RECORD_SIZE = struct.calcsize(NETFLOW_V5_RECORD_FMT)

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


def parse_netflow_v5_packet(data: bytes, exporter_ip: str = "") -> list[dict[str, Any]]:
    """Decode a NetFlow v5 UDP packet into structured flow dicts."""
    if len(data) < NETFLOW_V5_HEADER_SIZE:
        return []
    version, count, *_ = struct.unpack(NETFLOW_V5_HEADER_FMT, data[:NETFLOW_V5_HEADER_SIZE])
    if version != 5 or count == 0:
        return []

    flows: list[dict[str, Any]] = []
    offset = NETFLOW_V5_HEADER_SIZE
    for _ in range(min(count, 64)):
        if offset + NETFLOW_V5_RECORD_SIZE > len(data):
            break
        rec = struct.unpack(
            NETFLOW_V5_RECORD_FMT, data[offset : offset + NETFLOW_V5_RECORD_SIZE]
        )
        offset += NETFLOW_V5_RECORD_SIZE
        src_raw, dst_raw = rec[0], rec[1]
        d_pkts, d_octets = rec[5], rec[6]
        src_port, dst_port = rec[9], rec[10]
        prot_num = rec[13]
        flows.append(
            {
                "exporter": exporter_ip,
                "src_ip": socket.inet_ntoa(struct.pack("!I", src_raw)),
                "dst_ip": socket.inet_ntoa(struct.pack("!I", dst_raw)),
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": PROTO_NAMES.get(prot_num, f"PROTO-{prot_num}"),
                "packets": d_pkts,
                "bytes": d_octets,
            }
        )
    return flows


class _NetFlowProtocol(asyncio.DatagramProtocol):
    def __init__(self, on_datagram: Any) -> None:
        self.on_datagram = on_datagram

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.on_datagram(data, addr[0])


class NetFlowCollector:
    """Async UDP NetFlow v5 listener keeping bounded recent flows & top conversations."""

    def __init__(self, port: int = 2055) -> None:
        self.port = port
        self._transport: asyncio.DatagramTransport | None = None
        self._running = False
        self._last_error: str | None = None
        self.recent_flows: deque[dict[str, Any]] = deque(maxlen=300)
        self._conversations: dict[tuple[str, str, str], dict[str, Any]] = {}

    def status(self) -> dict[str, Any]:
        return {
            "running": self._running,
            "port": self.port,
            "flow_count": len(self.recent_flows),
            "last_error": self._last_error,
        }

    async def start(self, host: str = "0.0.0.0", port: int | None = None) -> dict[str, Any]:
        if self._running:
            return self.status()
        if port is not None:
            self.port = port
        self._last_error = None
        loop = asyncio.get_running_loop()
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _NetFlowProtocol(self._handle_packet), local_addr=(host, self.port)
            )
            self._transport = transport
            self._running = True
        except Exception as exc:
            self._last_error = f"Unable to bind NetFlow UDP {self.port}: {exc}"
        return self.status()

    def stop(self) -> dict[str, Any]:
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        self._running = False
        return self.status()

    def _handle_packet(self, data: bytes, src_ip: str) -> None:
        for flow in parse_netflow_v5_packet(data, exporter_ip=src_ip):
            self.recent_flows.appendleft(flow)
            key = (flow["src_ip"], flow["dst_ip"], flow["protocol"])
            if len(self._conversations) >= 512 and key not in self._conversations:
                del self._conversations[next(iter(self._conversations))]
            conv = self._conversations.setdefault(
                key,
                {
                    "src_ip": flow["src_ip"],
                    "dst_ip": flow["dst_ip"],
                    "protocol": flow["protocol"],
                    "bytes": 0,
                    "packets": 0,
                },
            )
            conv["bytes"] += flow["bytes"]
            conv["packets"] += flow["packets"]

    def get_summary(self) -> dict[str, Any]:
        top_conv = sorted(
            self._conversations.values(), key=lambda c: c["bytes"], reverse=True
        )[:15]
        return {
            "status": self.status(),
            "top_conversations": top_conv,
            "recent_flows": list(self.recent_flows)[:50],
        }
