"""Async UDP SNMP Trap Receiver (port 1162) for Switch/Router/UPS notifications."""

from __future__ import annotations

import asyncio
import re
from collections import deque
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable


PRINTABLE_ASCII_RE = re.compile(r"[ -~]{4,}")


def parse_snmp_trap_payload(raw: bytes, source_ip: str) -> dict[str, Any]:
    """Extract readable OIDs/strings from an SNMPv1/v2c Trap UDP datagram."""
    strings = PRINTABLE_ASCII_RE.findall(raw.decode("latin-1", errors="ignore"))
    summary = " | ".join(strings[:8]) if strings else f"Binary SNMP Trap ({len(raw)} bytes)"
    return {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "length": len(raw),
        "summary": summary[:300],
    }


class _TrapProtocol(asyncio.DatagramProtocol):
    def __init__(self, on_datagram: Callable[[bytes, str], None]) -> None:
        self.on_datagram = on_datagram

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.on_datagram(data, addr[0])


class SnmpTrapReceiver:
    """Listens on UDP 1162 for SNMP traps with bounded ring buffer."""

    def __init__(
        self,
        port: int = 1162,
        on_trap: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    ) -> None:
        self.port = port
        self.on_trap = on_trap
        self._transport: asyncio.DatagramTransport | None = None
        self._running = False
        self._last_error: str | None = None
        self.recent_traps: deque[dict[str, Any]] = deque(maxlen=200)

    def status(self) -> dict[str, Any]:
        return {
            "running": self._running,
            "port": self.port,
            "count": len(self.recent_traps),
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
                lambda: _TrapProtocol(self._handle_packet), local_addr=(host, self.port)
            )
            self._transport = transport
            self._running = True
        except Exception as exc:
            self._last_error = f"Unable to bind SNMP Trap UDP {self.port}: {exc}"
        return self.status()

    def stop(self) -> dict[str, Any]:
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        self._running = False
        return self.status()

    def _handle_packet(self, data: bytes, src_ip: str) -> None:
        trap = parse_snmp_trap_payload(data, src_ip)
        self.recent_traps.appendleft(trap)
        if self.on_trap:
            asyncio.create_task(self.on_trap(trap))
