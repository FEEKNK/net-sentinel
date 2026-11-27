"""Async UDP Syslog Receiver (RFC 3164) for Router/Switch/Firewall logs."""

from __future__ import annotations

import asyncio
import re
from typing import Any, Awaitable, Callable

from app.db.database import Database


SYSLOG_SEVERITIES = [
    "emergency",
    "alert",
    "critical",
    "error",
    "warning",
    "notice",
    "info",
    "debug",
]

PRI_RE = re.compile(r"^<(\d{1,3})>(.*)$", re.DOTALL)


def parse_syslog_datagram(raw: bytes) -> tuple[str, str, str]:
    """Parse RFC 3164 <PRI>message into (severity, facility, message)."""
    text = raw.decode("utf-8", errors="replace").strip()
    m = PRI_RE.match(text)
    if not m:
        return "info", "user", text[:1000]
    pri = int(m.group(1))
    sev_idx = pri & 0x07
    fac_idx = pri >> 3
    severity = SYSLOG_SEVERITIES[sev_idx] if 0 <= sev_idx < len(SYSLOG_SEVERITIES) else "info"
    return severity, f"fac-{fac_idx}", m.group(2).strip()[:1000]


class _SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, on_datagram: Callable[[bytes, str], None]) -> None:
        self.on_datagram = on_datagram

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.on_datagram(data, addr[0])


class SyslogServer:
    """Manages an async UDP Syslog listener bound safely on a configurable port."""

    def __init__(
        self,
        *,
        db: Database,
        port: int = 5140,
        on_event: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    ) -> None:
        self.db = db
        self.port = port
        self.on_event = on_event
        self._transport: asyncio.DatagramTransport | None = None
        self._running = False
        self._last_error: str | None = None
        self._received_count = 0

    def status(self) -> dict[str, Any]:
        return {
            "running": self._running,
            "port": self.port,
            "received_count": self._received_count,
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
                lambda: _SyslogProtocol(self._handle_packet),
                local_addr=(host, self.port),
            )
            self._transport = transport
            self._running = True
        except Exception as exc:
            self._last_error = f"Unable to bind UDP port {self.port}: {exc}"
            self._running = False
        return self.status()

    def stop(self) -> dict[str, Any]:
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        self._running = False
        return self.status()

    def _handle_packet(self, data: bytes, src_ip: str) -> None:
        self._received_count += 1
        severity, facility, message = parse_syslog_datagram(data)
        asyncio.create_task(
            self._persist_and_emit(
                source_ip=src_ip, severity=severity, facility=facility, message=message
            )
        )

    async def _persist_and_emit(
        self, *, source_ip: str, severity: str, facility: str, message: str
    ) -> None:
        saved = await self.db.insert_syslog_event(
            source_ip=source_ip, severity=severity, facility=facility, message=message
        )
        if self.on_event:
            await self.on_event(saved)
