"""Shared FastAPI application state and WebSocket hub."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from fastapi import Request, WebSocket

from app.core.blocker import ActiveResponseBlocker
from app.core.ids_engine import IDSEngine
from app.core.scanner import SubnetScanner
from app.core.sniffer import PacketSniffer
from app.core.snmp_monitor import SnmpMonitor
from app.db.database import Database
from app.platform.base import PlatformCapabilities


class LiveHub:
    """Manages active WebSocket clients and broadcasts live SOC/NOC events."""

    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._clients.add(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(ws)

    async def broadcast(self, event_type: str, payload: Any) -> None:
        async with self._lock:
            targets = list(self._clients)
        if not targets:
            return
        dead: list[WebSocket] = []
        message = {"type": event_type, "data": payload}
        for ws in targets:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self._clients.discard(ws)


@dataclass
class AppServices:
    """Container attached to app.state holding core services."""

    db: Database
    capabilities: PlatformCapabilities
    blocker: ActiveResponseBlocker
    scanner: SubnetScanner
    ids_engine: IDSEngine
    sniffer: PacketSniffer
    snmp_monitor: SnmpMonitor
    hub: LiveHub = field(default_factory=LiveHub)


def get_services(request: Request) -> AppServices:
    """FastAPI dependency returning the initialized AppServices container."""
    return request.app.state.services
