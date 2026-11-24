"""FastAPI application entrypoint, security middleware, lifespan, and WebSocket."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from contextlib import asynccontextmanager, suppress
from typing import AsyncIterator

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import alerts, devices, firewall, rules, snmp, system
from app.api.deps import AppServices, LiveHub
from app.config import Settings, settings
from app.core.blocker import ActiveResponseBlocker
from app.core.ids_engine import IDSEngine
from app.core.scanner import SubnetScanner
from app.core.sniffer import PacketSniffer
from app.core.snmp_monitor import SnmpMonitor
from app.db.database import Database
from app.platform import get_firewall_adapter, get_platform_capabilities


logger = logging.getLogger("netsentinel")


def create_app(custom_settings: Settings | None = None) -> FastAPI:
    """Create and configure the NetSentinel FastAPI application."""
    cfg = custom_settings or settings

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        db = Database(cfg.db_path)
        await db.initialize()

        capabilities = get_platform_capabilities()
        firewall_adapter = get_firewall_adapter()
        hub = LiveHub()

        protected = set(capabilities.local_ips)
        if capabilities.gateway_ip:
            protected.add(capabilities.gateway_ip)

        blocker = ActiveResponseBlocker(
            db=db,
            firewall=firewall_adapter,
            protected_ips=protected,
            whitelist_ips=set(cfg.whitelist_ips),
            dry_run=cfg.dry_run,
            auto_block_enabled=cfg.auto_block_enabled,
            auto_block_threshold=cfg.auto_block_threshold,
            block_ttl_seconds=cfg.block_ttl_seconds,
        )
        await blocker.load_persisted_policy()

        try:
            home_nets = [ipaddress.IPv4Network(capabilities.default_subnet, strict=False)]
        except ValueError:
            home_nets = [ipaddress.IPv4Network("192.168.0.0/16")]

        async def broadcast_alert(alert: dict) -> None:
            await hub.broadcast("alert", alert)

        async def broadcast_packet(pkt: dict) -> None:
            await hub.broadcast("packet", pkt)

        ids_engine = IDSEngine(
            db=db, blocker=blocker, home_nets=home_nets, on_alert=broadcast_alert
        )
        if cfg.snort_rules_path.exists():
            ids_engine.load_rules_text(cfg.snort_rules_path.read_text(encoding="utf-8"))

        sniffer = PacketSniffer(
            ids_engine=ids_engine,
            buffer_size=cfg.live_packet_buffer_size,
            on_packet=broadcast_packet,
        )
        scanner = SubnetScanner(db=db, max_prefix=cfg.max_scan_prefix)
        snmp_monitor = SnmpMonitor(db=db)

        app.state.services = AppServices(
            db=db,
            capabilities=capabilities,
            blocker=blocker,
            scanner=scanner,
            ids_engine=ids_engine,
            sniffer=sniffer,
            snmp_monitor=snmp_monitor,
            hub=hub,
        )

        # Background sampler & TTL block expiry task
        stop_bg = asyncio.Event()

        async def background_loop() -> None:
            tick = 0
            while not stop_bg.is_set():
                try:
                    metrics = await snmp_monitor.poll_once()
                    for m in metrics:
                        await hub.broadcast("snmp_metric", m)
                    if tick % 6 == 0:
                        await blocker.expire_stale_blocks()
                except Exception:
                    logger.exception("Background telemetry loop encountered an error")
                tick += 1
                try:
                    await asyncio.wait_for(
                        stop_bg.wait(), timeout=cfg.snmp_poll_interval_seconds
                    )
                except asyncio.TimeoutError:
                    continue

        bg_task = asyncio.create_task(background_loop())
        try:
            yield
        finally:
            stop_bg.set()
            with suppress(asyncio.CancelledError, asyncio.TimeoutError):
                await asyncio.wait_for(bg_task, timeout=3.0)
            sniffer.stop()

    app = FastAPI(
        title=cfg.app_name,
        version=cfg.app_version,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Content-Type"],
    )

    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; connect-src 'self' ws: wss:; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
        )
        return response

    @app.exception_handler(Exception)
    async def safe_global_exception_handler(request: Request, exc: Exception):
        logger.exception("Unhandled error while serving %s", request.url.path)
        return JSONResponse(
            status_code=503,
            content={"detail": "Service unavailable or database operation failed"},
        )

    app.include_router(system.router)
    app.include_router(devices.router)
    app.include_router(alerts.router)
    app.include_router(rules.router)
    app.include_router(snmp.router)
    app.include_router(firewall.router)

    @app.websocket("/ws/live")
    async def live_websocket(ws: WebSocket) -> None:
        services: AppServices = ws.app.state.services
        await services.hub.connect(ws)
        try:
            while True:
                # Keepalive receive loop; client messages ignored cleanly
                await ws.receive_text()
        except WebSocketDisconnect:
            await services.hub.disconnect(ws)
        except Exception:
            await services.hub.disconnect(ws)

    return app


app = create_app()
