"""FastAPI application entrypoint, security middleware, lifespan, and WebSocket."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from contextlib import asynccontextmanager, suppress
from typing import AsyncIterator

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api import alerts, auth, devices, enterprise, firewall, network, reports, rules, snmp, soc, system, tools, webhooks
from app.api.deps import AppServices, LiveHub, ScanScheduleState
from app.config import BASE_DIR, Settings, settings
from app.core.auth import LocalAuthManager
from app.core.blocker import ActiveResponseBlocker
from app.core.ids_engine import IDSEngine
from app.core.ioc_matcher import IOCMatcher
from app.core.netflow_collector import NetFlowCollector
from app.core.notifier import WebhookNotifier
from app.core.playbooks import PlaybookEngine
from app.core.safety import SafetyPolicyManager
from app.core.scanner import SubnetScanner
from app.core.sniffer import PacketSniffer
from app.core.snmp_monitor import SnmpMonitor
from app.core.snmp_traps import SnmpTrapReceiver
from app.core.syslog_server import SyslogServer
from app.core.threat_intel import ThreatIntelClient
from app.core.watchdog import InternetWatchdog
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
        notifier = WebhookNotifier(db=db)
        await notifier.load_settings()
        watchdog = InternetWatchdog(db=db)
        await watchdog.load_settings()
        threat_intel = ThreatIntelClient(db=db)
        await threat_intel.load_settings()
        auth_manager = LocalAuthManager(db=db)
        await auth_manager.load_settings()
        safety_manager = SafetyPolicyManager(db=db)
        await safety_manager.load_settings()
        ioc_matcher = IOCMatcher(db=db)
        await ioc_matcher.reload()

        async def handle_syslog_event(evt: dict) -> None:
            await hub.broadcast("syslog_event", evt)
            if evt.get("severity") in ("emergency", "alert", "critical", "error"):
                saved_alert = await db.insert_alert(
                    source_ip=str(evt["source_ip"]),
                    protocol="SYSLOG",
                    title=f"Syslog {str(evt['severity']).upper()} Event",
                    description=str(evt["message"])[:200],
                    severity="high" if evt["severity"] in ("critical", "alert", "emergency") else "medium",
                    detector_type="syslog",
                    action_taken="logged",
                )
                await handle_alert(saved_alert)

        syslog_server = SyslogServer(db=db, port=5140, on_event=handle_syslog_event)

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
            safety_manager=safety_manager,
        )
        await blocker.load_persisted_policy()

        try:
            home_nets = [ipaddress.IPv4Network(capabilities.default_subnet, strict=False)]
        except ValueError:
            home_nets = [ipaddress.IPv4Network("192.168.0.0/16")]

        async def handle_alert(alert: dict) -> None:
            await hub.broadcast("alert", alert)
            asyncio.create_task(notifier.notify_alert(alert))
            asyncio.create_task(playbook_engine.run_for_alert(alert))

        async def broadcast_packet(pkt: dict) -> None:
            await hub.broadcast("packet", pkt)

        trusted_dhcp = {capabilities.gateway_ip} if capabilities.gateway_ip else set()
        ids_engine = IDSEngine(
            db=db,
            blocker=blocker,
            home_nets=home_nets,
            trusted_dhcp_servers=trusted_dhcp,
            ioc_matcher=ioc_matcher,
            on_alert=handle_alert,
        )
        saved_tuning = await db.get_setting("ids_tuning")
        if isinstance(saved_tuning, dict):
            ids_engine.update_tuning(saved_tuning)
        if cfg.snort_rules_path.exists():
            ids_engine.load_rules_text(cfg.snort_rules_path.read_text(encoding="utf-8"))

        playbook_engine = PlaybookEngine(db=db, blocker=blocker, notifier=notifier)

        async def handle_trap(trap: dict) -> None:
            await hub.broadcast("snmp_trap", trap)
            saved_trap_alert = await db.insert_alert(
                source_ip=str(trap["source_ip"]),
                protocol="SNMP-TRAP",
                title="SNMP Trap Notification Received",
                description=str(trap["summary"])[:200],
                severity="medium",
                detector_type="snmp_trap",
                action_taken="logged",
            )
            await handle_alert(saved_trap_alert)

        trap_receiver = SnmpTrapReceiver(port=1162, on_trap=handle_trap)
        netflow_collector = NetFlowCollector(port=2055)

        sniffer = PacketSniffer(
            ids_engine=ids_engine,
            buffer_size=cfg.live_packet_buffer_size,
            on_packet=broadcast_packet,
            safety_manager=safety_manager,
        )

        async def handle_rogue_device(device: dict) -> None:
            mac = device.get("mac") or "Unknown MAC"
            vendor = device.get("vendor") or "Unknown"
            saved = await db.insert_alert(
                source_ip=str(device["ip"]),
                dest_ip=capabilities.default_subnet,
                protocol="LAN",
                title="New Unknown Device Detected on LAN",
                description=(
                    f"พบอุปกรณ์ใหม่ {device['ip']} (MAC: {mac}, ยี่ห้อ: {vendor}) "
                    "เข้ามาในวงเครือข่ายและยังไม่ได้ยืนยัน Trusted"
                ),
                severity="medium",
                detector_type="rogue_device",
                action_taken="logged",
            )
            await handle_alert(saved)

        async def handle_ip_conflict(conflict: dict) -> None:
            saved = await db.insert_alert(
                source_ip=str(conflict["ip"]),
                protocol="ARP",
                title="IP-MAC Address Conflict Detected",
                description=(
                    f"IP {conflict['ip']} changed MAC from {conflict['previous_mac']} "
                    f"to {conflict['new_mac']} during network scan."
                ),
                severity="critical",
                detector_type="ip_mac_conflict",
                action_taken="logged",
            )
            await handle_alert(saved)

        scanner = SubnetScanner(
            db=db,
            max_prefix=cfg.max_scan_prefix,
            on_rogue_device=handle_rogue_device,
            on_ip_conflict=handle_ip_conflict,
            safety_manager=safety_manager,
        )
        snmp_monitor = SnmpMonitor(db=db)

        scan_schedule = ScanScheduleState(
            enabled=bool(await db.get_setting("auto_scan_enabled", False)),
            interval_seconds=int(await db.get_setting("auto_scan_interval_seconds", 120) or 120),
            cidr=str(
                await db.get_setting("auto_scan_cidr", capabilities.default_subnet)
                or capabilities.default_subnet
            ),
            scan_ports=bool(await db.get_setting("auto_scan_ports", False)),
        )

        app.state.services = AppServices(
            db=db,
            capabilities=capabilities,
            blocker=blocker,
            scanner=scanner,
            ids_engine=ids_engine,
            sniffer=sniffer,
            snmp_monitor=snmp_monitor,
            notifier=notifier,
            scan_schedule=scan_schedule,
            syslog_server=syslog_server,
            watchdog=watchdog,
            threat_intel=threat_intel,
            auth_manager=auth_manager,
            safety_manager=safety_manager,
            ioc_matcher=ioc_matcher,
            trap_receiver=trap_receiver,
            netflow_collector=netflow_collector,
            playbook_engine=playbook_engine,
            hub=hub,
        )

        # Background telemetry, TTL expiry, and scheduled auto-scan loop
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
                        if watchdog.enabled:
                            wd = await watchdog.check_once()
                            await hub.broadcast("watchdog_ping", wd)

                    now_m = time.monotonic()
                    if (
                        scan_schedule.enabled
                        and not scanner.is_scanning
                        and (now_m - scan_schedule.last_run_at) >= scan_schedule.interval_seconds
                    ):
                        scan_schedule.last_run_at = now_m

                        async def on_prog(evt: dict) -> None:
                            await hub.broadcast("scan_progress", evt)

                        await scanner.scan_subnet(
                            scan_schedule.cidr,
                            scan_ports=scan_schedule.scan_ports,
                            on_progress=on_prog,
                        )
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
            syslog_server.stop()
            trap_receiver.stop()
            netflow_collector.stop()

    app = FastAPI(
        title=cfg.app_name,
        version=cfg.app_version,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "X-NetSentinel-Token"],
    )

    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next):
        path = request.url.path
        if (
            path.startswith("/api/")
            and not path.startswith("/api/auth/")
            and path != "/api/enterprise/sensors/ingest"
            and hasattr(request.app.state, "services")
        ):
            auth_mgr: LocalAuthManager = request.app.state.services.auth_manager
            token = request.headers.get("X-NetSentinel-Token")
            if not auth_mgr.is_token_valid(token):
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Dashboard locked: valid X-NetSentinel-Token required"},
                )
            if request.method in ("POST", "PUT", "PATCH", "DELETE"):
                if not auth_mgr.has_min_role(token, "analyst"):
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "Read-only Viewer role cannot perform modifications"},
                    )
                if path.startswith("/api/firewall/") and not auth_mgr.has_min_role(token, "admin"):
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "Admin role required to modify firewall policies"},
                    )

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
    app.include_router(auth.router)
    app.include_router(devices.router)
    app.include_router(alerts.router)
    app.include_router(rules.router)
    app.include_router(snmp.router)
    app.include_router(firewall.router)
    app.include_router(webhooks.router)
    app.include_router(reports.router)
    app.include_router(tools.router)
    app.include_router(enterprise.router)
    app.include_router(network.router)
    app.include_router(soc.router)

    @app.websocket("/ws/live")
    async def live_websocket(ws: WebSocket) -> None:
        services: AppServices = ws.app.state.services
        await services.hub.connect(ws)
        try:
            while True:
                await ws.receive_text()
        except WebSocketDisconnect:
            await services.hub.disconnect(ws)
        except Exception:
            await services.hub.disconnect(ws)

    # Single-port Production SPA serving when frontend/dist is built
    dist_dir = BASE_DIR.parent / "frontend" / "dist"
    index_file = dist_dir / "index.html"
    assets_dir = dist_dir / "assets"
    if index_file.exists():
        if assets_dir.exists():
            app.mount("/assets", StaticFiles(directory=assets_dir), name="spa-assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        async def serve_spa(full_path: str):
            if full_path.startswith("api/") or full_path.startswith("ws/"):
                raise HTTPException(status_code=404, detail="Not found")
            return FileResponse(index_file)

    return app


app = create_app()
