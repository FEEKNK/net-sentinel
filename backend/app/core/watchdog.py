"""Internet connectivity & latency watchdog (ISP outage monitor)."""

from __future__ import annotations

import asyncio
import platform
import re
import time
from typing import Any

from app.db.database import Database
from app.platform.base import validate_ip_address


class InternetWatchdog:
    """Periodically checks external IP reachability (e.g., 1.1.1.1) and logs to SQLite."""

    def __init__(self, db: Database, target_ip: str = "1.1.1.1") -> None:
        self.db = db
        self.target_ip = validate_ip_address(target_ip)
        self.enabled: bool = False

    async def load_settings(self) -> None:
        self.enabled = bool(await self.db.get_setting("watchdog_enabled", False))
        saved_ip = await self.db.get_setting("watchdog_target_ip", "1.1.1.1")
        if isinstance(saved_ip, str) and saved_ip:
            try:
                self.target_ip = validate_ip_address(saved_ip)
            except ValueError:
                pass

    async def set_config(self, *, enabled: bool | None = None, target_ip: str | None = None) -> dict[str, Any]:
        if enabled is not None:
            self.enabled = enabled
            await self.db.set_setting("watchdog_enabled", enabled)
        if target_ip is not None:
            self.target_ip = validate_ip_address(target_ip)
            await self.db.set_setting("watchdog_target_ip", self.target_ip)
        return {"enabled": self.enabled, "target_ip": self.target_ip}

    async def check_once(self) -> dict[str, Any]:
        is_win = platform.system().lower() == "windows"
        cmd = (
            ["ping", "-n", "1", "-w", "900", self.target_ip]
            if is_win
            else ["ping", "-c", "1", "-W", "1", self.target_ip]
        )
        online = False
        rtt: float | None = None
        started = time.perf_counter()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=1.8)
            elapsed = (time.perf_counter() - started) * 1000
            if proc.returncode == 0:
                online = True
                text = stdout.decode("utf-8", errors="replace")
                m = re.search(r"time[=<]\s*([\d.]+)\s*ms", text, re.IGNORECASE)
                rtt = round(float(m.group(1)) if m else elapsed, 2)
        except Exception:
            online = False

        return await self.db.insert_watchdog_ping(
            target_ip=self.target_ip, online=online, latency_ms=rtt
        )
