"""Traceroute and Internet Speed Diagnostic Lab without shell=True."""

from __future__ import annotations

import asyncio
import ipaddress
import platform
import re
import time
from typing import Any

import httpx


SAFE_TARGET_RE = re.compile(r"^[a-zA-Z0-9.-]{1,128}$")
SPEED_TEST_URL = "https://speed.cloudflare.com/__down?bytes=2000000"


def validate_diagnostic_target(target: str) -> str:
    """Validate IP or hostname strictly to prevent command injection."""
    cleaned = target.strip()
    if not cleaned:
        raise ValueError("Target cannot be empty")
    try:
        return str(ipaddress.ip_address(cleaned))
    except ValueError:
        if not SAFE_TARGET_RE.match(cleaned) or cleaned.startswith("-"):
            raise ValueError("Invalid target IP or hostname")
        return cleaned


def parse_traceroute_output(output: str) -> list[dict[str, Any]]:
    """Parse Windows tracert / Linux traceroute output into structured hops."""
    hops: list[dict[str, Any]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        m = re.match(r"^(\d{1,2})\s+(.+)$", line)
        if not m:
            continue
        hop_num = int(m.group(1))
        rest = m.group(2)
        ip_m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", rest)
        rtts = [float(val) for val in re.findall(r"(?:<)?([\d.]+)\s*ms", rest, re.IGNORECASE)]
        avg_rtt = round(sum(rtts) / len(rtts), 2) if rtts else None
        hops.append(
            {
                "hop": hop_num,
                "ip": ip_m.group(1) if ip_m else "*",
                "rtt_ms": avg_rtt,
                "timed_out": ip_m is None,
            }
        )
    return hops


async def run_traceroute(target: str, max_hops: int = 15) -> dict[str, Any]:
    """Run traceroute safely without shell=True and return parsed hops."""
    safe_target = validate_diagnostic_target(target)
    clamped_hops = max(1, min(max_hops, 30))
    is_win = platform.system().lower() == "windows"
    cmd = (
        ["tracert", "-d", "-h", str(clamped_hops), "-w", "700", safe_target]
        if is_win
        else ["traceroute", "-n", "-m", str(clamped_hops), "-w", "1", safe_target]
    )
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=22.0)
        text = stdout.decode("utf-8", errors="replace")
        hops = parse_traceroute_output(text)
        return {"target": safe_target, "hops": hops, "raw_lines": len(text.splitlines())}
    except asyncio.TimeoutError:
        return {"target": safe_target, "hops": [], "error": "Traceroute timed out"}
    except FileNotFoundError:
        return {"target": safe_target, "hops": [], "error": "Traceroute binary not installed on host"}


async def run_speed_test() -> dict[str, Any]:
    """Measure real HTTPS latency and 2 MB download throughput against Cloudflare speed endpoint."""
    started_connect = time.perf_counter()
    total_bytes = 0
    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            async with client.stream("GET", SPEED_TEST_URL) as resp:
                ttfb_ms = round((time.perf_counter() - started_connect) * 1000, 1)
                if resp.status_code >= 400:
                    return {"success": False, "error": f"Speed test endpoint returned HTTP {resp.status_code}"}
                dl_start = time.perf_counter()
                async for chunk in resp.aiter_bytes():
                    total_bytes += len(chunk)
                dl_elapsed = max(0.05, time.perf_counter() - dl_start)
        mbps = round((total_bytes * 8.0) / dl_elapsed / 1_000_000, 2)
        return {
            "success": True,
            "latency_ms": ttfb_ms,
            "download_mbps": mbps,
            "bytes_downloaded": total_bytes,
            "duration_seconds": round(dl_elapsed, 2),
        }
    except Exception as exc:
        return {"success": False, "error": f"Unable to reach speed test server: {exc}"}
