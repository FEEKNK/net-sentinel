"""Local Process-to-Network socket inspector (GlassWire/TCPView style)."""

from __future__ import annotations

import socket
from typing import Any

import psutil


def list_process_connections(limit: int = 200) -> dict[str, Any]:
    """Inspect active inet sockets mapped to local OS processes."""
    safe_limit = max(1, min(limit, 500))
    proc_names: dict[int, str] = {}
    rows: list[dict[str, Any]] = []
    by_process: dict[str, int] = {}

    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        return {
            "error": "Insufficient privileges to inspect all OS socket PIDs",
            "connections": [],
            "process_summary": [],
        }

    for conn in connections:
        pid = conn.pid or 0
        proc_name = "System"
        if pid > 0:
            if pid not in proc_names:
                try:
                    proc_names[pid] = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    proc_names[pid] = f"PID-{pid}"
            proc_name = proc_names[pid]

        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-"
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"
        proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        status = conn.status or ("LISTEN" if not conn.raddr else "ACTIVE")

        by_process[proc_name] = by_process.get(proc_name, 0) + 1
        rows.append(
            {
                "pid": pid,
                "process": proc_name,
                "protocol": proto,
                "status": status,
                "local": laddr,
                "remote": raddr,
                "remote_ip": conn.raddr.ip if conn.raddr else "",
            }
        )

    rows.sort(
        key=lambda r: (
            0 if r["status"] == "ESTABLISHED" else (1 if r["remote_ip"] else 2),
            r["process"].lower(),
        )
    )
    summary = [
        {"process": name, "count": cnt}
        for name, cnt in sorted(by_process.items(), key=lambda x: x[1], reverse=True)[:12]
    ]
    return {
        "error": None,
        "total": len(rows),
        "connections": rows[:safe_limit],
        "process_summary": summary,
    }
