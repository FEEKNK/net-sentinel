"""Cross-platform Wi-Fi Signal & Neighbor Channel Analyzer."""

from __future__ import annotations

import asyncio
import platform
import re
from typing import Any


def parse_windows_wlan_interfaces(output: str) -> dict[str, Any]:
    """Parse `netsh wlan show interfaces` output cleanly."""
    info: dict[str, Any] = {}
    patterns = {
        "name": r"^\s*Name\s*:\s*(.+)$",
        "ssid": r"^\s*SSID\s*:\s*(.+)$",
        "bssid": r"^\s*BSSID\s*:\s*(.+)$",
        "radio_type": r"^\s*Radio type\s*:\s*(.+)$",
        "channel": r"^\s*Channel\s*:\s*(\d+)$",
        "signal_pct": r"^\s*Signal\s*:\s*(\d+)%",
        "rx_mbps": r"^\s*Receive rate \(Mbps\)\s*:\s*([\d.]+)",
        "tx_mbps": r"^\s*Transmit rate \(Mbps\)\s*:\s*([\d.]+)",
        "state": r"^\s*State\s*:\s*(.+)$",
    }
    for key, pat in patterns.items():
        m = re.search(pat, output, re.IGNORECASE | re.MULTILINE)
        if m:
            val = m.group(1).strip()
            if key in ("channel", "signal_pct"):
                info[key] = int(val)
            elif key in ("rx_mbps", "tx_mbps"):
                info[key] = float(val)
            else:
                info[key] = val
    return info


def parse_windows_wlan_networks(output: str) -> list[dict[str, Any]]:
    """Parse `netsh wlan show networks mode=bssid` output into nearby AP records."""
    networks: list[dict[str, Any]] = []
    current_ssid = ""
    current_auth = ""
    current_bssid: dict[str, Any] | None = None

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        ssid_m = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", line, re.IGNORECASE)
        if ssid_m:
            if current_bssid:
                networks.append(current_bssid)
                current_bssid = None
            current_ssid = ssid_m.group(1).strip() or "(Hidden SSID)"
            current_auth = ""
            continue

        auth_m = re.match(r"^Authentication\s*:\s*(.+)$", line, re.IGNORECASE)
        if auth_m:
            current_auth = auth_m.group(1).strip()
            continue

        bssid_m = re.match(r"^BSSID\s+\d+\s*:\s*([0-9a-fA-F:.-]+)$", line, re.IGNORECASE)
        if bssid_m:
            if current_bssid:
                networks.append(current_bssid)
            current_bssid = {
                "ssid": current_ssid,
                "bssid": bssid_m.group(1).strip().upper(),
                "authentication": current_auth,
                "signal_pct": None,
                "channel": None,
                "band": "",
            }
            continue

        if current_bssid:
            sig_m = re.match(r"^Signal\s*:\s*(\d+)%", line, re.IGNORECASE)
            if sig_m:
                current_bssid["signal_pct"] = int(sig_m.group(1))
            chan_m = re.match(r"^Channel\s*:\s*(\d+)", line, re.IGNORECASE)
            if chan_m:
                ch = int(chan_m.group(1))
                current_bssid["channel"] = ch
                current_bssid["band"] = "2.4 GHz" if ch <= 14 else "5/6 GHz"

    if current_bssid:
        networks.append(current_bssid)

    networks.sort(key=lambda n: n.get("signal_pct") or 0, reverse=True)
    return networks


def recommend_clean_24ghz_channel(neighbors: list[dict[str, Any]]) -> int:
    """Pick the least congested standard non-overlapping 2.4 GHz channel (1, 6, or 11)."""
    counts = {1: 0, 6: 0, 11: 0}
    for ap in neighbors:
        ch = ap.get("channel")
        if not isinstance(ch, int) or ch > 14:
            continue
        for c in (1, 6, 11):
            if abs(ch - c) <= 2:
                counts[c] += 1
    return min(counts, key=lambda c: counts[c])


async def analyze_wifi() -> dict[str, Any]:
    """Inspect current Wi-Fi link and nearby access points cross-platform."""
    system = platform.system().lower()
    if system == "windows":
        iface_out = await _exec_text(["netsh", "wlan", "show", "interfaces"])
        nets_out = await _exec_text(["netsh", "wlan", "show", "networks", "mode=bssid"])
        current = parse_windows_wlan_interfaces(iface_out)
        neighbors = parse_windows_wlan_networks(nets_out)
        return {
            "available": bool(current or neighbors),
            "current": current,
            "neighbors": neighbors,
            "recommended_24ghz_channel": recommend_clean_24ghz_channel(neighbors),
            "note": None if (current or neighbors) else "No active Windows Wi-Fi interface found",
        }

    # Linux fallback using nmcli if available
    nm_out = await _exec_text(
        ["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,CHAN,SIGNAL,SECURITY", "dev", "wifi", "list"]
    )
    neighbors: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for line in nm_out.splitlines():
        parts = line.replace("\\:", "_COLON_").split(":")
        if len(parts) < 6:
            continue
        active, ssid, bssid, chan_s, sig_s, sec = parts[:6]
        ch = int(chan_s) if chan_s.isdigit() else None
        sig = int(sig_s) if sig_s.isdigit() else None
        entry = {
            "ssid": ssid or "(Hidden SSID)",
            "bssid": bssid.replace("_COLON_", ":"),
            "channel": ch,
            "signal_pct": sig,
            "authentication": sec,
            "band": "2.4 GHz" if (ch and ch <= 14) else "5/6 GHz",
        }
        neighbors.append(entry)
        if active == "yes":
            current = {
                "ssid": entry["ssid"],
                "bssid": entry["bssid"],
                "channel": ch,
                "signal_pct": sig,
                "state": "connected",
            }
    return {
        "available": bool(current or neighbors),
        "current": current,
        "neighbors": neighbors,
        "recommended_24ghz_channel": recommend_clean_24ghz_channel(neighbors),
        "note": None if (current or neighbors) else "Wi-Fi scan requires nmcli on Linux",
    }


async def _exec_text(cmd: list[str]) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=4.0)
        return stdout.decode("utf-8", errors="replace")
    except Exception:
        return ""
