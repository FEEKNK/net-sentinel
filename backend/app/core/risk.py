"""Deterministic Device Security Risk Scoring (0-100, Grade A-F)."""

from __future__ import annotations

from typing import Any


RISKY_PORT_WEIGHTS: dict[int, tuple[int, str]] = {
    23: (30, "Telnet (23) unencrypted remote shell"),
    21: (20, "FTP (21) cleartext file transfer"),
    445: (20, "SMB (445) lateral-movement surface"),
    3389: (20, "RDP (3389) remote desktop exposed"),
    139: (10, "NetBIOS (139) legacy sharing"),
    3306: (15, "MySQL (3306) database port open"),
    5432: (15, "PostgreSQL (5432) database port open"),
    80: (5, "HTTP (80) unencrypted web"),
    8080: (5, "HTTP-Proxy (8080) unencrypted web"),
}


def calculate_device_risk(
    device: dict[str, Any], *, recent_alert_count: int = 0
) -> dict[str, Any]:
    """Calculate a 0-100 risk score, letter grade (A-F), and human-readable reasons."""
    score = 0
    reasons: list[str] = []

    open_ports = device.get("open_ports") or []
    for p in open_ports:
        port_num = int(p.get("port", 0))
        if port_num in RISKY_PORT_WEIGHTS:
            pts, label = RISKY_PORT_WEIGHTS[port_num]
            score += pts
            reasons.append(f"+{pts}: {label}")

    if not device.get("trusted", False) and device.get("ip") != "127.0.0.1":
        score += 15
        reasons.append("+15: Device not marked Trusted")

    if recent_alert_count > 0:
        alert_pts = min(30, recent_alert_count * 15)
        score += alert_pts
        reasons.append(f"+{alert_pts}: Associated with {recent_alert_count} IDS alert(s)")

    # Banner version advisories
    for p in open_ports:
        banner = str(p.get("banner", "")).lower()
        if not banner:
            continue
        if "openssh_7." in banner or "openssh_6." in banner or "apache/2.2" in banner:
            score += 10
            reasons.append(f"+10: Older service banner detected ({p.get('banner')})")
        elif "tlsv1.0" in banner or "tlsv1.1" in banner:
            score += 15
            reasons.append(f"+15: Legacy TLS protocol ({p.get('banner')})")

    score = max(0, min(100, score))

    if score >= 70:
        grade = "F"
    elif score >= 50:
        grade = "D"
    elif score >= 30:
        grade = "C"
    elif score >= 15:
        grade = "B"
    else:
        grade = "A"

    return {
        "risk_score": score,
        "risk_grade": grade,
        "risk_reasons": reasons,
    }
