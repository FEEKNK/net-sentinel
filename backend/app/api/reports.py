"""Security Audit Summary and CSV Export endpoints."""

from __future__ import annotations

import csv
import io
from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import Response

from app.api.deps import AppServices, get_services
from app.core.risk import calculate_device_risk
from app.db.database import utc_now_iso


router = APIRouter(prefix="/api/reports", tags=["reports"])


def sanitize_csv_cell(value: Any) -> str:
    """Neutralize CSV formula injection (Excel/Sheets =, +, -, @, tab, CR)."""
    text = str(value if value is not None else "")
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{text}"
    return text


@router.get("/summary")
async def get_audit_summary(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    devices = await services.db.list_devices(limit=1024)
    alert_counts = await services.db.count_alerts()
    alerts_by_ip = await services.db.count_alerts_by_source_ip()
    recent_alerts = await services.db.list_alerts(limit=50)
    blocked = await services.db.list_blocked_ips(active_only=False)
    telemetry = services.sniffer.get_telemetry()

    scored_devices = [
        {
            **d,
            **calculate_device_risk(d, recent_alert_count=alerts_by_ip.get(d["ip"], 0)),
        }
        for d in devices
    ]
    avg_risk = (
        round(sum(d["risk_score"] for d in scored_devices) / len(scored_devices), 1)
        if scored_devices
        else 0.0
    )
    high_risk_devices = [d for d in scored_devices if d["risk_score"] >= 30]

    return {
        "generated_at": utc_now_iso(),
        "environment": asdict(services.capabilities),
        "device_summary": {
            "total": len(scored_devices),
            "online": sum(1 for d in scored_devices if d.get("status") == "online"),
            "trusted": sum(1 for d in scored_devices if d.get("trusted")),
            "high_risk_count": len(high_risk_devices),
            "average_risk_score": avg_risk,
        },
        "alert_summary": alert_counts,
        "firewall_summary": {
            "dry_run": services.blocker.dry_run,
            "active_blocks": sum(1 for b in blocked if b["active"]),
            "total_block_records": len(blocked),
        },
        "telemetry": telemetry,
        "scored_devices": scored_devices,
        "recent_alerts": recent_alerts,
    }


@router.get("/export.csv")
async def export_audit_csv(services: AppServices = Depends(get_services)) -> Response:
    devices = await services.db.list_devices(limit=1024)
    alerts = await services.db.list_alerts(limit=500)
    alerts_by_ip = await services.db.count_alerts_by_source_ip()

    buf = io.StringIO()
    writer = csv.writer(buf)

    writer.writerow(["=== NETSENTINEL DEVICE & RISK INVENTORY ==="])
    writer.writerow(
        [
            "IP",
            "Status",
            "Trusted",
            "CustomName",
            "Hostname",
            "MAC",
            "Vendor",
            "RiskGrade",
            "RiskScore",
            "OpenPorts",
            "RiskReasons",
        ]
    )
    for d in devices:
        risk = calculate_device_risk(d, recent_alert_count=alerts_by_ip.get(d["ip"], 0))
        ports_str = "; ".join(
            f"{p['port']}/{p['service']}" + (f" ({p['banner']})" if p.get("banner") else "")
            for p in (d.get("open_ports") or [])
        )
        writer.writerow(
            [
                sanitize_csv_cell(d["ip"]),
                sanitize_csv_cell(d["status"]),
                sanitize_csv_cell(d.get("trusted", False)),
                sanitize_csv_cell(d.get("custom_name", "")),
                sanitize_csv_cell(d.get("hostname", "")),
                sanitize_csv_cell(d.get("mac", "")),
                sanitize_csv_cell(d.get("vendor", "")),
                sanitize_csv_cell(risk["risk_grade"]),
                sanitize_csv_cell(risk["risk_score"]),
                sanitize_csv_cell(ports_str),
                sanitize_csv_cell("; ".join(risk["risk_reasons"])),
            ]
        )

    writer.writerow([])
    writer.writerow(["=== NETSENTINEL IDS ALERTS ==="])
    writer.writerow(["ID", "Timestamp", "Severity", "SourceIP", "DestIP", "Protocol", "Title", "Action"])
    for a in alerts:
        writer.writerow(
            [
                sanitize_csv_cell(a["id"]),
                sanitize_csv_cell(a["timestamp"]),
                sanitize_csv_cell(a["severity"]),
                sanitize_csv_cell(a["source_ip"]),
                sanitize_csv_cell(a["dest_ip"]),
                sanitize_csv_cell(a["protocol"]),
                sanitize_csv_cell(a["title"]),
                sanitize_csv_cell(a["action_taken"]),
            ]
        )

    return Response(
        content=buf.getvalue().encode("utf-8-sig"),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="netsentinel-audit-report.csv"'
        },
    )
