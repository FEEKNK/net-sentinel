"""Suricata eve.json parser for integrating 10Gbps C/Rust sensors into NetSentinel."""

from __future__ import annotations

import json
from typing import Any


def parse_suricata_eve_lines(raw_ndjson: str) -> dict[str, list[dict[str, Any]]]:
    """Parse newline-delimited Suricata eve.json events into alerts and DNS observations."""
    alerts: list[dict[str, Any]] = []
    dns_events: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    for line_no, raw in enumerate(raw_ndjson.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            evt = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append({"line": line_no, "error": f"Invalid JSON: {exc}"})
            continue

        if not isinstance(evt, dict):
            continue

        evt_type = str(evt.get("event_type", "")).lower()
        src_ip = str(evt.get("src_ip", ""))
        dst_ip = str(evt.get("dest_ip", ""))
        src_port = evt.get("src_port")
        dst_port = evt.get("dest_port")
        proto = str(evt.get("proto", "ANY")).upper()

        if evt_type == "alert":
            alert_obj = evt.get("alert") or {}
            sev_num = int(alert_obj.get("severity", 3))
            sev = (
                "critical"
                if sev_num <= 1
                else "high"
                if sev_num == 2
                else "medium"
                if sev_num == 3
                else "low"
            )
            alerts.append(
                {
                    "source_ip": src_ip or "0.0.0.0",
                    "dest_ip": dst_ip,
                    "src_port": int(src_port) if isinstance(src_port, int) else None,
                    "dest_port": int(dst_port) if isinstance(dst_port, int) else None,
                    "protocol": proto,
                    "rule_sid": alert_obj.get("signature_id"),
                    "title": str(alert_obj.get("signature", "Suricata Alert")),
                    "description": f"Suricata category: {alert_obj.get('category', 'unknown')}",
                    "severity": sev,
                    "detector_type": "suricata_eve",
                }
            )
        elif evt_type == "dns":
            dns_obj = evt.get("dns") or {}
            rrname = str(dns_obj.get("rrname", "")).strip()
            if rrname:
                dns_events.append({"src_ip": src_ip, "domain": rrname.rstrip(".")})

    return {"alerts": alerts, "dns": dns_events, "errors": errors}
