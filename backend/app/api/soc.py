"""SOC Operations API: Incidents, Mini-SOAR Playbooks, IOCs, IDS Tuning, Compliance, and Device 360 Timeline."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.api.deps import AppServices, get_services
from app.config import settings
from app.core.risk import calculate_device_risk
from app.platform.base import validate_ip_address


router = APIRouter(prefix="/api/soc", tags=["soc"])


class UpdateIncidentRequest(BaseModel):
    status: Literal["open", "investigating", "resolved", "false_positive"] | None = None
    notes: str | None = Field(default=None, max_length=1000)


class CreatePlaybookRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=64)
    trigger_severity: Literal["low", "medium", "high", "critical"] = "critical"
    trigger_detector: str = Field(default="any", max_length=48)
    action_type: Literal["create_incident", "notify_webhook", "dry_run_block"] = "create_incident"


class ImportIocRequest(BaseModel):
    raw_text: str = Field(..., min_length=3, max_length=500_000)
    source: str = Field(default="manual", max_length=64)
    severity: Literal["medium", "high", "critical"] = "critical"


class UpdateTuningRequest(BaseModel):
    port_scan_threshold: int | None = Field(default=None, ge=2, le=5000)
    syn_flood_threshold: int | None = Field(default=None, ge=2, le=5000)
    bruteforce_threshold: int | None = Field(default=None, ge=2, le=5000)
    icmp_flood_threshold: int | None = Field(default=None, ge=2, le=5000)
    icmp_oversize_bytes: int | None = Field(default=None, ge=64, le=65500)
    dns_length_threshold: int | None = Field(default=None, ge=15, le=255)
    dns_entropy_threshold: float | None = Field(default=None, ge=2.0, le=6.0)
    cooldown_seconds: float | None = Field(default=None, ge=1.0, le=3600.0)
    disabled_detectors: list[str] | None = None


@router.get("/incidents")
async def list_incidents(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    return {"incidents": await services.db.list_incidents(limit=100)}


@router.patch("/incidents/{incident_id}")
async def update_incident(
    incident_id: int,
    payload: UpdateIncidentRequest,
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    updated = await services.db.update_incident(
        incident_id, status=payload.status, notes=payload.notes
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return updated


@router.get("/playbooks")
async def list_playbooks(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    return {"playbooks": await services.db.list_playbooks()}


@router.post("/playbooks")
async def create_playbook(
    payload: CreatePlaybookRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    return await services.db.create_playbook(
        name=payload.name.strip(),
        trigger_severity=payload.trigger_severity,
        trigger_detector=payload.trigger_detector.strip(),
        action_type=payload.action_type,
    )


@router.patch("/playbooks/{playbook_id}")
async def toggle_playbook(
    playbook_id: int,
    enabled: bool = Query(...),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    if not await services.db.toggle_playbook(playbook_id, enabled):
        raise HTTPException(status_code=404, detail="Playbook not found")
    return {"id": playbook_id, "enabled": enabled}


@router.delete("/playbooks/{playbook_id}")
async def delete_playbook(
    playbook_id: int,
    confirm: bool = Query(default=False),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    if not confirm:
        raise HTTPException(status_code=400, detail="Confirmation required (confirm=true)")
    if not await services.db.delete_playbook(playbook_id):
        raise HTTPException(status_code=404, detail="Playbook not found")
    return {"deleted": True, "id": playbook_id}


@router.get("/iocs")
async def list_iocs(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    rows = await services.db.list_iocs(limit=500)
    return {
        "iocs": rows,
        "ip_count": len(services.ioc_matcher.ips),
        "domain_count": len(services.ioc_matcher.domains),
    }


@router.post("/iocs/import")
async def import_iocs(
    payload: ImportIocRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    return await services.ioc_matcher.import_text(
        payload.raw_text, source=payload.source.strip(), severity=payload.severity
    )


@router.delete("/iocs/{ioc_id}")
async def delete_ioc(
    ioc_id: int,
    confirm: bool = Query(default=False),
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    if not confirm:
        raise HTTPException(status_code=400, detail="Confirmation required (confirm=true)")
    if not await services.db.delete_ioc(ioc_id):
        raise HTTPException(status_code=404, detail="IOC not found")
    await services.ioc_matcher.reload()
    return {"deleted": True, "id": ioc_id}


@router.get("/ids-tuning")
async def get_ids_tuning(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    return services.ids_engine.get_tuning()


@router.put("/ids-tuning")
async def update_ids_tuning(
    payload: UpdateTuningRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    updated = services.ids_engine.update_tuning(payload.model_dump(exclude_none=True))
    await services.db.set_setting("ids_tuning", updated)
    return updated


@router.get("/compliance")
async def get_compliance_scorecard(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    safety = services.safety_manager.get_state()
    users = await services.db.list_users()
    audit_logs = await services.db.list_audit_logs(limit=10)
    sensors = await services.db.list_sensors()
    snaps = await services.db.list_config_snapshots(limit=5)

    checks = [
        {
            "id": "auth_rbac",
            "control": "Access Control (Passcode / Multi-User RBAC)",
            "passed": services.auth_manager.enabled or len(users) > 0,
            "detail": "เปิดใช้งาน Dashboard Lock / RBAC เพื่อป้องกันการเข้าถึงโดยไม่ได้รับอนุญาต",
        },
        {
            "id": "retention_90d",
            "control": "Thai Computer Crime Act (>= 90-Day Log Retention)",
            "passed": safety["retention_days"] >= 90,
            "detail": f"ตั้งค่าเก็บ Log ไว้ที่ {safety['retention_days']} วัน",
        },
        {
            "id": "safe_firewall",
            "control": "Safe Active Response (Dry-Run or Hospital Passive Mode)",
            "passed": services.blocker.dry_run or safety["is_hospital_safe"],
            "detail": "ป้องกันการบล็อกอุปกรณ์สำคัญผิดพลาดอัตโนมัติ",
        },
        {
            "id": "pdpa_privacy",
            "control": "PDPA / PHI Privacy (Header-Only Redaction)",
            "passed": safety["privacy_mode"],
            "detail": "ตัด Payload และชื่อโดเมนก่อนจัดเก็บเพื่อลดความเสี่ยงข้อมูลส่วนบุคคล",
        },
        {
            "id": "audit_trail",
            "control": "Immutable Audit Trail",
            "passed": len(audit_logs) > 0,
            "detail": f"มีประวัติ Audit Log แล้ว {len(audit_logs)}+ รายการ",
        },
        {
            "id": "config_backup",
            "control": "Configuration Snapshot & Drift Baseline",
            "passed": len(snaps) > 0,
            "detail": "บันทึก Snapshot กฎและนโยบายไว้ตรวจสอบการเปลี่ยนแปลง",
        },
        {
            "id": "dual_db",
            "control": "Database Engine (SQLite / PostgreSQL Ready)",
            "passed": True,
            "detail": (
                "PostgreSQL Configured"
                if settings.database_url.startswith("postgresql")
                else f"SQLite Local Mode ({len(sensors)} remote sensors)"
            ),
        },
    ]

    passed_count = sum(1 for c in checks if c["passed"])
    score_pct = round((passed_count / len(checks)) * 100)
    return {
        "score_pct": score_pct,
        "passed_count": passed_count,
        "total_checks": len(checks),
        "checks": checks,
    }


@router.get("/device-360/{ip}")
async def get_device_360_timeline(
    ip: str, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    try:
        safe_ip = validate_ip_address(ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    device = await services.db.get_device(safe_ip)
    history = await services.db.get_device_history(safe_ip, limit=60)
    all_alerts = await services.db.list_alerts(limit=250)
    related_alerts = [
        a for a in all_alerts if a.get("source_ip") == safe_ip or a.get("dest_ip") == safe_ip
    ][:40]

    risk = (
        calculate_device_risk(device, recent_alert_count=len(related_alerts))
        if device
        else {"risk_score": 0, "risk_grade": "A", "risk_reasons": []}
    )
    return {
        "ip": safe_ip,
        "device": device,
        "risk": risk,
        "history": history,
        "alerts": related_alerts,
    }
