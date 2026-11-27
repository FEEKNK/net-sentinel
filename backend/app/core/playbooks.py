"""Mini-SOAR Playbook Automation Engine triggered by IDS alerts."""

from __future__ import annotations

from typing import Any

from app.core.blocker import ActiveResponseBlocker
from app.core.notifier import SEVERITY_RANK, WebhookNotifier
from app.db.database import Database


class PlaybookEngine:
    """Evaluates user-configured IF-THIS-THEN-THAT rules on incoming IDS alerts."""

    def __init__(
        self,
        *,
        db: Database,
        blocker: ActiveResponseBlocker,
        notifier: WebhookNotifier,
    ) -> None:
        self.db = db
        self.blocker = blocker
        self.notifier = notifier

    async def run_for_alert(self, alert: dict[str, Any]) -> list[str]:
        playbooks = await self.db.list_playbooks()
        executed: list[str] = []
        alert_sev = str(alert.get("severity", "low")).lower()
        alert_det = str(alert.get("detector_type", "")).lower()

        for pb in playbooks:
            if not pb.get("enabled"):
                continue
            trig_sev = str(pb.get("trigger_severity", "critical")).lower()
            trig_det = str(pb.get("trigger_detector", "any")).lower()
            if SEVERITY_RANK.get(alert_sev, 1) < SEVERITY_RANK.get(trig_sev, 4):
                continue
            if trig_det != "any" and trig_det != alert_det:
                continue

            action = pb.get("action_type", "create_incident")
            if action == "create_incident":
                await self.db.upsert_incident_for_source(
                    source_ip=str(alert.get("source_ip", "0.0.0.0")),
                    title=str(alert.get("title", "Automated SOC Incident")),
                    severity=alert_sev,
                )
                executed.append(f"playbook:{pb['name']}->create_incident")
            elif action == "notify_webhook":
                await self.notifier.notify_alert(alert, force=True)
                executed.append(f"playbook:{pb['name']}->notify_webhook")
            elif action == "dry_run_block":
                src = str(alert.get("source_ip", ""))
                if src:
                    await self.blocker.evaluate_alert(
                        source_ip=src,
                        severity=alert_sev,
                        title=f"Playbook {pb['name']}",
                    )
                    executed.append(f"playbook:{pb['name']}->evaluate_block")
        return executed
