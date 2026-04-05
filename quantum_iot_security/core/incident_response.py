"""Automated incident response: quarantine, alerting, and forensic evidence collection."""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any

from quantum_iot_security.core.models import (
    AnomalyEvent,
    Incident,
    IncidentAction,
    ThreatLevel,
)

# Mapping from threat level to automated response actions
_RESPONSE_POLICIES: dict[ThreatLevel, list[IncidentAction]] = {
    ThreatLevel.CRITICAL: [
        IncidentAction.QUARANTINE,
        IncidentAction.ALERT,
        IncidentAction.LOG,
        IncidentAction.BLOCK,
    ],
    ThreatLevel.HIGH: [
        IncidentAction.QUARANTINE,
        IncidentAction.ALERT,
        IncidentAction.LOG,
    ],
    ThreatLevel.MEDIUM: [
        IncidentAction.ALERT,
        IncidentAction.LOG,
        IncidentAction.INVESTIGATE,
    ],
    ThreatLevel.LOW: [
        IncidentAction.LOG,
        IncidentAction.INVESTIGATE,
    ],
    ThreatLevel.INFO: [
        IncidentAction.LOG,
    ],
}


class IncidentResponder:
    """Automated incident response engine for IoT security events."""

    def __init__(self, evidence_dir: str | Path | None = None) -> None:
        self._incidents: dict[str, Incident] = {}
        self._quarantined_devices: set[str] = set()
        self._alerts: list[dict[str, Any]] = []
        self._evidence_dir = Path(evidence_dir) if evidence_dir else None
        if self._evidence_dir:
            self._evidence_dir.mkdir(parents=True, exist_ok=True)

    @property
    def incidents(self) -> dict[str, Incident]:
        return dict(self._incidents)

    @property
    def quarantined_devices(self) -> set[str]:
        return set(self._quarantined_devices)

    @property
    def alerts(self) -> list[dict[str, Any]]:
        return list(self._alerts)

    def evaluate_threat(self, events: list[AnomalyEvent]) -> ThreatLevel:
        """Determine the overall threat level from a set of anomaly events."""
        if not events:
            return ThreatLevel.INFO

        anomalies = [e for e in events if e.is_anomaly]
        if not anomalies:
            return ThreatLevel.INFO

        # Use the worst score to determine threat
        worst_score = min(e.anomaly_score for e in anomalies)
        if worst_score < -0.5:
            return ThreatLevel.CRITICAL
        if worst_score < -0.3:
            return ThreatLevel.HIGH
        if worst_score < -0.1:
            return ThreatLevel.MEDIUM
        return ThreatLevel.LOW

    def create_incident(
        self,
        device_id: str,
        events: list[AnomalyEvent],
        description: str = "",
    ) -> Incident:
        """Create a new incident from anomaly events and trigger automated response."""
        threat_level = self.evaluate_threat(events)
        incident_id = uuid.uuid4().hex[:12]

        incident = Incident(
            incident_id=incident_id,
            device_id=device_id,
            threat_level=threat_level,
            description=description or f"Automated incident for device {device_id}",
            anomaly_events=events,
        )

        # Execute response policy
        actions = _RESPONSE_POLICIES.get(threat_level, [IncidentAction.LOG])
        for action in actions:
            self._execute_action(incident, action)

        self._incidents[incident_id] = incident
        return incident

    def _execute_action(self, incident: Incident, action: IncidentAction) -> None:
        """Execute a single response action on an incident."""
        incident.actions_taken.append(action)

        if action == IncidentAction.QUARANTINE:
            self._quarantine_device(incident.device_id)
        elif action == IncidentAction.ALERT:
            self._generate_alert(incident)
        elif action == IncidentAction.LOG:
            self._log_evidence(incident)
        elif action == IncidentAction.BLOCK:
            self._block_device(incident.device_id)

    def _quarantine_device(self, device_id: str) -> None:
        """Place a device in quarantine — isolate from network."""
        self._quarantined_devices.add(device_id)

    def _generate_alert(self, incident: Incident) -> None:
        """Generate an alert notification."""
        alert = {
            "incident_id": incident.incident_id,
            "device_id": incident.device_id,
            "threat_level": incident.threat_level.value,
            "description": incident.description,
            "timestamp": time.time(),
            "num_anomalies": len([e for e in incident.anomaly_events if e.is_anomaly]),
        }
        self._alerts.append(alert)

    def _block_device(self, device_id: str) -> None:
        """Block device traffic (adds to quarantine with block flag)."""
        self._quarantined_devices.add(device_id)

    def _log_evidence(self, incident: Incident) -> None:
        """Collect forensic evidence and optionally write to disk."""
        evidence = {
            "incident_id": incident.incident_id,
            "device_id": incident.device_id,
            "timestamp": time.time(),
            "threat_level": incident.threat_level.value,
            "anomaly_events": [e.model_dump() for e in incident.anomaly_events],
        }
        incident.evidence = evidence

        if self._evidence_dir:
            path = self._evidence_dir / f"{incident.incident_id}.json"
            path.write_text(json.dumps(evidence, indent=2, default=str))

    def resolve_incident(self, incident_id: str) -> bool:
        """Mark an incident as resolved and release quarantined device."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return False
        incident.resolved = True
        self._quarantined_devices.discard(incident.device_id)
        return True

    def get_active_incidents(self) -> list[Incident]:
        """Return all unresolved incidents."""
        return [inc for inc in self._incidents.values() if not inc.resolved]

    def get_incident_summary(self) -> dict[str, Any]:
        """Return a summary of all incidents."""
        all_incidents = list(self._incidents.values())
        return {
            "total": len(all_incidents),
            "active": len([i for i in all_incidents if not i.resolved]),
            "resolved": len([i for i in all_incidents if i.resolved]),
            "quarantined_devices": len(self._quarantined_devices),
            "by_threat_level": {
                level.value: len([i for i in all_incidents if i.threat_level == level])
                for level in ThreatLevel
            },
        }
