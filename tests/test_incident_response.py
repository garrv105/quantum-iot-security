"""Tests for incident response automation."""

from __future__ import annotations

from quantum_iot_security.core.incident_response import IncidentResponder
from quantum_iot_security.core.models import AnomalyEvent, ThreatLevel


class TestIncidentResponder:
    def test_create_incident_from_events(
        self, incident_responder: IncidentResponder, sample_anomaly_events: list[AnomalyEvent]
    ):
        """Creating an incident should trigger automated response actions."""
        incident = incident_responder.create_incident(
            device_id="device-001",
            events=sample_anomaly_events,
            description="Test incident",
        )
        assert incident.incident_id
        assert incident.device_id == "device-001"
        assert incident.threat_level == ThreatLevel.CRITICAL
        assert len(incident.actions_taken) > 0

    def test_critical_triggers_quarantine(
        self, incident_responder: IncidentResponder, sample_anomaly_events: list[AnomalyEvent]
    ):
        """Critical incidents should quarantine the device."""
        incident_responder.create_incident("device-001", sample_anomaly_events)
        assert "device-001" in incident_responder.quarantined_devices

    def test_critical_generates_alert(
        self, incident_responder: IncidentResponder, sample_anomaly_events: list[AnomalyEvent]
    ):
        """Critical incidents should generate alerts."""
        incident_responder.create_incident("device-001", sample_anomaly_events)
        assert len(incident_responder.alerts) > 0
        assert incident_responder.alerts[0]["threat_level"] == "critical"

    def test_resolve_incident(
        self, incident_responder: IncidentResponder, sample_anomaly_events: list[AnomalyEvent]
    ):
        """Resolving an incident should release the quarantined device."""
        incident = incident_responder.create_incident("device-001", sample_anomaly_events)
        assert not incident.resolved

        success = incident_responder.resolve_incident(incident.incident_id)
        assert success
        assert "device-001" not in incident_responder.quarantined_devices

    def test_resolve_nonexistent(self, incident_responder: IncidentResponder):
        """Resolving a nonexistent incident should return False."""
        assert not incident_responder.resolve_incident("fake-id")

    def test_evaluate_threat_no_anomalies(self, incident_responder: IncidentResponder):
        """No anomalies should result in INFO threat level."""
        events = [
            AnomalyEvent(event_id="e1", device_id="d1", anomaly_score=0.5, is_anomaly=False),
        ]
        level = incident_responder.evaluate_threat(events)
        assert level == ThreatLevel.INFO

    def test_evidence_collection(
        self, incident_responder: IncidentResponder, sample_anomaly_events: list[AnomalyEvent]
    ):
        """Incidents should collect forensic evidence."""
        incident = incident_responder.create_incident("device-001", sample_anomaly_events)
        assert incident.evidence
        assert "anomaly_events" in incident.evidence

    def test_incident_summary(
        self, incident_responder: IncidentResponder, sample_anomaly_events: list[AnomalyEvent]
    ):
        """Summary should reflect current incident state."""
        incident_responder.create_incident("device-001", sample_anomaly_events)
        summary = incident_responder.get_incident_summary()
        assert summary["total"] == 1
        assert summary["active"] == 1
