"""JSON report generation for IoT security assessments."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from quantum_iot_security.core.models import (
    DeviceFingerprint,
    FirmwareInfo,
    Incident,
    ThreatLevel,
)


class ReportGenerator:
    """Generates structured security assessment reports in JSON format."""

    def __init__(self, organization: str = "QuantumIoT Security") -> None:
        self._organization = organization

    def generate_incident_report(
        self,
        incidents: list[Incident],
        include_evidence: bool = True,
    ) -> dict[str, Any]:
        """Generate a comprehensive incident report."""
        critical = [i for i in incidents if i.threat_level == ThreatLevel.CRITICAL]
        high = [i for i in incidents if i.threat_level == ThreatLevel.HIGH]

        report = {
            "report_type": "incident_report",
            "organization": self._organization,
            "generated_at": time.time(),
            "summary": {
                "total_incidents": len(incidents),
                "critical": len(critical),
                "high": len(high),
                "resolved": len([i for i in incidents if i.resolved]),
                "unresolved": len([i for i in incidents if not i.resolved]),
            },
            "incidents": [],
        }

        for incident in incidents:
            entry = {
                "incident_id": incident.incident_id,
                "device_id": incident.device_id,
                "threat_level": incident.threat_level.value,
                "description": incident.description,
                "actions_taken": [a.value for a in incident.actions_taken],
                "resolved": incident.resolved,
                "anomaly_count": len(incident.anomaly_events),
            }
            if include_evidence and incident.evidence:
                entry["evidence"] = incident.evidence
            report["incidents"].append(entry)

        return report

    def generate_device_inventory(
        self,
        devices: list[DeviceFingerprint],
    ) -> dict[str, Any]:
        """Generate a device inventory report."""
        return {
            "report_type": "device_inventory",
            "organization": self._organization,
            "generated_at": time.time(),
            "summary": {
                "total_devices": len(devices),
                "by_type": self._count_by(devices, lambda d: d.device_type.value),
                "avg_confidence": (
                    sum(d.confidence for d in devices) / len(devices) if devices else 0.0
                ),
            },
            "devices": [
                {
                    "device_id": d.device_id,
                    "ip_address": d.ip_address,
                    "mac_address": d.mac_address,
                    "device_type": d.device_type.value,
                    "protocols": [p.value for p in d.protocols],
                    "open_ports": d.open_ports,
                    "confidence": d.confidence,
                    "fingerprint_hash": d.fingerprint_hash,
                }
                for d in devices
            ],
        }

    def generate_firmware_report(
        self,
        analyses: list[FirmwareInfo],
    ) -> dict[str, Any]:
        """Generate a firmware analysis report."""
        return {
            "report_type": "firmware_analysis",
            "organization": self._organization,
            "generated_at": time.time(),
            "summary": {
                "total_analyzed": len(analyses),
                "high_risk": len([a for a in analyses if a.risk_score >= 7.0]),
                "medium_risk": len([a for a in analyses if 4.0 <= a.risk_score < 7.0]),
                "low_risk": len([a for a in analyses if a.risk_score < 4.0]),
                "total_vulnerabilities": sum(len(a.vulnerabilities) for a in analyses),
            },
            "analyses": [
                {
                    "firmware_id": a.firmware_id,
                    "version": a.version,
                    "file_size": a.file_size,
                    "sha256": a.sha256,
                    "entropy": round(a.entropy, 4),
                    "risk_score": round(a.risk_score, 2),
                    "vulnerabilities": a.vulnerabilities,
                    "suspicious_strings_count": len(a.suspicious_strings),
                }
                for a in analyses
            ],
        }

    def save_report(self, report: dict[str, Any], path: str | Path) -> Path:
        """Save a report to a JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, default=str))
        return path

    @staticmethod
    def _count_by(items: list, key_fn) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in items:
            k = key_fn(item)
            counts[k] = counts.get(k, 0) + 1
        return counts
