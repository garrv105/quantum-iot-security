"""Tests for report generation and compliance checking."""

from __future__ import annotations

from quantum_iot_security.core.models import (
    DeviceFingerprint,
    FirmwareInfo,
    Incident,
    ProtocolType,
    ThreatLevel,
)
from quantum_iot_security.reporting.compliance import ComplianceChecker
from quantum_iot_security.reporting.generator import ReportGenerator


class TestReportGenerator:
    def test_incident_report(self):
        """Incident report should include summary and details."""
        gen = ReportGenerator()
        incidents = [
            Incident(
                incident_id="inc-001",
                device_id="dev-001",
                threat_level=ThreatLevel.CRITICAL,
                description="Test incident",
            ),
        ]
        report = gen.generate_incident_report(incidents)
        assert report["report_type"] == "incident_report"
        assert report["summary"]["total_incidents"] == 1
        assert report["summary"]["critical"] == 1

    def test_device_inventory(self):
        """Device inventory should list all devices."""
        gen = ReportGenerator()
        devices = [
            DeviceFingerprint(
                device_id="dev-001",
                ip_address="10.0.0.1",
                mac_address="AA:BB:CC:DD:EE:01",
                protocols=[ProtocolType.MQTT],
                confidence=0.8,
            ),
        ]
        report = gen.generate_device_inventory(devices)
        assert report["summary"]["total_devices"] == 1
        assert len(report["devices"]) == 1

    def test_firmware_report(self):
        """Firmware report should categorize by risk."""
        gen = ReportGenerator()
        analyses = [
            FirmwareInfo(firmware_id="fw-001", risk_score=8.0, vulnerabilities=["CVE-2021-44228"]),
            FirmwareInfo(firmware_id="fw-002", risk_score=2.0),
        ]
        report = gen.generate_firmware_report(analyses)
        assert report["summary"]["high_risk"] == 1
        assert report["summary"]["low_risk"] == 1

    def test_save_report(self, tmp_path):
        """Report should save to JSON file."""
        gen = ReportGenerator()
        report = {"test": "data"}
        path = gen.save_report(report, tmp_path / "report.json")
        assert path.exists()


class TestComplianceChecker:
    def test_nist_compliance(self):
        """NIST compliance check should produce results."""
        checker = ComplianceChecker()
        devices = [
            DeviceFingerprint(
                device_id="d1",
                ip_address="10.0.0.1",
                mac_address="AA:BB:CC:DD:EE:01",
                protocols=[ProtocolType.MQTT],
            ),
        ]
        results = checker.check_nist_compliance(devices)
        assert len(results) > 0
        assert all(r.framework == "NIST-IoT" for r in results)

    def test_iec62443_compliance(self):
        """IEC 62443 compliance check should produce results."""
        checker = ComplianceChecker()
        devices = [
            DeviceFingerprint(
                device_id="d1",
                ip_address="10.0.0.1",
                protocols=[ProtocolType.HTTPS],
            ),
        ]
        results = checker.check_iec62443_compliance(devices)
        assert len(results) > 0

    def test_compliance_summary(self):
        """Summary should aggregate results by framework."""
        checker = ComplianceChecker()
        devices = [
            DeviceFingerprint(device_id="d1", ip_address="10.0.0.1", protocols=[ProtocolType.MQTT]),
        ]
        checker.check_nist_compliance(devices)
        checker.check_iec62443_compliance(devices)
        summary = checker.get_compliance_summary()
        assert "NIST-IoT" in summary
        assert "IEC-62443" in summary
