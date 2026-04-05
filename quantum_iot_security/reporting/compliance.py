"""IoT compliance mapping against NIST and IEC 62443 security frameworks."""

from __future__ import annotations

from typing import Any

from quantum_iot_security.core.models import ComplianceResult, DeviceFingerprint, FirmwareInfo

# NIST IoT Cybersecurity requirements (simplified subset)
_NIST_REQUIREMENTS: list[dict[str, str]] = [
    {
        "id": "NIST-IOT-1.1",
        "category": "Device Identification",
        "description": "Device shall support unique logical and physical identifiers",
    },
    {
        "id": "NIST-IOT-1.2",
        "category": "Device Identification",
        "description": "Device configuration shall be changeable only by authorized entities",
    },
    {
        "id": "NIST-IOT-2.1",
        "category": "Data Protection",
        "description": "Device shall use approved cryptographic algorithms for data at rest",
    },
    {
        "id": "NIST-IOT-2.2",
        "category": "Data Protection",
        "description": "Device shall use approved cryptographic algorithms for data in transit",
    },
    {
        "id": "NIST-IOT-3.1",
        "category": "Access Control",
        "description": "Device shall restrict logical access to authorized entities only",
    },
    {
        "id": "NIST-IOT-4.1",
        "category": "Software Update",
        "description": "Device shall support secure software updates",
    },
    {
        "id": "NIST-IOT-5.1",
        "category": "Logging",
        "description": "Device shall log security-relevant events",
    },
]

# IEC 62443 Industrial IoT requirements (simplified subset)
_IEC62443_REQUIREMENTS: list[dict[str, str]] = [
    {
        "id": "IEC-62443-3.3-SR-1.1",
        "category": "Authentication",
        "description": "Human user identification and authentication",
    },
    {
        "id": "IEC-62443-3.3-SR-1.7",
        "category": "Authentication",
        "description": "Strength of password-based authentication",
    },
    {
        "id": "IEC-62443-3.3-SR-3.1",
        "category": "Communication Integrity",
        "description": "Communication integrity protection",
    },
    {
        "id": "IEC-62443-3.3-SR-3.5",
        "category": "Input Validation",
        "description": "Input validation for all external data",
    },
    {
        "id": "IEC-62443-3.3-SR-4.1",
        "category": "Confidentiality",
        "description": "Information confidentiality protection",
    },
    {
        "id": "IEC-62443-3.3-SR-6.1",
        "category": "Audit",
        "description": "Audit log accessibility and protection",
    },
]


class ComplianceChecker:
    """Checks IoT devices and firmware against security compliance frameworks."""

    def __init__(self) -> None:
        self._results: list[ComplianceResult] = []

    @property
    def results(self) -> list[ComplianceResult]:
        return list(self._results)

    def check_nist_compliance(
        self,
        devices: list[DeviceFingerprint],
        firmware: list[FirmwareInfo] | None = None,
    ) -> list[ComplianceResult]:
        """Evaluate devices against NIST IoT cybersecurity requirements."""
        results: list[ComplianceResult] = []

        for req in _NIST_REQUIREMENTS:
            result = ComplianceResult(
                framework="NIST-IoT",
                category=req["category"],
                requirement_id=req["id"],
                description=req["description"],
            )

            if req["id"] == "NIST-IOT-1.1":
                # Check unique device identification
                ids = {d.device_id for d in devices}
                if len(ids) == len(devices) and all(d.mac_address for d in devices):
                    result.status = "compliant"
                elif len(ids) == len(devices):
                    result.status = "partially_compliant"
                    result.findings.append("Some devices lack MAC address identification")
                else:
                    result.status = "non_compliant"
                    result.findings.append("Duplicate device identifiers detected")

            elif req["id"] == "NIST-IOT-2.2":
                # Check encryption in transit
                encrypted = [d for d in devices if any(
                    p.value in ("https", "mqtt") for p in d.protocols
                )]
                ratio = len(encrypted) / len(devices) if devices else 0
                if ratio >= 0.9:
                    result.status = "compliant"
                elif ratio >= 0.5:
                    result.status = "partially_compliant"
                    result.findings.append(
                        f"{len(devices) - len(encrypted)} devices use unencrypted protocols"
                    )
                else:
                    result.status = "non_compliant"
                    result.findings.append("Majority of devices lack encrypted communication")

            elif req["id"] == "NIST-IOT-4.1" and firmware:
                # Check firmware for update capability indicators
                high_risk = [f for f in firmware if f.risk_score >= 7.0]
                if not high_risk:
                    result.status = "compliant"
                else:
                    result.status = "non_compliant"
                    result.findings.append(
                        f"{len(high_risk)} firmware images have high risk scores"
                    )
            else:
                result.status = "not_assessed"
                result.findings.append("Insufficient data for assessment")

            results.append(result)

        self._results.extend(results)
        return results

    def check_iec62443_compliance(
        self,
        devices: list[DeviceFingerprint],
    ) -> list[ComplianceResult]:
        """Evaluate devices against IEC 62443 requirements."""
        results: list[ComplianceResult] = []

        for req in _IEC62443_REQUIREMENTS:
            result = ComplianceResult(
                framework="IEC-62443",
                category=req["category"],
                requirement_id=req["id"],
                description=req["description"],
            )

            if req["id"] == "IEC-62443-3.3-SR-3.1":
                # Check communication integrity (encrypted protocols)
                secure = [d for d in devices if any(
                    p.value in ("https", "mqtt") for p in d.protocols
                )]
                if len(secure) == len(devices) and devices:
                    result.status = "compliant"
                elif secure:
                    result.status = "partially_compliant"
                    result.findings.append("Not all devices use integrity-protected communication")
                else:
                    result.status = "non_compliant"
                    result.findings.append("No devices use integrity-protected protocols")
            else:
                result.status = "not_assessed"
                result.findings.append("Requires manual assessment")

            results.append(result)

        self._results.extend(results)
        return results

    def get_compliance_summary(self) -> dict[str, Any]:
        """Return a summary of all compliance checks."""
        summary: dict[str, dict[str, int]] = {}
        for result in self._results:
            fw = result.framework
            if fw not in summary:
                summary[fw] = {
                    "compliant": 0,
                    "partially_compliant": 0,
                    "non_compliant": 0,
                    "not_assessed": 0,
                }
            summary[fw][result.status] = summary[fw].get(result.status, 0) + 1
        return summary
