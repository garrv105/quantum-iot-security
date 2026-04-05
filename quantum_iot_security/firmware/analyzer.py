"""Static firmware analysis: entropy, string extraction, CVE matching.

Analyzes firmware binary images for security issues without executing them.
"""

from __future__ import annotations

import hashlib
import math
import re
import uuid
from collections import Counter

from quantum_iot_security.core.models import DeviceType, FirmwareInfo
from quantum_iot_security.firmware.vulnerability_db import (
    VULNERABILITY_DATABASE,
    VulnerabilityEntry,
)

# Patterns indicating potential security issues in firmware strings
_SUSPICIOUS_PATTERNS: list[tuple[str, str]] = [
    (r"password\s*[:=]\s*\S+", "Hardcoded password"),
    (r"api[_-]?key\s*[:=]\s*\S+", "Hardcoded API key"),
    (r"secret\s*[:=]\s*\S+", "Hardcoded secret"),
    (r"BEGIN\s+(RSA|DSA|EC)\s+PRIVATE\s+KEY", "Embedded private key"),
    (r"telnetd", "Telnet daemon present"),
    (r"debug_mode\s*[:=]\s*(true|1|on)", "Debug mode enabled"),
    (r"admin[:/@]admin", "Default admin credentials"),
    (r"root[:/@]root", "Default root credentials"),
    (r"wget\s+http://", "Insecure HTTP download"),
    (r"/etc/shadow", "Shadow file reference"),
]


def compute_entropy(data: bytes) -> float:
    """Compute Shannon entropy of binary data. Range: 0.0 to 8.0.

    High entropy (>7.0) suggests encryption or compression.
    Very low entropy (<1.0) suggests padding or empty data.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def extract_strings(data: bytes, min_length: int = 4) -> list[str]:
    """Extract printable ASCII strings from binary data."""
    pattern = rb"[\x20-\x7e]{%d,}" % min_length
    matches = re.findall(pattern, data)
    return [m.decode("ascii", errors="ignore") for m in matches]


def find_suspicious_strings(strings: list[str]) -> list[str]:
    """Scan extracted strings for known security-sensitive patterns."""
    findings: list[str] = []
    for s in strings:
        for pattern, description in _SUSPICIOUS_PATTERNS:
            if re.search(pattern, s, re.IGNORECASE):
                findings.append(f"{description}: {s[:80]}")
                break
    return findings


class FirmwareAnalyzer:
    """Static analysis engine for IoT firmware images."""

    def __init__(self) -> None:
        self._analyses: dict[str, FirmwareInfo] = {}

    @property
    def analyses(self) -> dict[str, FirmwareInfo]:
        return dict(self._analyses)

    def analyze(
        self,
        firmware_data: bytes,
        device_type: DeviceType = DeviceType.UNKNOWN,
        version: str = "",
    ) -> FirmwareInfo:
        """Perform full static analysis on a firmware image."""
        firmware_id = uuid.uuid4().hex[:12]
        sha256 = hashlib.sha256(firmware_data).hexdigest()
        entropy = compute_entropy(firmware_data)
        strings = extract_strings(firmware_data)
        suspicious = find_suspicious_strings(strings)
        vulns = self._match_vulnerabilities(strings)
        risk_score = self._calculate_risk_score(entropy, suspicious, vulns)

        info = FirmwareInfo(
            firmware_id=firmware_id,
            device_type=device_type,
            version=version,
            file_size=len(firmware_data),
            sha256=sha256,
            entropy=entropy,
            suspicious_strings=suspicious,
            vulnerabilities=[v.cve_id for v in vulns],
            risk_score=risk_score,
        )
        self._analyses[firmware_id] = info
        return info

    def _match_vulnerabilities(self, strings: list[str]) -> list[VulnerabilityEntry]:
        """Match extracted strings against the vulnerability database."""
        matched: list[VulnerabilityEntry] = []
        all_text = " ".join(strings).lower()
        for vuln in VULNERABILITY_DATABASE:
            if vuln.affected_pattern.lower() in all_text:
                matched.append(vuln)
        return matched

    def _calculate_risk_score(
        self,
        entropy: float,
        suspicious: list[str],
        vulns: list[VulnerabilityEntry],
    ) -> float:
        """Calculate an overall risk score (0-10) for the firmware."""
        score = 0.0

        # High entropy is suspicious (may be packed/encrypted malware)
        if entropy > 7.5:
            score += 2.0
        elif entropy > 7.0:
            score += 1.0

        # Each suspicious string adds risk
        score += min(len(suspicious) * 0.5, 3.0)

        # Vulnerabilities add risk based on severity
        for vuln in vulns:
            if vuln.severity == "critical":
                score += 2.0
            elif vuln.severity == "high":
                score += 1.5
            elif vuln.severity == "medium":
                score += 1.0
            elif vuln.severity == "low":
                score += 0.5

        return min(score, 10.0)

    def compare_firmware(self, fw1: FirmwareInfo, fw2: FirmwareInfo) -> dict[str, any]:
        """Compare two firmware versions for security regression."""
        return {
            "size_delta": fw2.file_size - fw1.file_size,
            "entropy_delta": fw2.entropy - fw1.entropy,
            "new_vulnerabilities": [
                v for v in fw2.vulnerabilities if v not in fw1.vulnerabilities
            ],
            "fixed_vulnerabilities": [
                v for v in fw1.vulnerabilities if v not in fw2.vulnerabilities
            ],
            "risk_delta": fw2.risk_score - fw1.risk_score,
            "regression": fw2.risk_score > fw1.risk_score,
        }
