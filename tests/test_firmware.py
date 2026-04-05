"""Tests for firmware analysis."""

from __future__ import annotations

from quantum_iot_security.firmware.analyzer import (
    FirmwareAnalyzer,
    compute_entropy,
    extract_strings,
    find_suspicious_strings,
)
from quantum_iot_security.firmware.vulnerability_db import (
    get_by_cve,
    get_critical_vulnerabilities,
    search_vulnerabilities,
)


class TestFirmwareAnalyzer:
    def test_analyze_basic(self, firmware_analyzer: FirmwareAnalyzer, sample_firmware_data: bytes):
        """Basic analysis should produce complete FirmwareInfo."""
        result = firmware_analyzer.analyze(sample_firmware_data, version="3.1")
        assert result.firmware_id
        assert result.sha256
        assert result.file_size == len(sample_firmware_data)
        assert result.version == "3.1"
        assert result.entropy > 0.0

    def test_detect_hardcoded_password(
        self, firmware_analyzer: FirmwareAnalyzer, sample_firmware_data: bytes
    ):
        """Firmware with password= should flag suspicious strings."""
        result = firmware_analyzer.analyze(sample_firmware_data)
        assert len(result.suspicious_strings) > 0
        assert any("password" in s.lower() for s in result.suspicious_strings)

    def test_detect_vulnerabilities(
        self, firmware_analyzer: FirmwareAnalyzer, sample_firmware_data: bytes
    ):
        """Firmware with known patterns should match CVEs."""
        result = firmware_analyzer.analyze(sample_firmware_data)
        assert len(result.vulnerabilities) > 0

    def test_risk_score_range(self, firmware_analyzer: FirmwareAnalyzer, sample_firmware_data: bytes):
        """Risk score should be between 0 and 10."""
        result = firmware_analyzer.analyze(sample_firmware_data)
        assert 0.0 <= result.risk_score <= 10.0

    def test_compare_firmware(self, firmware_analyzer: FirmwareAnalyzer):
        """Firmware comparison should detect regressions."""
        fw1 = firmware_analyzer.analyze(b"safe firmware" + bytes(100))
        fw2 = firmware_analyzer.analyze(b"password=admin telnetd" + bytes(100))
        comparison = firmware_analyzer.compare_firmware(fw1, fw2)
        assert "risk_delta" in comparison
        assert "regression" in comparison


class TestEntropyAndStrings:
    def test_entropy_empty(self):
        assert compute_entropy(b"") == 0.0

    def test_entropy_uniform(self):
        """Uniform data should have high entropy."""
        data = bytes(range(256)) * 100
        assert compute_entropy(data) > 7.0

    def test_entropy_repeated(self):
        """Repeated single byte should have zero entropy."""
        assert compute_entropy(b"\x00" * 1000) == 0.0

    def test_extract_strings(self):
        data = b"\x00\x00hello world\x00\x00test\x00\x01\x02"
        strings = extract_strings(data, min_length=4)
        assert "hello world" in strings
        assert "test" in strings

    def test_find_suspicious_password(self):
        strings = ["password=secret123", "normal text"]
        findings = find_suspicious_strings(strings)
        assert len(findings) > 0


class TestVulnerabilityDB:
    def test_search_log4j(self):
        results = search_vulnerabilities("log4j")
        assert len(results) > 0
        assert results[0].cve_id == "CVE-2021-44228"

    def test_get_by_cve(self):
        entry = get_by_cve("CVE-2021-44228")
        assert entry is not None
        assert entry.cvss_score == 10.0

    def test_get_by_cve_not_found(self):
        assert get_by_cve("CVE-9999-99999") is None

    def test_get_critical(self):
        critical = get_critical_vulnerabilities()
        assert len(critical) > 0
        assert all(v.severity == "critical" for v in critical)
