"""Shared test fixtures for the quantum IoT security test suite."""

from __future__ import annotations

import numpy as np
import pytest

from quantum_iot_security.core.anomaly_detector import AnomalyDetector
from quantum_iot_security.core.device_fingerprint import DeviceFingerprintEngine
from quantum_iot_security.core.incident_response import IncidentResponder
from quantum_iot_security.core.models import (
    AnomalyEvent,
    DeviceFingerprint,
    ProtocolType,
    ThreatLevel,
)
from quantum_iot_security.crypto.certificate_manager import CertificateManager
from quantum_iot_security.firmware.analyzer import FirmwareAnalyzer
from quantum_iot_security.network.topology_mapper import TopologyMapper
from quantum_iot_security.network.traffic_monitor import TrafficMonitor


@pytest.fixture
def fingerprint_engine() -> DeviceFingerprintEngine:
    return DeviceFingerprintEngine()


@pytest.fixture
def anomaly_detector() -> AnomalyDetector:
    return AnomalyDetector(contamination=0.1)


@pytest.fixture
def fitted_detector() -> AnomalyDetector:
    """A detector pre-fitted with normal traffic data."""
    detector = AnomalyDetector(contamination=0.1)
    rng = np.random.RandomState(42)
    normal_data = rng.normal(loc=[100, 50, 80, 1, 3.0], scale=[10, 5, 10, 0.5, 0.5], size=(100, 5))
    detector.fit(normal_data)
    return detector


@pytest.fixture
def incident_responder(tmp_path) -> IncidentResponder:
    return IncidentResponder(evidence_dir=tmp_path / "evidence")


@pytest.fixture
def certificate_manager() -> CertificateManager:
    return CertificateManager()


@pytest.fixture
def firmware_analyzer() -> FirmwareAnalyzer:
    return FirmwareAnalyzer()


@pytest.fixture
def traffic_monitor() -> TrafficMonitor:
    return TrafficMonitor()


@pytest.fixture
def topology_mapper() -> TopologyMapper:
    return TopologyMapper()


@pytest.fixture
def sample_fingerprint() -> DeviceFingerprint:
    return DeviceFingerprint(
        device_id="test-device-001",
        ip_address="192.168.1.100",
        mac_address="AA:BB:CC:DD:EE:01",
        open_ports=[1883, 8883],
        protocols=[ProtocolType.MQTT],
        avg_packet_size=256.0,
        avg_interval_ms=1000.0,
    )


@pytest.fixture
def sample_anomaly_events() -> list[AnomalyEvent]:
    return [
        AnomalyEvent(
            event_id="evt-001",
            device_id="device-001",
            anomaly_score=-0.6,
            threat_level=ThreatLevel.CRITICAL,
            is_anomaly=True,
            description="Unusual traffic burst",
        ),
        AnomalyEvent(
            event_id="evt-002",
            device_id="device-001",
            anomaly_score=-0.2,
            threat_level=ThreatLevel.MEDIUM,
            is_anomaly=True,
            description="Unexpected protocol",
        ),
    ]


@pytest.fixture
def sample_firmware_data() -> bytes:
    """Firmware binary with known vulnerability patterns embedded."""
    return (
        b"IoT Firmware v3.1\x00"
        b"password=factory_default\x00"
        b"telnetd --port 23\x00"
        b"debug_mode=true\x00"
        b"log4j-core-2.14.1.jar\x00"
        + bytes(range(256)) * 10
    )
