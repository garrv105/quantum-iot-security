"""Tests for IoT device fingerprinting."""

from __future__ import annotations

import time

from quantum_iot_security.core.device_fingerprint import DeviceFingerprintEngine
from quantum_iot_security.core.models import DeviceFingerprint, DeviceType, ProtocolType


class TestDeviceFingerprintEngine:
    def test_ingest_and_build_fingerprint(self, fingerprint_engine: DeviceFingerprintEngine):
        """Ingested traffic should produce a valid fingerprint."""
        base_time = time.time()
        for i in range(10):
            fingerprint_engine.ingest_traffic(
                device_id="sensor-001",
                ip_address="192.168.1.10",
                port=1883,
                packet_size=128,
                timestamp=base_time + i,
                mac_address="AA:BB:CC:DD:EE:01",
            )

        fp = fingerprint_engine.build_fingerprint("sensor-001")
        assert fp is not None
        assert fp.device_id == "sensor-001"
        assert fp.ip_address == "192.168.1.10"
        assert 1883 in fp.open_ports
        assert fp.confidence > 0.0

    def test_identify_mqtt_protocol(self, fingerprint_engine: DeviceFingerprintEngine):
        """MQTT ports should map to MQTT protocol."""
        protocols = fingerprint_engine.identify_protocols([1883, 8883])
        assert ProtocolType.MQTT in protocols

    def test_identify_http_protocol(self, fingerprint_engine: DeviceFingerprintEngine):
        """HTTP ports should map to HTTP protocol."""
        protocols = fingerprint_engine.identify_protocols([80, 8080])
        assert ProtocolType.HTTP in protocols

    def test_unknown_protocol_fallback(self, fingerprint_engine: DeviceFingerprintEngine):
        """Unknown ports should return UNKNOWN protocol."""
        protocols = fingerprint_engine.identify_protocols([12345])
        assert ProtocolType.UNKNOWN in protocols

    def test_classify_sensor(self, fingerprint_engine: DeviceFingerprintEngine):
        """A device with MQTT on few ports and small packets should classify as sensor."""
        fp = DeviceFingerprint(
            device_id="test",
            ip_address="10.0.0.1",
            protocols=[ProtocolType.MQTT],
            open_ports=[1883],
            avg_packet_size=200.0,
        )
        result = fingerprint_engine.classify_device(fp)
        assert result == DeviceType.SENSOR

    def test_classify_camera(self, fingerprint_engine: DeviceFingerprintEngine):
        """A device with HTTP and large packets should classify as camera."""
        fp = DeviceFingerprint(
            device_id="cam",
            ip_address="10.0.0.2",
            protocols=[ProtocolType.HTTP, ProtocolType.HTTPS],
            open_ports=[80, 443, 554],
            avg_packet_size=2000.0,
        )
        result = fingerprint_engine.classify_device(fp)
        assert result == DeviceType.CAMERA

    def test_compute_similarity_identical(self, fingerprint_engine: DeviceFingerprintEngine):
        """Identical fingerprints should have similarity = 1.0."""
        fp = DeviceFingerprint(
            device_id="a",
            ip_address="10.0.0.1",
            protocols=[ProtocolType.MQTT],
            open_ports=[1883],
            avg_packet_size=256.0,
            avg_interval_ms=1000.0,
        )
        sim = fingerprint_engine.compute_similarity(fp, fp)
        assert abs(sim - 1.0) < 0.01

    def test_no_traffic_returns_none(self, fingerprint_engine: DeviceFingerprintEngine):
        """Building fingerprint with no data should return None."""
        assert fingerprint_engine.build_fingerprint("nonexistent") is None

    def test_fingerprint_hash_deterministic(self, sample_fingerprint: DeviceFingerprint):
        """Fingerprint hash should be deterministic."""
        h1 = sample_fingerprint.fingerprint_hash
        h2 = sample_fingerprint.fingerprint_hash
        assert h1 == h2
        assert len(h1) == 16
