"""IoT device identification via protocol, port, and timing analysis."""

from __future__ import annotations

import hashlib
import statistics
from collections import defaultdict
from typing import Any

import numpy as np

from quantum_iot_security.core.models import (
    DeviceFingerprint,
    DeviceType,
    ProtocolType,
)

# Known protocol-to-port mappings for IoT
_PROTOCOL_PORTS: dict[ProtocolType, set[int]] = {
    ProtocolType.MQTT: {1883, 8883},
    ProtocolType.COAP: {5683, 5684},
    ProtocolType.HTTP: {80, 8080},
    ProtocolType.HTTPS: {443, 8443},
    ProtocolType.MODBUS: {502},
}

# Heuristic: device type classification based on protocol and port patterns
_DEVICE_SIGNATURES: dict[DeviceType, dict[str, Any]] = {
    DeviceType.SENSOR: {
        "protocols": {ProtocolType.MQTT, ProtocolType.COAP},
        "max_ports": 3,
        "max_packet_size": 512,
    },
    DeviceType.CAMERA: {
        "protocols": {ProtocolType.HTTP, ProtocolType.HTTPS},
        "min_packet_size": 1000,
        "min_ports": 2,
    },
    DeviceType.GATEWAY: {
        "protocols": {ProtocolType.MQTT, ProtocolType.HTTP, ProtocolType.HTTPS},
        "min_ports": 4,
    },
    DeviceType.ACTUATOR: {
        "protocols": {ProtocolType.MODBUS, ProtocolType.COAP},
        "max_ports": 2,
    },
    DeviceType.CONTROLLER: {
        "protocols": {ProtocolType.MODBUS, ProtocolType.HTTP},
        "min_ports": 3,
    },
}


class DeviceFingerprintEngine:
    """Identifies and classifies IoT devices based on network behavior."""

    def __init__(self) -> None:
        self._known_devices: dict[str, DeviceFingerprint] = {}
        self._traffic_history: dict[str, list[dict[str, Any]]] = defaultdict(list)

    @property
    def known_devices(self) -> dict[str, DeviceFingerprint]:
        return dict(self._known_devices)

    def ingest_traffic(
        self,
        device_id: str,
        ip_address: str,
        port: int,
        packet_size: int,
        timestamp: float,
        protocol: str = "unknown",
        mac_address: str = "",
    ) -> None:
        """Ingest a single traffic observation for a device."""
        self._traffic_history[device_id].append(
            {
                "ip": ip_address,
                "port": port,
                "packet_size": packet_size,
                "timestamp": timestamp,
                "protocol": protocol,
                "mac": mac_address,
            }
        )

    def identify_protocols(self, ports: list[int]) -> list[ProtocolType]:
        """Map open ports to known IoT protocols."""
        protocols: list[ProtocolType] = []
        for proto, known_ports in _PROTOCOL_PORTS.items():
            if known_ports & set(ports):
                protocols.append(proto)
        if not protocols:
            protocols.append(ProtocolType.UNKNOWN)
        return protocols

    def classify_device(self, fingerprint: DeviceFingerprint) -> DeviceType:
        """Classify a device type based on its fingerprint characteristics."""
        best_match = DeviceType.UNKNOWN
        best_score = 0.0

        for device_type, sig in _DEVICE_SIGNATURES.items():
            score = 0.0
            total_checks = 0

            # Check protocol overlap
            expected_protos = sig.get("protocols", set())
            if expected_protos:
                total_checks += 1
                overlap = expected_protos & set(fingerprint.protocols)
                if overlap:
                    score += len(overlap) / len(expected_protos)

            # Check port count constraints
            num_ports = len(fingerprint.open_ports)
            if "max_ports" in sig:
                total_checks += 1
                if num_ports <= sig["max_ports"]:
                    score += 1.0
            if "min_ports" in sig:
                total_checks += 1
                if num_ports >= sig["min_ports"]:
                    score += 1.0

            # Check packet size constraints
            if "max_packet_size" in sig:
                total_checks += 1
                if fingerprint.avg_packet_size <= sig["max_packet_size"]:
                    score += 1.0
            if "min_packet_size" in sig:
                total_checks += 1
                if fingerprint.avg_packet_size >= sig["min_packet_size"]:
                    score += 1.0

            normalized = score / total_checks if total_checks > 0 else 0.0
            if normalized > best_score:
                best_score = normalized
                best_match = device_type

        return best_match

    def build_fingerprint(self, device_id: str) -> DeviceFingerprint | None:
        """Build a device fingerprint from accumulated traffic observations."""
        history = self._traffic_history.get(device_id)
        if not history:
            return None

        ip_address = history[-1]["ip"]
        mac_address = history[-1].get("mac", "")
        ports = sorted({obs["port"] for obs in history})
        packet_sizes = [obs["packet_size"] for obs in history]
        timestamps = sorted(obs["timestamp"] for obs in history)

        avg_packet_size = statistics.mean(packet_sizes)
        avg_interval = 0.0
        if len(timestamps) > 1:
            intervals = [
                (timestamps[i + 1] - timestamps[i]) * 1000
                for i in range(len(timestamps) - 1)
            ]
            avg_interval = statistics.mean(intervals)

        protocols = self.identify_protocols(ports)

        fingerprint = DeviceFingerprint(
            device_id=device_id,
            ip_address=ip_address,
            mac_address=mac_address,
            open_ports=ports,
            protocols=protocols,
            avg_packet_size=avg_packet_size,
            avg_interval_ms=avg_interval,
        )

        fingerprint.device_type = self.classify_device(fingerprint)
        fingerprint.confidence = self._compute_confidence(fingerprint, len(history))
        self._known_devices[device_id] = fingerprint
        return fingerprint

    def compute_similarity(self, fp1: DeviceFingerprint, fp2: DeviceFingerprint) -> float:
        """Compute similarity score between two device fingerprints using cosine similarity."""
        vec1 = self._fingerprint_to_vector(fp1)
        vec2 = self._fingerprint_to_vector(fp2)

        dot = np.dot(vec1, vec2)
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)
        if norm1 == 0 or norm2 == 0:
            return 0.0
        return float(dot / (norm1 * norm2))

    def _fingerprint_to_vector(self, fp: DeviceFingerprint) -> np.ndarray:
        """Convert a fingerprint to a numeric feature vector."""
        port_hash = int(hashlib.md5(
            ",".join(str(p) for p in fp.open_ports).encode()
        ).hexdigest()[:8], 16)
        proto_hash = int(hashlib.md5(
            ",".join(p.value for p in fp.protocols).encode()
        ).hexdigest()[:8], 16)
        return np.array([
            fp.avg_packet_size,
            fp.avg_interval_ms,
            len(fp.open_ports),
            len(fp.protocols),
            port_hash % 10000,
            proto_hash % 10000,
        ], dtype=np.float64)

    def _compute_confidence(self, fp: DeviceFingerprint, num_observations: int) -> float:
        """Compute confidence score for a fingerprint based on data quality."""
        score = 0.0
        if num_observations >= 10:
            score += 0.3
        elif num_observations >= 5:
            score += 0.2
        elif num_observations >= 1:
            score += 0.1

        if fp.device_type != DeviceType.UNKNOWN:
            score += 0.3

        if fp.protocols and fp.protocols[0] != ProtocolType.UNKNOWN:
            score += 0.2

        if fp.mac_address:
            score += 0.1

        if fp.avg_interval_ms > 0:
            score += 0.1

        return min(score, 1.0)
