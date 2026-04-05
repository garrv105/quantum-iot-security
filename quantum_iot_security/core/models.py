"""Pydantic data models for IoT security platform."""

from __future__ import annotations

import hashlib
import time
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class DeviceType(str, Enum):
    SENSOR = "sensor"
    CAMERA = "camera"
    GATEWAY = "gateway"
    ACTUATOR = "actuator"
    CONTROLLER = "controller"
    UNKNOWN = "unknown"


class ThreatLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ProtocolType(str, Enum):
    MQTT = "mqtt"
    COAP = "coap"
    HTTP = "http"
    HTTPS = "https"
    MODBUS = "modbus"
    ZIGBEE = "zigbee"
    BLUETOOTH = "bluetooth"
    UNKNOWN = "unknown"


class IncidentAction(str, Enum):
    QUARANTINE = "quarantine"
    ALERT = "alert"
    LOG = "log"
    BLOCK = "block"
    INVESTIGATE = "investigate"


class DeviceFingerprint(BaseModel):
    """Represents a unique IoT device fingerprint based on behavioral analysis."""

    device_id: str
    ip_address: str
    mac_address: str = ""
    device_type: DeviceType = DeviceType.UNKNOWN
    protocols: list[ProtocolType] = Field(default_factory=list)
    open_ports: list[int] = Field(default_factory=list)
    avg_packet_size: float = 0.0
    avg_interval_ms: float = 0.0
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    first_seen: float = Field(default_factory=time.time)
    last_seen: float = Field(default_factory=time.time)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def fingerprint_hash(self) -> str:
        """Generate a deterministic hash of the device fingerprint."""
        data = f"{self.mac_address}:{','.join(str(p) for p in sorted(self.open_ports))}:{self.device_type}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]


class AnomalyEvent(BaseModel):
    """An anomaly detected in IoT network traffic."""

    event_id: str
    device_id: str
    timestamp: float = Field(default_factory=time.time)
    anomaly_score: float = Field(ge=-1.0)
    threat_level: ThreatLevel = ThreatLevel.LOW
    description: str = ""
    features: dict[str, float] = Field(default_factory=dict)
    is_anomaly: bool = False


class Incident(BaseModel):
    """A security incident requiring response."""

    incident_id: str
    device_id: str
    timestamp: float = Field(default_factory=time.time)
    threat_level: ThreatLevel = ThreatLevel.MEDIUM
    description: str = ""
    anomaly_events: list[AnomalyEvent] = Field(default_factory=list)
    actions_taken: list[IncidentAction] = Field(default_factory=list)
    resolved: bool = False
    evidence: dict[str, Any] = Field(default_factory=dict)


class FirmwareInfo(BaseModel):
    """Metadata and analysis results for a firmware image."""

    firmware_id: str
    device_type: DeviceType = DeviceType.UNKNOWN
    version: str = ""
    file_size: int = 0
    sha256: str = ""
    entropy: float = 0.0
    suspicious_strings: list[str] = Field(default_factory=list)
    vulnerabilities: list[str] = Field(default_factory=list)
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)


class NetworkNode(BaseModel):
    """A node in the network topology."""

    node_id: str
    ip_address: str
    mac_address: str = ""
    device_type: DeviceType = DeviceType.UNKNOWN
    is_gateway: bool = False
    connected_to: list[str] = Field(default_factory=list)
    traffic_volume_bytes: int = 0


class ComplianceResult(BaseModel):
    """Result of a compliance check against a security framework."""

    framework: str
    category: str
    requirement_id: str
    description: str
    status: str = "not_assessed"
    findings: list[str] = Field(default_factory=list)
