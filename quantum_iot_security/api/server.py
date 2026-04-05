"""FastAPI management API for the IoT security platform."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from quantum_iot_security.core.device_fingerprint import DeviceFingerprintEngine
from quantum_iot_security.core.incident_response import IncidentResponder
from quantum_iot_security.firmware.analyzer import FirmwareAnalyzer

app = FastAPI(
    title="Quantum IoT Security API",
    description="Management API for IoT security monitoring and incident response",
    version="1.0.0",
)

# Shared state (in production, these would be backed by a database)
fingerprint_engine = DeviceFingerprintEngine()
incident_responder = IncidentResponder()
firmware_analyzer = FirmwareAnalyzer()


class TrafficInput(BaseModel):
    device_id: str
    ip_address: str
    port: int
    packet_size: int
    timestamp: float
    protocol: str = "unknown"
    mac_address: str = ""


class HealthResponse(BaseModel):
    status: str
    version: str
    devices_tracked: int
    active_incidents: int


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Check API health and system status."""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        devices_tracked=len(fingerprint_engine.known_devices),
        active_incidents=len(incident_responder.get_active_incidents()),
    )


@app.post("/traffic/ingest")
async def ingest_traffic(data: TrafficInput) -> dict[str, str]:
    """Ingest a traffic observation for device fingerprinting."""
    fingerprint_engine.ingest_traffic(
        device_id=data.device_id,
        ip_address=data.ip_address,
        port=data.port,
        packet_size=data.packet_size,
        timestamp=data.timestamp,
        protocol=data.protocol,
        mac_address=data.mac_address,
    )
    return {"status": "accepted", "device_id": data.device_id}


@app.get("/devices")
async def list_devices() -> dict[str, Any]:
    """List all known devices and their fingerprints."""
    devices = fingerprint_engine.known_devices
    return {
        "count": len(devices),
        "devices": {
            dev_id: {
                "device_type": fp.device_type.value,
                "ip_address": fp.ip_address,
                "protocols": [p.value for p in fp.protocols],
                "confidence": fp.confidence,
            }
            for dev_id, fp in devices.items()
        },
    }


@app.post("/devices/{device_id}/fingerprint")
async def build_fingerprint(device_id: str) -> dict[str, Any]:
    """Build a fingerprint for a specific device."""
    fp = fingerprint_engine.build_fingerprint(device_id)
    if fp is None:
        raise HTTPException(status_code=404, detail="No traffic data for device")
    return {
        "device_id": fp.device_id,
        "device_type": fp.device_type.value,
        "protocols": [p.value for p in fp.protocols],
        "open_ports": fp.open_ports,
        "confidence": fp.confidence,
        "fingerprint_hash": fp.fingerprint_hash,
    }


@app.get("/incidents")
async def list_incidents() -> dict[str, Any]:
    """List all security incidents."""
    return incident_responder.get_incident_summary()


@app.post("/incidents/{incident_id}/resolve")
async def resolve_incident(incident_id: str) -> dict[str, Any]:
    """Resolve a security incident."""
    success = incident_responder.resolve_incident(incident_id)
    if not success:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"status": "resolved", "incident_id": incident_id}


@app.get("/firmware")
async def list_firmware_analyses() -> dict[str, Any]:
    """List all firmware analyses."""
    analyses = firmware_analyzer.analyses
    return {
        "count": len(analyses),
        "analyses": {
            fid: {
                "risk_score": info.risk_score,
                "vulnerabilities": info.vulnerabilities,
                "entropy": round(info.entropy, 4),
            }
            for fid, info in analyses.items()
        },
    }
