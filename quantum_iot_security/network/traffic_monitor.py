"""Network traffic monitoring and protocol-level analysis.

Captures and analyzes IoT network traffic patterns without requiring raw sockets.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from quantum_iot_security.core.models import ProtocolType


@dataclass
class TrafficFlow:
    """Represents a network traffic flow between two endpoints."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: ProtocolType
    packets: list[dict[str, Any]] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    total_bytes: int = 0

    @property
    def flow_id(self) -> str:
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}"

    @property
    def duration(self) -> float:
        return self.last_seen - self.start_time

    @property
    def packet_count(self) -> int:
        return len(self.packets)


@dataclass
class TrafficStats:
    """Aggregate statistics for monitored traffic."""

    total_flows: int = 0
    total_packets: int = 0
    total_bytes: int = 0
    unique_sources: int = 0
    unique_destinations: int = 0
    protocol_distribution: dict[str, int] = field(default_factory=dict)
    avg_packet_size: float = 0.0
    top_talkers: list[tuple[str, int]] = field(default_factory=list)


class TrafficMonitor:
    """Monitors and analyzes IoT network traffic patterns.

    Ingests packet-level data and produces flow records, statistics,
    and anomaly-relevant features for downstream analysis.
    """

    def __init__(self, flow_timeout_sec: float = 300.0) -> None:
        self._flows: dict[str, TrafficFlow] = {}
        self._flow_timeout = flow_timeout_sec
        self._packet_log: list[dict[str, Any]] = []
        self._ip_bytes: dict[str, int] = defaultdict(int)

    @property
    def active_flows(self) -> dict[str, TrafficFlow]:
        return dict(self._flows)

    def ingest_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        size: int,
        timestamp: float | None = None,
        payload: bytes = b"",
    ) -> TrafficFlow:
        """Ingest a single packet observation."""
        ts = timestamp or time.time()
        proto = ProtocolType(protocol) if protocol in ProtocolType.__members__.values() else ProtocolType.UNKNOWN

        flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        flow = self._flows.get(flow_key)

        if flow is None:
            flow = TrafficFlow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                start_time=ts,
            )
            self._flows[flow_key] = flow

        packet_info = {
            "size": size,
            "timestamp": ts,
            "payload_size": len(payload),
        }
        flow.packets.append(packet_info)
        flow.last_seen = ts
        flow.total_bytes += size

        self._packet_log.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto.value,
            "size": size,
            "timestamp": ts,
        })
        self._ip_bytes[src_ip] += size

        return flow

    def get_statistics(self) -> TrafficStats:
        """Compute aggregate traffic statistics."""
        all_packets = []
        sources = set()
        destinations = set()
        proto_dist: dict[str, int] = defaultdict(int)

        for flow in self._flows.values():
            all_packets.extend(flow.packets)
            sources.add(flow.src_ip)
            destinations.add(flow.dst_ip)
            proto_dist[flow.protocol.value] += flow.packet_count

        total_bytes = sum(p["size"] for p in all_packets) if all_packets else 0
        avg_size = np.mean([p["size"] for p in all_packets]) if all_packets else 0.0

        # Top talkers by bytes
        sorted_ips = sorted(self._ip_bytes.items(), key=lambda x: x[1], reverse=True)

        return TrafficStats(
            total_flows=len(self._flows),
            total_packets=len(all_packets),
            total_bytes=total_bytes,
            unique_sources=len(sources),
            unique_destinations=len(destinations),
            protocol_distribution=dict(proto_dist),
            avg_packet_size=float(avg_size),
            top_talkers=sorted_ips[:10],
        )

    def extract_features_for_device(self, device_ip: str) -> list[dict[str, Any]]:
        """Extract anomaly detection features for a specific device IP."""
        device_flows = [
            f for f in self._flows.values() if f.src_ip == device_ip
        ]
        features = []
        for flow in device_flows:
            for pkt in flow.packets:
                features.append({
                    "packet_size": pkt["size"],
                    "interval_ms": 0.0,  # Will be filled below
                    "port": flow.dst_port,
                    "protocol_id": hash(flow.protocol.value) % 100,
                    "payload_entropy": 0.0,
                })

        # Compute inter-packet intervals
        if len(features) > 1:
            timestamps = [p["timestamp"] for f in device_flows for p in f.packets]
            timestamps.sort()
            for i in range(1, len(features)):
                if i < len(timestamps):
                    features[i]["interval_ms"] = (timestamps[i] - timestamps[i - 1]) * 1000

        return features

    def cleanup_expired_flows(self) -> int:
        """Remove flows that have been idle beyond the timeout."""
        now = time.time()
        expired = [
            key for key, flow in self._flows.items()
            if (now - flow.last_seen) > self._flow_timeout
        ]
        for key in expired:
            del self._flows[key]
        return len(expired)
