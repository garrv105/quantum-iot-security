"""Tests for network traffic monitoring and topology mapping."""

from __future__ import annotations

import time

from quantum_iot_security.core.models import DeviceType
from quantum_iot_security.network.topology_mapper import TopologyMapper
from quantum_iot_security.network.traffic_monitor import TrafficMonitor


class TestTrafficMonitor:
    def test_ingest_creates_flow(self, traffic_monitor: TrafficMonitor):
        """Ingesting a packet should create a flow record."""
        flow = traffic_monitor.ingest_packet(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=12345,
            dst_port=1883,
            protocol="mqtt",
            size=256,
        )
        assert flow.src_ip == "10.0.0.1"
        assert flow.packet_count == 1
        assert flow.total_bytes == 256

    def test_multiple_packets_same_flow(self, traffic_monitor: TrafficMonitor):
        """Multiple packets on the same flow should aggregate."""
        for _ in range(5):
            traffic_monitor.ingest_packet(
                src_ip="10.0.0.1", dst_ip="10.0.0.2",
                src_port=12345, dst_port=80,
                protocol="http", size=100,
            )
        flows = traffic_monitor.active_flows
        assert len(flows) == 1
        flow = list(flows.values())[0]
        assert flow.packet_count == 5
        assert flow.total_bytes == 500

    def test_statistics(self, traffic_monitor: TrafficMonitor):
        """Statistics should reflect ingested traffic."""
        for i in range(10):
            traffic_monitor.ingest_packet(
                src_ip=f"10.0.0.{i % 3}",
                dst_ip="10.0.0.100",
                src_port=10000 + i,
                dst_port=1883,
                protocol="mqtt",
                size=128,
            )
        stats = traffic_monitor.get_statistics()
        assert stats.total_packets == 10
        assert stats.total_bytes == 1280
        assert stats.unique_destinations == 1

    def test_extract_features(self, traffic_monitor: TrafficMonitor):
        """Feature extraction for a device should return feature dicts."""
        base_time = time.time()
        for i in range(5):
            traffic_monitor.ingest_packet(
                src_ip="10.0.0.1", dst_ip="10.0.0.2",
                src_port=12345, dst_port=80,
                protocol="http", size=100 + i * 10,
                timestamp=base_time + i,
            )
        features = traffic_monitor.extract_features_for_device("10.0.0.1")
        assert len(features) == 5
        assert "packet_size" in features[0]


class TestTopologyMapper:
    def test_add_node(self, topology_mapper: TopologyMapper):
        """Adding a node should register it."""
        node = topology_mapper.add_node("10.0.0.1", device_type=DeviceType.SENSOR)
        assert node.ip_address == "10.0.0.1"
        assert len(topology_mapper.nodes) == 1

    def test_record_communication(self, topology_mapper: TopologyMapper):
        """Recording communication should create edges."""
        topology_mapper.record_communication("10.0.0.1", "10.0.0.2", 1024)
        assert topology_mapper.edge_count == 1
        neighbors = topology_mapper.get_neighbors("10.0.0.1")
        assert len(neighbors) == 1
        assert neighbors[0].ip_address == "10.0.0.2"

    def test_find_gateways(self, topology_mapper: TopologyMapper):
        """Nodes with many connections should be identified as gateways."""
        gateway_ip = "10.0.0.1"
        for i in range(10):
            topology_mapper.record_communication(gateway_ip, f"10.0.0.{100 + i}")
        gateways = topology_mapper.find_gateways()
        assert len(gateways) >= 1
        assert any(g.ip_address == gateway_ip for g in gateways)

    def test_isolated_nodes(self, topology_mapper: TopologyMapper):
        """Nodes with no connections should be detected as isolated."""
        topology_mapper.add_node("10.0.0.99")
        isolated = topology_mapper.detect_isolated_nodes()
        assert len(isolated) == 1
        assert isolated[0].ip_address == "10.0.0.99"

    def test_topology_summary(self, topology_mapper: TopologyMapper):
        """Summary should include node and edge counts."""
        topology_mapper.record_communication("10.0.0.1", "10.0.0.2")
        topology_mapper.record_communication("10.0.0.1", "10.0.0.3")
        summary = topology_mapper.get_topology_summary()
        assert summary["total_nodes"] == 3
        assert summary["total_edges"] == 2
