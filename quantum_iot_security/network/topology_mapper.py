"""Network device discovery and topology mapping for IoT environments."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from quantum_iot_security.core.models import DeviceType, NetworkNode


class TopologyMapper:
    """Builds and maintains a network topology map of IoT devices.

    Discovers devices from traffic observations and maps their connectivity.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, NetworkNode] = {}
        self._edges: set[tuple[str, str]] = set()
        self._traffic_counts: dict[tuple[str, str], int] = defaultdict(int)

    @property
    def nodes(self) -> dict[str, NetworkNode]:
        return dict(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    def add_node(
        self,
        ip_address: str,
        mac_address: str = "",
        device_type: DeviceType = DeviceType.UNKNOWN,
        is_gateway: bool = False,
    ) -> NetworkNode:
        """Add or update a node in the topology."""
        node = self._nodes.get(ip_address)
        if node is None:
            node = NetworkNode(
                node_id=ip_address,
                ip_address=ip_address,
                mac_address=mac_address,
                device_type=device_type,
                is_gateway=is_gateway,
            )
            self._nodes[ip_address] = node
        else:
            if mac_address:
                node.mac_address = mac_address
            if device_type != DeviceType.UNKNOWN:
                node.device_type = device_type
            if is_gateway:
                node.is_gateway = is_gateway
        return node

    def record_communication(
        self,
        src_ip: str,
        dst_ip: str,
        bytes_transferred: int = 0,
    ) -> None:
        """Record a communication event between two nodes."""
        self.add_node(src_ip)
        self.add_node(dst_ip)

        edge = (src_ip, dst_ip)
        self._edges.add(edge)
        self._traffic_counts[edge] += 1

        # Update connectivity
        src_node = self._nodes[src_ip]
        if dst_ip not in src_node.connected_to:
            src_node.connected_to.append(dst_ip)

        # Update traffic volume
        src_node.traffic_volume_bytes += bytes_transferred

    def get_neighbors(self, ip_address: str) -> list[NetworkNode]:
        """Get all nodes directly connected to the given IP."""
        node = self._nodes.get(ip_address)
        if not node:
            return []
        return [
            self._nodes[ip] for ip in node.connected_to if ip in self._nodes
        ]

    def find_gateways(self) -> list[NetworkNode]:
        """Identify gateway nodes (high connectivity or explicitly marked)."""
        gateways = []
        for node in self._nodes.values():
            if node.is_gateway:
                gateways.append(node)
            elif len(node.connected_to) >= 5:
                # Heuristic: nodes with many connections are likely gateways
                node.is_gateway = True
                gateways.append(node)
        return gateways

    def detect_isolated_nodes(self) -> list[NetworkNode]:
        """Find nodes with no connections (potentially suspicious)."""
        return [
            node for node in self._nodes.values()
            if not node.connected_to
        ]

    def get_topology_summary(self) -> dict[str, Any]:
        """Return a summary of the network topology."""
        device_types: dict[str, int] = defaultdict(int)
        for node in self._nodes.values():
            device_types[node.device_type.value] += 1

        return {
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
            "gateways": len(self.find_gateways()),
            "isolated_nodes": len(self.detect_isolated_nodes()),
            "device_types": dict(device_types),
            "avg_connections": (
                sum(len(n.connected_to) for n in self._nodes.values()) / len(self._nodes)
                if self._nodes else 0.0
            ),
        }

    def export_adjacency_list(self) -> dict[str, list[str]]:
        """Export the topology as an adjacency list."""
        return {
            ip: list(node.connected_to) for ip, node in self._nodes.items()
        }
