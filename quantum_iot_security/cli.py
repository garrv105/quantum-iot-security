"""Click CLI entry point for the quantum IoT security platform."""

from __future__ import annotations

import json
import time

import click
import numpy as np

from quantum_iot_security import __version__
from quantum_iot_security.core.anomaly_detector import AnomalyDetector
from quantum_iot_security.core.device_fingerprint import DeviceFingerprintEngine
from quantum_iot_security.crypto.pqc_handshake import PQCHandshake
from quantum_iot_security.firmware.analyzer import FirmwareAnalyzer


@click.group()
@click.version_option(version=__version__)
def cli() -> None:
    """Quantum IoT Security — post-quantum IoT protection platform."""


@cli.command()
def status() -> None:
    """Show platform status."""
    click.echo(f"Quantum IoT Security v{__version__}")
    click.echo("Status: Operational")
    click.echo("Modules: fingerprint, anomaly, incident_response, pqc_crypto, firmware")


@cli.command()
@click.argument("firmware_path", type=click.Path(exists=True))
@click.option("--version", "fw_version", default="", help="Firmware version string")
def analyze_firmware(firmware_path: str, fw_version: str) -> None:
    """Analyze a firmware image for vulnerabilities."""
    with open(firmware_path, "rb") as f:
        data = f.read()

    analyzer = FirmwareAnalyzer()
    result = analyzer.analyze(data, version=fw_version)

    click.echo(f"Firmware Analysis: {firmware_path}")
    click.echo(f"  SHA256:       {result.sha256}")
    click.echo(f"  Size:         {result.file_size} bytes")
    click.echo(f"  Entropy:      {result.entropy:.4f}")
    click.echo(f"  Risk Score:   {result.risk_score:.1f}/10.0")
    click.echo(f"  Suspicious:   {len(result.suspicious_strings)} patterns")
    click.echo(f"  CVEs matched: {len(result.vulnerabilities)}")

    if result.vulnerabilities:
        click.echo("  Vulnerabilities:")
        for cve in result.vulnerabilities:
            click.echo(f"    - {cve}")


@cli.command()
@click.option("--dimension", "-n", default=256, help="Lattice dimension")
def pqc_test(dimension: int) -> None:
    """Test post-quantum key exchange."""
    from quantum_iot_security.crypto.pqc_handshake import LatticeParameters

    params = LatticeParameters(n=dimension)
    handshake = PQCHandshake(params)
    server_key, client_key = handshake.perform_handshake()

    click.echo("Post-Quantum Key Exchange Test")
    click.echo(f"  Lattice dimension: {dimension}")
    click.echo(f"  Server key: {server_key.hex()[:32]}...")
    click.echo(f"  Client key: {client_key.hex()[:32]}...")
    click.echo(f"  Keys match: {server_key == client_key}")


@cli.command()
@click.option("--output", "-o", type=click.Path(), help="Output JSON path")
def demo(output: str | None) -> None:
    """Run a demonstration of all platform capabilities."""
    click.echo("=== Quantum IoT Security Demo ===\n")

    # Device fingerprinting
    click.echo("1. Device Fingerprinting")
    engine = DeviceFingerprintEngine()
    for i in range(20):
        engine.ingest_traffic(
            device_id="sensor-001",
            ip_address="192.168.1.100",
            port=1883,
            packet_size=128 + (i * 10),
            timestamp=time.time() + i,
            mac_address="AA:BB:CC:DD:EE:01",
        )
    fp = engine.build_fingerprint("sensor-001")
    if fp:
        click.echo(f"   Device type: {fp.device_type.value}")
        click.echo(f"   Confidence:  {fp.confidence:.2f}")

    # Anomaly detection
    click.echo("\n2. Anomaly Detection")
    detector = AnomalyDetector()
    normal = np.random.RandomState(42).normal(100, 10, (50, 5))
    detector.fit(normal)
    test = np.array([[100, 10, 80, 1, 3.0], [999, 0.1, 9999, 99, 7.9]])
    labels = detector.predict(test)
    click.echo(f"   Normal traffic:  label={labels[0]}")
    click.echo(f"   Anomaly traffic: label={labels[1]}")

    # PQC key exchange
    click.echo("\n3. Post-Quantum Key Exchange")
    handshake = PQCHandshake()
    s_key, c_key = handshake.perform_handshake()
    click.echo(f"   Key exchange complete, key size: {len(s_key) * 8} bits")

    # Firmware analysis
    click.echo("\n4. Firmware Analysis")
    fake_fw = b"IoT firmware v2.1\x00" + b"password=admin123\x00" + b"telnetd\x00" + bytes(1000)
    analyzer = FirmwareAnalyzer()
    fw_result = analyzer.analyze(fake_fw, version="2.1")
    click.echo(f"   Risk score: {fw_result.risk_score:.1f}/10.0")
    click.echo(f"   CVEs found: {len(fw_result.vulnerabilities)}")

    click.echo("\n=== Demo Complete ===")

    if output:
        report = {
            "demo_results": {
                "fingerprint": fp.model_dump() if fp else None,
                "anomaly_labels": labels.tolist(),
                "pqc_key_size_bits": len(s_key) * 8,
                "firmware_risk": fw_result.risk_score,
            }
        }
        with open(output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        click.echo(f"\nResults saved to {output}")
