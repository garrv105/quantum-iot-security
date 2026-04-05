# Quantum IoT Security

[![CI](https://github.com/garrv105/quantum-iot-security/actions/workflows/ci.yml/badge.svg)](https://github.com/garrv105/quantum-iot-security/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Quantum-Enhanced Incident Response for IoT Security** — A production-grade platform combining post-quantum cryptography with real-time IoT threat detection and automated incident response.

## Features

### IoT Device Fingerprinting
- Behavioral identification of IoT devices via protocol, port, and timing analysis
- Automatic device classification (sensor, camera, gateway, actuator, controller)
- Cosine similarity-based device comparison

### Anomaly Detection
- Lightweight Isolation Forest and Local Outlier Factor models
- Designed for resource-constrained IoT environments
- Real-time scoring with threat level classification

### Post-Quantum Cryptography
- Lattice-based (Kyber-like) key exchange resistant to quantum attacks
- AES-256-GCM secure channels with PQC-derived key material
- X.509 certificate management for IoT device identity

### Incident Response Automation
- Threat-level-based automated response policies
- Device quarantine, alerting, and traffic blocking
- Forensic evidence collection and persistence

### Firmware Analysis
- Static analysis: entropy computation, string extraction, CVE matching
- Known vulnerability database with CVSS scoring
- Firmware version comparison for security regression detection

### Compliance & Reporting
- NIST IoT Cybersecurity framework mapping
- IEC 62443 industrial IoT compliance checks
- JSON report generation for incidents, device inventory, and firmware audits

## Installation

```bash
# Clone the repository
git clone https://github.com/garrv105/quantum-iot-security.git
cd quantum-iot-security

# Install with pip
pip install -e ".[dev]"
```

## Quick Start

### CLI

```bash
# Show platform status
qiot status

# Analyze firmware for vulnerabilities
qiot analyze-firmware path/to/firmware.bin

# Test post-quantum key exchange
qiot pqc-test --dimension 256

# Run full demo
qiot demo
```

### API Server

```bash
uvicorn quantum_iot_security.api.server:app --reload
# Visit http://localhost:8000/docs for interactive API docs
```

### Docker

```bash
docker build -f docker/Dockerfile -t quantum-iot-security .
docker run -p 8000:8000 quantum-iot-security
```

## Architecture

```
quantum_iot_security/
├── core/                  # Device fingerprinting, anomaly detection, incident response
├── crypto/                # Post-quantum key exchange, AES-GCM channels, certificates
├── firmware/              # Static firmware analysis and vulnerability database
├── network/               # Traffic monitoring and topology mapping
├── reporting/             # Report generation and compliance frameworks
├── api/                   # FastAPI management interface
└── cli.py                 # Click CLI entry point
```

## Testing

```bash
# Run all tests with coverage
pytest tests/ -v --cov=quantum_iot_security

# Run specific test module
pytest tests/test_pqc_crypto.py -v
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | System health and status |
| POST | `/traffic/ingest` | Ingest traffic observation |
| GET | `/devices` | List known devices |
| POST | `/devices/{id}/fingerprint` | Build device fingerprint |
| GET | `/incidents` | List security incidents |
| POST | `/incidents/{id}/resolve` | Resolve an incident |
| GET | `/firmware` | List firmware analyses |

## Dependencies

- **numpy** + **scikit-learn** — Anomaly detection models
- **cryptography** — AES-GCM encryption, X.509 certificates
- **pydantic** — Data validation and serialization
- **click** — CLI framework
- **fastapi** + **uvicorn** — REST API

## License

MIT License — see [LICENSE](LICENSE) for details.
