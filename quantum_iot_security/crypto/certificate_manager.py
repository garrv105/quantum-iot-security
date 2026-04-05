"""X.509-like certificate management for IoT devices.

Handles certificate generation, validation, and revocation for device identity.
"""

from __future__ import annotations

import datetime
import ipaddress
from dataclasses import dataclass, field
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


@dataclass
class DeviceCertificate:
    """Wrapper around an X.509 certificate for an IoT device."""

    device_id: str
    certificate: x509.Certificate
    private_key: ec.EllipticCurvePrivateKey
    issued_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    expires_at: datetime.datetime | None = None

    @property
    def serial_number(self) -> int:
        return self.certificate.serial_number

    @property
    def subject_cn(self) -> str:
        attrs = self.certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else ""

    @property
    def is_expired(self) -> bool:
        now = datetime.datetime.utcnow()
        return now > self.certificate.not_valid_after_utc

    def to_pem(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.PEM)

    def private_key_pem(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )


class CertificateManager:
    """Manages X.509 certificates for IoT device identity and authentication."""

    def __init__(self, ca_name: str = "QuantumIoT CA") -> None:
        self._ca_name = ca_name
        self._ca_key = ec.generate_private_key(ec.SECP256R1())
        self._ca_cert = self._create_ca_cert()
        self._issued: dict[str, DeviceCertificate] = {}
        self._revoked: set[int] = set()

    def _create_ca_cert(self) -> x509.Certificate:
        """Create a self-signed CA certificate."""
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self._ca_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "QuantumIoT Security"),
        ])
        now = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self._ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .sign(self._ca_key, hashes.SHA256())
        )
        return cert

    @property
    def ca_certificate(self) -> x509.Certificate:
        return self._ca_cert

    def issue_device_certificate(
        self,
        device_id: str,
        ip_address: str | None = None,
        validity_days: int = 365,
    ) -> DeviceCertificate:
        """Issue a new certificate for an IoT device."""
        device_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.utcnow()
        expires = now + datetime.timedelta(days=validity_days)

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"iot-device-{device_id}"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "QuantumIoT Security"),
        ])

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(device_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(expires)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
        )

        if ip_address:
            san = x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.ip_address(ip_address)),
            ])
            builder = builder.add_extension(san, critical=False)

        cert = builder.sign(self._ca_key, hashes.SHA256())

        device_cert = DeviceCertificate(
            device_id=device_id,
            certificate=cert,
            private_key=device_key,
            issued_at=now,
            expires_at=expires,
        )
        self._issued[device_id] = device_cert
        return device_cert

    def verify_certificate(self, device_cert: DeviceCertificate) -> dict[str, Any]:
        """Verify a device certificate against the CA."""
        result: dict[str, Any] = {
            "valid": True,
            "device_id": device_cert.device_id,
            "errors": [],
        }

        # Check expiration
        if device_cert.is_expired:
            result["valid"] = False
            result["errors"].append("Certificate has expired")

        # Check revocation
        if device_cert.serial_number in self._revoked:
            result["valid"] = False
            result["errors"].append("Certificate has been revoked")

        # Verify issuer matches our CA
        ca_cn = self._ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        issuer_cn = device_cert.certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not issuer_cn or issuer_cn[0].value != ca_cn:
            result["valid"] = False
            result["errors"].append("Certificate issuer does not match CA")

        return result

    def revoke_certificate(self, device_id: str) -> bool:
        """Revoke a device's certificate."""
        device_cert = self._issued.get(device_id)
        if not device_cert:
            return False
        self._revoked.add(device_cert.serial_number)
        return True

    def is_revoked(self, device_id: str) -> bool:
        """Check if a device's certificate is revoked."""
        device_cert = self._issued.get(device_id)
        if not device_cert:
            return False
        return device_cert.serial_number in self._revoked

    def get_issued_certificates(self) -> list[DeviceCertificate]:
        """Return all issued certificates."""
        return list(self._issued.values())
