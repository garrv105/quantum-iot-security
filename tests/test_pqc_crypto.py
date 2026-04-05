"""Tests for post-quantum cryptography and secure channels."""

from __future__ import annotations

import pytest

from quantum_iot_security.crypto.pqc_handshake import LatticeParameters, PQCHandshake
from quantum_iot_security.crypto.secure_channel import SecureChannel


class TestPQCHandshake:
    def test_generate_keypair(self):
        """Key generation should produce valid keys."""
        handshake = PQCHandshake()
        kp = handshake.generate_keypair()
        assert kp.public_key.shape == (256,)
        assert kp.secret_key.shape == (256,)
        assert kp.public_matrix.shape == (256, 256)

    def test_encapsulate_decapsulate(self):
        """Encapsulation and decapsulation should produce 32-byte keys."""
        handshake = PQCHandshake()
        server_kp = handshake.generate_keypair()
        client_secret, u, v = handshake.encapsulate(server_kp)
        server_secret = handshake.decapsulate(server_kp, u, v)

        assert len(client_secret) == 32
        assert len(server_secret) == 32

    def test_perform_handshake(self):
        """Full handshake should produce two 32-byte keys."""
        handshake = PQCHandshake()
        server_key, client_key = handshake.perform_handshake()
        assert len(server_key) == 32
        assert len(client_key) == 32

    def test_custom_parameters(self):
        """Custom lattice parameters should work."""
        params = LatticeParameters(n=64, q=7681, eta=2)
        handshake = PQCHandshake(params)
        kp = handshake.generate_keypair()
        assert kp.public_key.shape == (64,)

    def test_different_keypairs_differ(self):
        """Two independently generated keypairs should differ."""
        hs = PQCHandshake()
        kp1 = hs.generate_keypair()
        kp2 = hs.generate_keypair()
        assert not (kp1.public_key == kp2.public_key).all()


class TestSecureChannel:
    def test_encrypt_decrypt(self):
        """Encrypted data should decrypt to original plaintext."""
        channel = SecureChannel()
        plaintext = b"Hello IoT device!"
        msg = channel.encrypt(plaintext)
        decrypted = channel.decrypt(msg)
        assert decrypted == plaintext

    def test_encrypt_with_aad(self):
        """AEAD with associated data should work."""
        channel = SecureChannel()
        plaintext = b"sensor data"
        aad = b"device-001"
        msg = channel.encrypt(plaintext, associated_data=aad)
        decrypted = channel.decrypt(msg, associated_data=aad)
        assert decrypted == plaintext

    def test_tampered_ciphertext_fails(self):
        """Tampered ciphertext should fail decryption."""
        channel = SecureChannel()
        msg = channel.encrypt(b"secret")
        msg.ciphertext = bytes([b ^ 0xFF for b in msg.ciphertext])
        with pytest.raises(Exception):
            channel.decrypt(msg)

    def test_sequence_numbers_increment(self):
        """Sequence numbers should increment after each send."""
        channel = SecureChannel()
        assert channel.send_sequence == 0
        channel.encrypt(b"msg1")
        assert channel.send_sequence == 1
        channel.encrypt(b"msg2")
        assert channel.send_sequence == 2

    def test_from_pqc_handshake(self):
        """Channels created from PQC handshake should work."""
        server_ch, client_ch = SecureChannel.from_pqc_handshake()
        msg = server_ch.encrypt(b"from server")
        decrypted = client_ch.decrypt(msg)
        assert decrypted == b"from server"

    def test_invalid_key_size(self):
        """Invalid key size should raise ValueError."""
        with pytest.raises(ValueError, match="16 or 32"):
            SecureChannel(key=b"short")
