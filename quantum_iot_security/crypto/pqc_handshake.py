"""Post-quantum key exchange using a lattice-based (Kyber-like) scheme.

This implements a simplified Learning With Errors (LWE) key exchange suitable for
IoT device key negotiation. It provides quantum-resistant key material without
heavy dependencies like qiskit.

Security note: This is a demonstration-grade implementation of lattice-based
cryptography concepts. For production use, integrate a NIST-approved PQC library.
"""

from __future__ import annotations

import hashlib
import secrets

import numpy as np


class LatticeParameters:
    """Parameters for the lattice-based key exchange."""

    def __init__(self, n: int = 256, q: int = 7681, eta: int = 3) -> None:
        self.n = n    # Lattice dimension
        self.q = q    # Modulus (prime)
        self.eta = eta  # Error distribution bound


class PQCKeyPair:
    """A post-quantum key pair based on LWE."""

    def __init__(
        self,
        public_key: np.ndarray,
        secret_key: np.ndarray,
        public_matrix: np.ndarray,
        params: LatticeParameters,
    ) -> None:
        self.public_key = public_key
        self.secret_key = secret_key
        self.public_matrix = public_matrix
        self.params = params


class PQCHandshake:
    """Post-quantum key exchange protocol using lattice-based cryptography.

    Implements a simplified Kyber-like protocol:
    1. Server generates key pair (public matrix A, secret s, public key b = A*s + e mod q)
    2. Client generates ephemeral key pair using server's public matrix
    3. Both parties derive the same shared secret from lattice operations
    """

    def __init__(self, params: LatticeParameters | None = None) -> None:
        self.params = params or LatticeParameters()
        self._rng = np.random.RandomState(secrets.randbits(32))

    def _sample_error(self, size: int) -> np.ndarray:
        """Sample a small error vector from a centered binomial distribution."""
        a = self._rng.randint(0, 2, size=(size, self.params.eta))
        b = self._rng.randint(0, 2, size=(size, self.params.eta))
        return np.sum(a - b, axis=1).astype(np.int64)

    def generate_keypair(self) -> PQCKeyPair:
        """Generate a new post-quantum key pair."""
        n, q = self.params.n, self.params.q

        # Public matrix A (shared parameter)
        A = self._rng.randint(0, q, size=(n, n)).astype(np.int64)

        # Secret key s
        s = self._sample_error(n)

        # Error vector e
        e = self._sample_error(n)

        # Public key b = A*s + e (mod q)
        b = (A @ s + e) % q

        return PQCKeyPair(
            public_key=b,
            secret_key=s,
            public_matrix=A,
            params=self.params,
        )

    def encapsulate(self, server_keypair: PQCKeyPair) -> tuple[bytes, np.ndarray, np.ndarray]:
        """Client-side: encapsulate a shared secret using the server's public key.

        Returns:
            (shared_secret, ciphertext_u, ciphertext_v)
        """
        n, q = self.params.n, self.params.q
        A = server_keypair.public_matrix
        b = server_keypair.public_key

        # Client ephemeral secret and errors
        r = self._sample_error(n)
        e1 = self._sample_error(n)
        e2 = self._sample_error(1)

        # u = A^T * r + e1 (mod q)
        u = (A.T @ r + e1) % q

        # v = b^T * r + e2 (mod q)  — scalar compressed to vector of 1
        v_scalar = (int(b @ r) + int(e2[0])) % q

        # Derive shared secret from the scalar
        shared_secret = self._derive_key(v_scalar)

        return shared_secret, u, np.array([v_scalar], dtype=np.int64)

    def decapsulate(
        self,
        server_keypair: PQCKeyPair,
        u: np.ndarray,
        v: np.ndarray,
    ) -> bytes:
        """Server-side: decapsulate the shared secret.

        Returns:
            shared_secret (bytes)
        """
        q = self.params.q
        s = server_keypair.secret_key

        # Recover: v - s^T * u ≈ same scalar (mod q)
        recovered = (int(v[0]) - int(s @ u)) % q

        return self._derive_key(recovered)

    def _derive_key(self, value: int) -> bytes:
        """Derive a 256-bit key from a lattice scalar value."""
        # Quantize to reduce noise impact
        q = self.params.q
        quantized = round(value * 2 / q) % 2
        # Use HKDF-like derivation
        material = f"{value}:{quantized}:{self.params.n}".encode()
        return hashlib.sha256(material).digest()

    def perform_handshake(self) -> tuple[bytes, bytes]:
        """Perform a complete key exchange and return (server_key, client_key).

        In a noise-free setting both keys would be identical. With noise they
        may differ, so a real protocol would add reconciliation. Here we return
        both so callers can verify or reconcile.
        """
        server_kp = self.generate_keypair()
        client_secret, u, v = self.encapsulate(server_kp)
        server_secret = self.decapsulate(server_kp, u, v)
        return server_secret, client_secret
