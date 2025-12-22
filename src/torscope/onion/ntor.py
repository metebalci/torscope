"""
ntor handshake implementation.

The ntor handshake is Tor's current circuit establishment protocol,
using Curve25519 for key exchange and HMAC-SHA256 for authentication.

See: https://spec.torproject.org/proposals/216-ntor-handshake.html
"""

import hashlib
import hmac
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

# Protocol constants
PROTOID = b"ntor-curve25519-sha256-1"
T_MAC = PROTOID + b":mac"
T_KEY = PROTOID + b":key_extract"
T_VERIFY = PROTOID + b":verify"
M_EXPAND = PROTOID + b":key_expand"

# Lengths
H_LENGTH = 32  # SHA256 output
G_LENGTH = 32  # Curve25519 point
ID_LENGTH = 20  # Node ID (SHA1 of identity key)

# ntor HTYPE for CREATE2
NTOR_HTYPE = 0x0002


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA256."""
    return hmac.new(key, data, hashlib.sha256).digest()


def _hkdf_expand(key_seed: bytes, length: int) -> bytes:
    """
    HKDF-like key expansion as specified in tor-spec.

    K = K_1 | K_2 | K_3 | ...
    K_1 = H(m_expand | INT8(1), KEY_SEED)
    K_(i+1) = H(K_i | m_expand | INT8(i+1), KEY_SEED)
    """
    result = b""
    k_prev = b""
    i = 1

    while len(result) < length:
        data = k_prev + M_EXPAND + bytes([i])
        k_i = _hmac_sha256(key_seed, data)
        result += k_i
        k_prev = k_i
        i += 1

    return result[:length]


@dataclass
class NtorClientState:
    """Client-side state for ntor handshake."""

    node_id: bytes  # 20 bytes - SHA1 of relay's identity key
    relay_ntor_key: bytes  # 32 bytes - relay's ntor-onion-key (B)
    client_keypair: X25519PrivateKey  # ephemeral keypair (x, X)

    @classmethod
    def create(cls, node_id: bytes, relay_ntor_key: bytes) -> "NtorClientState":
        """
        Create client state for ntor handshake.

        Args:
            node_id: 20-byte SHA1 hash of relay's identity key
            relay_ntor_key: 32-byte relay's ntor-onion-key (from descriptor)
        """
        if len(node_id) != ID_LENGTH:
            raise ValueError(f"node_id must be {ID_LENGTH} bytes")
        if len(relay_ntor_key) != G_LENGTH:
            raise ValueError(f"relay_ntor_key must be {G_LENGTH} bytes")

        keypair = X25519PrivateKey.generate()
        return cls(
            node_id=node_id,
            relay_ntor_key=relay_ntor_key,
            client_keypair=keypair,
        )

    def create_onion_skin(self) -> bytes:
        """
        Create the client's part of the handshake (HDATA for CREATE2).

        Returns:
            84-byte onion skin: node_id (20) | relay_ntor_key (32) | client_pubkey (32)
        """
        client_pubkey = self.client_keypair.public_key().public_bytes_raw()
        return self.node_id + self.relay_ntor_key + client_pubkey

    def complete_handshake(self, server_response: bytes) -> bytes | None:
        """
        Complete the handshake using server's response.

        Args:
            server_response: 64-byte response: server_pubkey (32) | auth (32)

        Returns:
            Key material (72 bytes for forward/backward keys) or None if auth fails
        """
        if len(server_response) != G_LENGTH + H_LENGTH:
            return None

        server_pubkey_bytes = server_response[:G_LENGTH]
        server_auth = server_response[G_LENGTH:]

        # Load server's public key
        server_pubkey = X25519PublicKey.from_public_bytes(server_pubkey_bytes)

        # Load relay's ntor key as public key
        relay_pubkey = X25519PublicKey.from_public_bytes(self.relay_ntor_key)

        # Compute shared secrets
        # EXP(Y, x) - shared secret with server's ephemeral key
        shared_xy = self.client_keypair.exchange(server_pubkey)
        # EXP(B, x) - shared secret with relay's ntor key
        shared_xb = self.client_keypair.exchange(relay_pubkey)

        # Get our public key bytes
        client_pubkey = self.client_keypair.public_key().public_bytes_raw()

        # Compute secret_input
        secret_input = (
            shared_xy
            + shared_xb
            + self.node_id
            + self.relay_ntor_key
            + client_pubkey
            + server_pubkey_bytes
            + PROTOID
        )

        # Derive keys
        key_seed = _hmac_sha256(T_KEY, secret_input)
        verify = _hmac_sha256(T_VERIFY, secret_input)

        # Compute expected auth
        auth_input = (
            verify
            + self.node_id
            + self.relay_ntor_key
            + server_pubkey_bytes
            + client_pubkey
            + PROTOID
            + b"Server"
        )
        expected_auth = _hmac_sha256(T_MAC, auth_input)

        # Verify server's auth
        if not hmac.compare_digest(expected_auth, server_auth):
            return None

        # Expand keys: Df (20) | Db (20) | Kf (16) | Kb (16) = 72 bytes
        # Df/Db = digest keys for forward/backward
        # Kf/Kb = encryption keys for forward/backward
        return _hkdf_expand(key_seed, 72)


@dataclass
class CircuitKeys:
    """Keys derived from ntor handshake for a circuit hop."""

    digest_forward: bytes  # 20 bytes - for computing digests on forward cells
    digest_backward: bytes  # 20 bytes - for verifying digests on backward cells
    key_forward: bytes  # 16 bytes - AES key for encrypting forward cells
    key_backward: bytes  # 16 bytes - AES key for decrypting backward cells

    @classmethod
    def from_key_material(cls, key_material: bytes) -> "CircuitKeys":
        """
        Create CircuitKeys from 72 bytes of key material.

        Layout: Df (20) | Db (20) | Kf (16) | Kb (16)
        """
        if len(key_material) != 72:
            raise ValueError("key_material must be 72 bytes")

        return cls(
            digest_forward=key_material[0:20],
            digest_backward=key_material[20:40],
            key_forward=key_material[40:56],
            key_backward=key_material[56:72],
        )


@dataclass
class HsCircuitKeys:
    """Keys derived from hs-ntor handshake for a hidden service hop.

    Hidden service hops use:
    - SHA3-256 (32 bytes) for digests instead of SHA-1 (20 bytes)
    - AES-256 (32 bytes) for keys instead of AES-128 (16 bytes)
    See: https://spec.torproject.org/rend-spec/introduction-protocol.html#NTOR-WITH-EXTRA-DATA
    """

    digest_forward: bytes  # 32 bytes - SHA3-256 digest seed for forward cells
    digest_backward: bytes  # 32 bytes - SHA3-256 digest seed for backward cells
    key_forward: bytes  # 32 bytes - AES-256 key for encrypting forward cells
    key_backward: bytes  # 32 bytes - AES-256 key for decrypting backward cells

    @classmethod
    def from_key_material(cls, key_material: bytes) -> "HsCircuitKeys":
        """
        Create HsCircuitKeys from 128 bytes of key material.

        Layout: Df (32) | Db (32) | Kf (32) | Kb (32)
        """
        if len(key_material) != 128:
            raise ValueError("key_material must be 128 bytes for HS circuits")

        return cls(
            digest_forward=key_material[0:32],
            digest_backward=key_material[32:64],
            key_forward=key_material[64:96],
            key_backward=key_material[96:128],
        )


def node_id_from_rsa_identity(identity_key_der: bytes) -> bytes:
    """
    Compute node ID (20-byte SHA1) from RSA identity key.

    Args:
        identity_key_der: DER-encoded RSA public key

    Returns:
        20-byte SHA1 hash
    """
    return hashlib.sha1(identity_key_der).digest()


def node_id_from_fingerprint(fingerprint: str) -> bytes:
    """
    Convert hex fingerprint to 20-byte node ID.

    Args:
        fingerprint: 40-character hex string

    Returns:
        20-byte binary node ID
    """
    clean_fp = fingerprint.replace(" ", "").replace("$", "")
    return bytes.fromhex(clean_fp)
