"""
obfs4 handshake implementation.

The obfs4 handshake establishes an encrypted session between client and server.
It uses an ntor-like key exchange with Elligator2-encoded public keys.

Protocol overview:
1. Client sends: X' (representative) || padding || mark || MAC
2. Server sends: Y' (representative) || auth || padding || mark || MAC
3. Both derive session keys from shared secrets

Reference: https://github.com/Yawning/obfs4/blob/master/doc/obfs4-spec.txt
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from torscope.onion.obfs4.elligator import elligator2_decode, elligator2_encode

# Protocol constants
NODE_ID_LENGTH = 20
PUBLIC_KEY_LENGTH = 32
REPRESENTATIVE_LENGTH = 32
AUTH_LENGTH = 32
MARK_LENGTH = 16
MAC_LENGTH = 16

# Padding ranges
CLIENT_MIN_PAD_LENGTH = 85  # Minimum padding
CLIENT_MAX_PAD_LENGTH = 8192 - REPRESENTATIVE_LENGTH - MARK_LENGTH - MAC_LENGTH

# Maximum handshake size
MAX_HANDSHAKE_LENGTH = 8192

# Key derivation constants
PROTO_ID = b"ntor-curve25519-sha256-1:obfs4"
T_MAC = PROTO_ID + b":mac"
T_KEY = PROTO_ID + b":key_extract"
T_VERIFY = PROTO_ID + b":verify"
M_EXPAND = PROTO_ID + b":key_expand"
SERVER_TIMING_TAG = b"Server"


class HandshakeError(Exception):
    """Error during obfs4 handshake."""


@dataclass
class Obfs4ServerCert:
    """
    Parsed obfs4 server certificate.

    The cert parameter in bridge lines encodes:
    - 20 bytes: Node ID
    - 32 bytes: Curve25519 public key

    Format: base64(node_id || public_key) with padding stripped
    """

    node_id: bytes  # 20 bytes
    public_key: bytes  # 32 bytes (Curve25519)

    @classmethod
    def from_string(cls, cert_str: str) -> Obfs4ServerCert:
        """
        Parse cert parameter from bridge line.

        The cert uses a compact base64 encoding with padding stripped.
        We need to add padding before decoding.
        """
        # Add padding characters
        # Standard base64 needs length to be multiple of 4
        padding_needed = (4 - len(cert_str) % 4) % 4
        padded = cert_str + "=" * padding_needed

        try:
            raw = base64.b64decode(padded)
        except Exception as e:
            raise HandshakeError(f"Invalid cert base64: {e}") from e

        if len(raw) != NODE_ID_LENGTH + PUBLIC_KEY_LENGTH:
            raise HandshakeError(
                f"Invalid cert length: expected {NODE_ID_LENGTH + PUBLIC_KEY_LENGTH}, "
                f"got {len(raw)}"
            )

        return cls(
            node_id=raw[:NODE_ID_LENGTH],
            public_key=raw[NODE_ID_LENGTH:],
        )


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA256."""
    return hmac.new(key, data, hashlib.sha256).digest()


def _hmac_sha256_128(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA256 truncated to 128 bits (16 bytes)."""
    return _hmac_sha256(key, data)[:16]


def _hkdf_expand(key_seed: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF-Expand as per RFC 5869.

    This matches Tor's key expansion algorithm.
    """
    result = b""
    prev = b""
    counter = 1

    while len(result) < length:
        prev = _hmac_sha256(key_seed, prev + info + bytes([counter]))
        result += prev
        counter += 1

    return result[:length]


def _get_epoch_hours() -> int:
    """Get current Unix epoch in hours."""
    return int(time.time()) // 3600


@dataclass
class ClientHandshake:
    """
    Client-side obfs4 handshake state.

    Manages the ephemeral keypair and handshake message generation.
    """

    server_cert: Obfs4ServerCert
    iat_mode: int = 0

    # Generated during __post_init__
    _private_key: X25519PrivateKey | None = None
    _public_key: bytes | None = None
    _representative: bytes | None = None
    _epoch_hours: int | None = None

    def __post_init__(self) -> None:
        """Generate an Elligator2-encodable ephemeral keypair."""
        self._epoch_hours = _get_epoch_hours()

        # Generate keypair until we get one that's Elligator2-encodable
        while True:
            self._private_key = X25519PrivateKey.generate()
            self._public_key = self._private_key.public_key().public_bytes_raw()
            self._representative = elligator2_encode(self._public_key)
            if self._representative is not None:
                break

    def _make_key_material(self) -> bytes:
        """Create the key material for MAC computation: server_pk || node_id."""
        return self.server_cert.public_key + self.server_cert.node_id

    def generate_request(self, pad_length: int | None = None) -> bytes:
        """
        Generate the client handshake request.

        Format: X' (32) || padding || M_C (16) || MAC_C (16)

        Args:
            pad_length: Padding length (default: random in valid range)

        Returns:
            Client handshake request bytes
        """
        if self._representative is None:
            raise HandshakeError("Handshake not initialized")

        # Determine padding length
        if pad_length is None:
            pad_length = os.urandom(1)[0] % (CLIENT_MAX_PAD_LENGTH - CLIENT_MIN_PAD_LENGTH)
            pad_length += CLIENT_MIN_PAD_LENGTH

        padding = os.urandom(pad_length)

        # Key material for MACs
        key_material = self._make_key_material()

        # M_C = HMAC-SHA256-128(B || ID, X')
        mark = _hmac_sha256_128(key_material, self._representative)

        # Epoch hour as 4 bytes (little-endian)
        epoch_bytes = (self._epoch_hours or 0).to_bytes(4, "little")

        # MAC_C = HMAC-SHA256-128(B || ID, X' || P_C || M_C || E)
        mac_input = self._representative + padding + mark + epoch_bytes
        mac = _hmac_sha256_128(key_material, mac_input)

        return self._representative + padding + mark + mac

    def process_response(self, response: bytes) -> bytes:
        """
        Process server response and derive session keys.

        Server response format: Y' (32) || AUTH (32) || padding || M_S (16) || MAC_S (16)

        Args:
            response: Server handshake response

        Returns:
            144 bytes of key material for framing

        Raises:
            HandshakeError: If response is invalid or authentication fails
        """
        if len(response) < REPRESENTATIVE_LENGTH + AUTH_LENGTH + MARK_LENGTH + MAC_LENGTH:
            raise HandshakeError(f"Response too short: {len(response)} bytes")

        key_material = self._make_key_material()

        # Find the mark in the response
        # The mark should be at: len(response) - MAC_LENGTH - MARK_LENGTH
        # But we need to scan for it since padding length is variable

        # First, try to find mark by scanning
        mark_pos = self._find_mark(response, key_material)
        if mark_pos < 0:
            raise HandshakeError("Could not find server mark in response")

        # Extract server representative and auth
        server_repr = response[:REPRESENTATIVE_LENGTH]
        server_auth = response[REPRESENTATIVE_LENGTH : REPRESENTATIVE_LENGTH + AUTH_LENGTH]

        # Verify MAC
        mac_pos = mark_pos + MARK_LENGTH
        if mac_pos + MAC_LENGTH > len(response):
            raise HandshakeError("Response truncated")

        epoch_bytes = (self._epoch_hours or 0).to_bytes(4, "little")
        expected_mac = _hmac_sha256_128(key_material, response[:mac_pos] + epoch_bytes)
        actual_mac = response[mac_pos : mac_pos + MAC_LENGTH]

        if not hmac.compare_digest(expected_mac, actual_mac):
            raise HandshakeError("Server MAC verification failed")

        # Decode server's public key from representative
        server_pubkey_bytes = elligator2_decode(server_repr)
        server_pubkey = X25519PublicKey.from_public_bytes(server_pubkey_bytes)

        # Compute shared secrets
        # EXP(Y, x) - shared secret with server's ephemeral
        shared_xy = self._private_key.exchange(server_pubkey)  # type: ignore

        # EXP(B, x) - shared secret with server's static key
        server_static = X25519PublicKey.from_public_bytes(self.server_cert.public_key)
        shared_xb = self._private_key.exchange(server_static)  # type: ignore

        # Derive keys
        keys = self._derive_keys(
            shared_xy,
            shared_xb,
            self._public_key or b"",
            server_pubkey_bytes,
            server_auth,
        )

        return keys

    def _find_mark(self, response: bytes, key_material: bytes) -> int:
        """
        Find the server's mark in the response.

        The mark is HMAC-SHA256-128(B || ID, Y') where Y' is the first 32 bytes.
        """
        if len(response) < REPRESENTATIVE_LENGTH:
            return -1

        server_repr = response[:REPRESENTATIVE_LENGTH]
        expected_mark = _hmac_sha256_128(key_material, server_repr)

        # Scan for mark (it should be near the end)
        min_pos = REPRESENTATIVE_LENGTH + AUTH_LENGTH
        max_pos = len(response) - MARK_LENGTH - MAC_LENGTH

        for pos in range(max_pos, min_pos - 1, -1):
            if response[pos : pos + MARK_LENGTH] == expected_mark:
                return pos

        return -1

    def _derive_keys(
        self,
        shared_xy: bytes,
        shared_xb: bytes,
        client_pubkey: bytes,
        server_pubkey: bytes,
        server_auth: bytes,
    ) -> bytes:
        """
        Derive session keys from shared secrets.

        Uses ntor-like key derivation.
        """
        # secret_input = EXP(Y,x) || EXP(B,x) || ID || B || X || Y || PROTO_ID
        secret_input = (
            shared_xy
            + shared_xb
            + self.server_cert.node_id
            + self.server_cert.public_key
            + client_pubkey
            + server_pubkey
            + PROTO_ID
        )

        # Compute verify and expected auth
        key_seed = _hmac_sha256(T_KEY, secret_input)
        verify = _hmac_sha256(T_VERIFY, secret_input)

        # auth = H(verify || ID || B || Y || X || PROTO_ID || "Server", T_MAC)
        auth_input = (
            verify
            + self.server_cert.node_id
            + self.server_cert.public_key
            + server_pubkey
            + client_pubkey
            + PROTO_ID
            + SERVER_TIMING_TAG
        )
        expected_auth = _hmac_sha256(T_MAC, auth_input)

        if not hmac.compare_digest(expected_auth, server_auth):
            raise HandshakeError("Server auth verification failed")

        # Expand keys: 144 bytes total (72 per direction)
        # Each direction: key (32) || nonce_prefix (16) || sip_key (16) || ofb_iv (8)
        return _hkdf_expand(key_seed, M_EXPAND, 144)
