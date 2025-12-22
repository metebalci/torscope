"""
ntor-v3 handshake implementation.

The ntor-v3 handshake is an updated circuit establishment protocol,
using Curve25519 for key exchange, SHA3-256 for hashing, and supporting
bidirectional encrypted extension data.

See: https://spec.torproject.org/tor-spec/create-created-cells.html (HTYPE=0x0003)
"""

import hashlib
import hmac
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Protocol constants for ntor-v3
PROTOID = b"ntor3-curve25519-sha3_256-1"

# Tag constants (PROTOID + suffix)
T_MSGKDF = PROTOID + b":msg_kdf"
T_MSGMAC = PROTOID + b":msg_mac"
T_KEY_SEED = PROTOID + b":key_seed"
T_VERIFY = PROTOID + b":verify"
T_FINAL = PROTOID + b":final"
T_AUTH = PROTOID + b":auth_final"

# Lengths
H_LENGTH = 32  # SHA3-256 output
G_LENGTH = 32  # Curve25519 point
ID_LENGTH = 32  # Ed25519 identity key (not SHA1 like in ntor v1)

# ntor-v3 HTYPE for CREATE2
NTOR_V3_HTYPE = 0x0003


def _encap(data: bytes) -> bytes:
    """
    Encapsulate data with its length for domain separation.

    ENCAP(s) = len(s) || s
    where len(s) is 8 bytes little-endian
    """
    return struct.pack("<Q", len(data)) + data


def _h(data: bytes, tag: bytes) -> bytes:
    """
    Tagged SHA3-256 hash.

    H(s, t) = SHA3_256(ENCAP(t) | s)
    """
    return hashlib.sha3_256(_encap(tag) + data).digest()


def _mac(key: bytes, msg: bytes, tag: bytes) -> bytes:
    """
    Tagged MAC using SHA3-256.

    MAC(k, msg, t) = SHA3_256(ENCAP(t) | ENCAP(k) | msg)
    """
    return hashlib.sha3_256(_encap(tag) + _encap(key) + msg).digest()


def _kdf(data: bytes, tag: bytes, length: int) -> bytes:
    """
    Key derivation using SHAKE-256.

    KDF(s, t) = SHAKE_256(ENCAP(t) | s)
    """
    shake = hashlib.shake_256(_encap(tag) + data)
    return shake.digest(length)


def _aes256_ctr_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    AES-256-CTR encryption with zero IV.

    Used for encrypting extension messages.
    """
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")

    iv = b"\x00" * 16
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def _aes256_ctr_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    AES-256-CTR decryption with zero IV.

    Decryption is the same as encryption for CTR mode.
    """
    return _aes256_ctr_encrypt(key, ciphertext)


@dataclass
class NtorV3ClientState:
    """Client-side state for ntor-v3 handshake."""

    node_id: bytes  # 32 bytes - Ed25519 identity key
    relay_ntor_key: bytes  # 32 bytes - relay's ntor-onion-key (B)
    client_keypair: X25519PrivateKey  # ephemeral keypair (x, X)
    verification: bytes  # VER string for binding

    # Computed during onion skin creation
    enc_key: bytes | None = None  # Encryption key for client message
    mac_key: bytes | None = None  # MAC key for authentication
    client_pubkey: bytes | None = None  # Our public key X

    @classmethod
    def create(
        cls,
        node_id: bytes,
        relay_ntor_key: bytes,
        verification: bytes = b"",
    ) -> "NtorV3ClientState":
        """
        Create client state for ntor-v3 handshake.

        Args:
            node_id: 32-byte Ed25519 identity key (not SHA1 hash!)
            relay_ntor_key: 32-byte relay's ntor-onion-key (from descriptor)
            verification: Optional verification binding data
        """
        if len(node_id) != ID_LENGTH:
            raise ValueError(f"node_id must be {ID_LENGTH} bytes (Ed25519 key)")
        if len(relay_ntor_key) != G_LENGTH:
            raise ValueError(f"relay_ntor_key must be {G_LENGTH} bytes")

        keypair = X25519PrivateKey.generate()
        return cls(
            node_id=node_id,
            relay_ntor_key=relay_ntor_key,
            client_keypair=keypair,
            verification=verification,
        )

    def create_onion_skin(self, client_message: bytes = b"") -> bytes:
        """
        Create the client's part of the handshake (HDATA for CREATE2).

        Format:
            NODEID (32) | KEYID (32) | CLIENT_PK (32) | MSG (variable) | MAC (32)

        Args:
            client_message: Optional extension data to encrypt and send

        Returns:
            Onion skin bytes for CREATE2 cell
        """
        # Get our public key
        self.client_pubkey = self.client_keypair.public_key().public_bytes_raw()

        # Load relay's ntor key as X25519 public key
        relay_pubkey = X25519PublicKey.from_public_bytes(self.relay_ntor_key)

        # Compute Bx = EXP(B, x) - shared secret with relay's ntor key
        bx = self.client_keypair.exchange(relay_pubkey)

        # Phase 1: Derive encryption and MAC keys for client message
        # secret_input_phase1 = Bx | ID | X | B | PROTOID | ENCAP(VER)
        secret_input_phase1 = (
            bx
            + self.node_id
            + self.client_pubkey
            + self.relay_ntor_key
            + PROTOID
            + _encap(self.verification)
        )

        # Derive phase1 keystream: ENC_KEY (32) | MAC_KEY (32)
        phase1_keys = _kdf(secret_input_phase1, T_MSGKDF, 64)
        self.enc_key = phase1_keys[:32]
        self.mac_key = phase1_keys[32:64]

        # Encrypt client message if provided
        if client_message:
            encrypted_msg = _aes256_ctr_encrypt(self.enc_key, client_message)
        else:
            encrypted_msg = b""

        # Compute MAC over: ID | B | X | MSG
        mac_input = self.node_id + self.relay_ntor_key + self.client_pubkey + encrypted_msg
        msg_mac = _mac(self.mac_key, mac_input, T_MSGMAC)

        # Build onion skin: NODEID | KEYID | CLIENT_PK | MSG | MAC
        return self.node_id + self.relay_ntor_key + self.client_pubkey + encrypted_msg + msg_mac

    def complete_handshake(self, server_response: bytes) -> tuple[bytes, bytes] | None:
        """
        Complete the handshake using server's response.

        Args:
            server_response: Server response: Y (32) | AUTH (32) | MSG (variable)

        Returns:
            Tuple of (key_material, server_message) or None if auth fails.
            key_material is 128 bytes: Df(32) | Db(32) | Kf(32) | Kb(32)
        """
        if len(server_response) < G_LENGTH + H_LENGTH:
            return None

        server_pubkey_bytes = server_response[:G_LENGTH]
        server_auth = server_response[G_LENGTH : G_LENGTH + H_LENGTH]
        encrypted_server_msg = server_response[G_LENGTH + H_LENGTH :]

        if self.client_pubkey is None:
            raise RuntimeError("Must call create_onion_skin before complete_handshake")

        # Load keys
        server_pubkey = X25519PublicKey.from_public_bytes(server_pubkey_bytes)
        relay_pubkey = X25519PublicKey.from_public_bytes(self.relay_ntor_key)

        # Compute shared secrets
        # Xy = EXP(Y, x) - shared secret with server's ephemeral key
        xy = self.client_keypair.exchange(server_pubkey)
        # Xb = EXP(B, x) - shared secret with relay's ntor key
        xb = self.client_keypair.exchange(relay_pubkey)

        # Compute secret_input
        # secret_input = Xy | Xb | ID | B | X | Y | PROTOID | ENCAP(VER)
        secret_input = (
            xy
            + xb
            + self.node_id
            + self.relay_ntor_key
            + self.client_pubkey
            + server_pubkey_bytes
            + PROTOID
            + _encap(self.verification)
        )

        # Derive ntor key seed and verification value
        ntor_key_seed = _h(secret_input, T_KEY_SEED)
        verify = _h(secret_input, T_VERIFY)

        # Compute expected auth
        # auth_input = verify | ID | B | Y | X | MSG | PROTOID
        auth_input = (
            verify
            + self.node_id
            + self.relay_ntor_key
            + server_pubkey_bytes
            + self.client_pubkey
            + encrypted_server_msg
            + PROTOID
        )
        expected_auth = _h(auth_input, T_AUTH)

        # Verify server's auth
        if not hmac.compare_digest(expected_auth, server_auth):
            return None

        # Derive final keystream
        # KDF(ntor_key_seed, T_FINAL) -> ENC_KEY (32) | KEYSTREAM (128)
        final_keys = _kdf(ntor_key_seed, T_FINAL, 32 + 128)
        server_enc_key = final_keys[:32]
        key_material = final_keys[32:160]  # 128 bytes

        # Decrypt server message if present
        if encrypted_server_msg:
            server_message = _aes256_ctr_decrypt(server_enc_key, encrypted_server_msg)
        else:
            server_message = b""

        return key_material, server_message


@dataclass
class NtorV3CircuitKeys:
    """Keys derived from ntor-v3 handshake for a circuit hop.

    ntor-v3 uses:
    - SHA3-256 (32 bytes) for digests
    - AES-256 (32 bytes) for keys
    """

    digest_forward: bytes  # 32 bytes - SHA3-256 digest seed for forward cells
    digest_backward: bytes  # 32 bytes - SHA3-256 digest seed for backward cells
    key_forward: bytes  # 32 bytes - AES-256 key for encrypting forward cells
    key_backward: bytes  # 32 bytes - AES-256 key for decrypting backward cells

    @classmethod
    def from_key_material(cls, key_material: bytes) -> "NtorV3CircuitKeys":
        """
        Create NtorV3CircuitKeys from 128 bytes of key material.

        Layout: Df (32) | Db (32) | Kf (32) | Kb (32)
        """
        if len(key_material) != 128:
            raise ValueError("key_material must be 128 bytes")

        return cls(
            digest_forward=key_material[0:32],
            digest_backward=key_material[32:64],
            key_forward=key_material[64:96],
            key_backward=key_material[96:128],
        )


def node_id_from_ed25519(ed25519_key: bytes) -> bytes:
    """
    Get node ID from Ed25519 public key.

    For ntor-v3, the node ID is the raw Ed25519 public key (32 bytes),
    not a SHA1 hash like in ntor v1.

    Args:
        ed25519_key: 32-byte Ed25519 public key

    Returns:
        32-byte node ID (same as input)
    """
    if len(ed25519_key) != 32:
        raise ValueError("Ed25519 key must be 32 bytes")
    return ed25519_key
