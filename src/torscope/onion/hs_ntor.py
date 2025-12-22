"""
hs-ntor handshake implementation for hidden services.

The hs-ntor handshake is used for establishing end-to-end encryption
with v3 hidden services. It differs from regular ntor:
- Uses SHA3-256 instead of SHA-256
- Uses SHAKE-256 for key derivation instead of HKDF
- Different PROTOID and tweak strings
- Two-phase: introduction (encrypt INTRODUCE1) and rendezvous (complete handshake)

See: https://spec.torproject.org/rend-spec/introduction-protocol.html
"""

import hmac
import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from torscope.crypto import sha3_256, shake256

# Protocol constants
PROTOID = b"tor-hs-ntor-curve25519-sha3-256-1"
T_HSENC = PROTOID + b":hs_key_extract"
T_HSVERIFY = PROTOID + b":hs_verify"
T_HSMAC = PROTOID + b":hs_mac"
M_HSEXPAND = PROTOID + b":hs_key_expand"

# Key lengths
S_KEY_LEN = 32  # AES-256 key length
MAC_LEN = 32  # SHA3-256 output
HASH_LEN = 32  # SHA3-256 output
G_LENGTH = 32  # Curve25519 point


def hs_ntor_mac(key: bytes, message: bytes) -> bytes:
    """Compute MAC as H(key_len | key | message) using SHA3-256.

    This is the MAC function used in hs-ntor, different from HMAC.

    Args:
        key: MAC key
        message: Message to authenticate

    Returns:
        32-byte MAC
    """
    return sha3_256(struct.pack(">Q", len(key)) + key + message)


def hs_ntor_kdf(secret_input: bytes, info: bytes, length: int) -> bytes:
    """SHAKE-256 based key derivation.

    Args:
        secret_input: Input keying material
        info: Context/info string
        length: Output length in bytes

    Returns:
        Derived key material
    """
    return shake256(secret_input + info, length)


@dataclass
class HsNtorIntroKeys:
    """Keys derived for encrypting INTRODUCE1 cell."""

    enc_key: bytes  # 32 bytes - AES-256 key for encrypting intro data
    mac_key: bytes  # 32 bytes - MAC key for authenticating intro data


@dataclass
class HsNtorClientState:
    """Client-side state for hs-ntor handshake.

    The hs-ntor handshake has two phases:
    1. Introduction: Client encrypts INTRODUCE1 to the intro point's enc_key
    2. Rendezvous: Client completes handshake when receiving RENDEZVOUS2
    """

    # Introduction point keys (from descriptor)
    enc_key_b: bytes  # 32-byte X25519 encryption key (B)
    auth_key: bytes  # 32-byte Ed25519 auth key

    # Client ephemeral keypair
    client_keypair: X25519PrivateKey  # (x, X)

    # Subcredential for key derivation
    subcredential: bytes  # 32 bytes

    @classmethod
    def create(
        cls,
        enc_key: bytes,
        auth_key: bytes,
        subcredential: bytes,
    ) -> "HsNtorClientState":
        """Create client state for hs-ntor handshake.

        Args:
            enc_key: 32-byte X25519 encryption key from intro point (B)
            auth_key: 32-byte Ed25519 auth key from intro point
            subcredential: 32-byte subcredential for the hidden service
        """
        if len(enc_key) != G_LENGTH:
            raise ValueError(f"enc_key must be {G_LENGTH} bytes")
        if len(auth_key) != G_LENGTH:
            raise ValueError(f"auth_key must be {G_LENGTH} bytes")
        if len(subcredential) != HASH_LEN:
            raise ValueError(f"subcredential must be {HASH_LEN} bytes")

        keypair = X25519PrivateKey.generate()
        return cls(
            enc_key_b=enc_key,
            auth_key=auth_key,
            client_keypair=keypair,
            subcredential=subcredential,
        )

    @property
    def client_pubkey(self) -> bytes:
        """Get client's ephemeral public key (X)."""
        return self.client_keypair.public_key().public_bytes_raw()

    def get_introduce_keys(self) -> HsNtorIntroKeys:
        """Derive keys for encrypting INTRODUCE1 cell.

        Computes:
            intro_secret_hs_input = EXP(B,x) | AUTH_KEY | X | B | PROTOID
            info = m_hsexpand | subcredential
            hs_keys = KDF(intro_secret_hs_input | t_hsenc | info, S_KEY_LEN + MAC_LEN)

        Returns:
            HsNtorIntroKeys with enc_key and mac_key
        """
        # Load intro point's enc key as X25519 public key
        b_pubkey = X25519PublicKey.from_public_bytes(self.enc_key_b)

        # Compute shared secret: EXP(B, x)
        shared_bx = self.client_keypair.exchange(b_pubkey)

        # Get client public key bytes
        client_pk = self.client_pubkey

        # Compute intro_secret_hs_input
        intro_secret_hs_input = shared_bx + self.auth_key + client_pk + self.enc_key_b + PROTOID

        # Derive keys
        info = M_HSEXPAND + self.subcredential
        kdf_input = intro_secret_hs_input + T_HSENC + info
        keys = hs_ntor_kdf(kdf_input, b"", S_KEY_LEN + MAC_LEN)

        return HsNtorIntroKeys(
            enc_key=keys[:S_KEY_LEN],
            mac_key=keys[S_KEY_LEN:],
        )

    def encrypt_introduce_data(self, plaintext: bytes) -> bytes:
        """Encrypt data for INTRODUCE1 cell.

        Args:
            plaintext: Data to encrypt (rendezvous cookie, link specs, etc.)

        Returns:
            Ciphertext (same length as plaintext)
        """
        keys = self.get_introduce_keys()

        # Generate random IV (16 bytes for AES-CTR)
        # Note: Per spec, the IV is derived, but we use zero IV like Tor does
        iv = b"\x00" * 16

        # Encrypt with AES-256-CTR
        cipher = Cipher(algorithms.AES(keys.enc_key), modes.CTR(iv))
        encryptor = cipher.encryptor()
        return encryptor.update(plaintext) + encryptor.finalize()

    def compute_introduce_mac(self, cell_without_mac: bytes) -> bytes:
        """Compute MAC for INTRODUCE1 cell.

        Per Tor's hs_cell.c compute_introduce_mac(), the MAC covers the
        entire cell up to (but not including) the MAC field itself.

        Args:
            cell_without_mac: The entire INTRODUCE1 cell payload without the MAC

        Returns:
            32-byte MAC
        """
        keys = self.get_introduce_keys()
        return hs_ntor_mac(keys.mac_key, cell_without_mac)

    def complete_rendezvous(self, server_pk_bytes: bytes, auth: bytes) -> bytes | None:
        """Complete the handshake using RENDEZVOUS2 response.

        The hidden service sends SERVER_PK (Y) and AUTH in RENDEZVOUS2.
        We verify the handshake and derive circuit keys.

        Args:
            server_pk_bytes: 32-byte server ephemeral public key (Y)
            auth: 32-byte authentication MAC from server

        Returns:
            Key material (Df | Db | Kf | Kb) or None if verification fails
        """
        if len(server_pk_bytes) != G_LENGTH:
            return None
        if len(auth) != MAC_LEN:
            return None

        # Load keys
        server_pk = X25519PublicKey.from_public_bytes(server_pk_bytes)
        b_pubkey = X25519PublicKey.from_public_bytes(self.enc_key_b)

        # Compute shared secrets
        # EXP(Y, x) - shared with server's ephemeral key
        shared_yx = self.client_keypair.exchange(server_pk)
        # EXP(B, x) - shared with intro point's enc key
        shared_bx = self.client_keypair.exchange(b_pubkey)

        # Get our public key bytes
        client_pk = self.client_pubkey

        # Compute rend_secret_hs_input
        # = EXP(Y,x) | EXP(B,x) | AUTH_KEY | B | X | Y | PROTOID
        rend_secret_hs_input = (
            shared_yx
            + shared_bx
            + self.auth_key
            + self.enc_key_b
            + client_pk
            + server_pk_bytes
            + PROTOID
        )

        # Derive NTOR_KEY_SEED and verify
        ntor_key_seed = hs_ntor_mac(rend_secret_hs_input, T_HSENC)
        verify = hs_ntor_mac(rend_secret_hs_input, T_HSVERIFY)

        # Compute expected auth
        # auth_input = verify | AUTH_KEY | B | Y | X | PROTOID | "Server"
        auth_input = (
            verify
            + self.auth_key
            + self.enc_key_b
            + server_pk_bytes
            + client_pk
            + PROTOID
            + b"Server"
        )
        expected_auth = hs_ntor_mac(auth_input, T_HSMAC)

        # Verify server's auth (constant-time comparison to prevent timing attacks)
        if not hmac.compare_digest(auth, expected_auth):
            return None

        # Derive circuit keys
        # K = KDF(NTOR_KEY_SEED | m_hsexpand, SHA3_256_LEN * 2 + S_KEY_LEN * 2)
        # For hs-ntor / hidden service hops:
        # - Digest uses SHA3-256 (32 bytes each for Df/Db)
        # - Encryption uses AES-256 (32 bytes each for Kf/Kb)
        # Total: Df (32) | Db (32) | Kf (32) | Kb (32) = 128 bytes
        # See: https://spec.torproject.org/rend-spec/introduction-protocol.html#NTOR-WITH-EXTRA-DATA
        # "instead of using AES-128 and SHA1 for this hop, we use AES-256 and SHA3-256"
        key_material = hs_ntor_kdf(ntor_key_seed, M_HSEXPAND, 128)

        return key_material


def create_introduce1_encrypted_payload(
    rendezvous_cookie: bytes,
    rendezvous_link_specifiers: list[tuple[int, bytes]],
    rendezvous_onion_key: bytes,
) -> bytes:
    """Create the plaintext for the encrypted portion of INTRODUCE1.

    Format:
        RENDEZVOUS_COOKIE      [20 bytes]
        N_EXTENSIONS           [1 byte]
        ONION_KEY_TYPE         [1 byte] (0x01 = ntor)
        ONION_KEY_LEN          [2 bytes]
        ONION_KEY              [ONION_KEY_LEN bytes]
        NSPEC                  [1 byte]
        NSPEC times:
            LSTYPE             [1 byte]
            LSLEN              [1 byte]
            LSPEC              [LSLEN bytes]

    Args:
        rendezvous_cookie: 20-byte random cookie
        rendezvous_link_specifiers: Link specifiers for the rendezvous point
        rendezvous_onion_key: 32-byte ntor key for the rendezvous point

    Returns:
        Encrypted payload plaintext
    """
    if len(rendezvous_cookie) != 20:
        raise ValueError("rendezvous_cookie must be 20 bytes")
    if len(rendezvous_onion_key) != 32:
        raise ValueError("rendezvous_onion_key must be 32 bytes")

    # Start building payload
    payload = bytearray()

    # RENDEZVOUS_COOKIE [20 bytes]
    payload.extend(rendezvous_cookie)

    # N_EXTENSIONS [1 byte] - no extensions
    payload.append(0)

    # ONION_KEY_TYPE [1 byte] - 0x01 = ntor
    payload.append(0x01)

    # ONION_KEY_LEN [2 bytes]
    payload.extend(struct.pack(">H", len(rendezvous_onion_key)))

    # ONION_KEY [32 bytes]
    payload.extend(rendezvous_onion_key)

    # NSPEC [1 byte]
    payload.append(len(rendezvous_link_specifiers))

    # Link specifiers
    for lstype, lspec in rendezvous_link_specifiers:
        payload.append(lstype)
        payload.append(len(lspec))
        payload.extend(lspec)

    # Pad the plaintext to a consistent size
    # The spec says to pad so INTRODUCE2 is a fixed size (246 or 490 bytes)
    # We'll pad the plaintext to 246 bytes to match current Tor implementations
    target_size = 246
    if len(payload) < target_size:
        payload.extend(b"\x00" * (target_size - len(payload)))

    return bytes(payload)


def generate_rendezvous_cookie() -> bytes:
    """Generate a random 20-byte rendezvous cookie."""
    return os.urandom(20)
