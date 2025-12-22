"""V3 hidden service client authorization.

This module implements client authorization for v3 hidden services as specified
in rend-spec-v3.txt section 2.5.1.4.

Client authorization allows hidden service operators to restrict access to
specific clients who possess the correct x25519 private key.

Key format (standard Tor format):
    descriptor:x25519:<base32-encoded-private-key>

The client key file is typically stored at:
    ~/.tor/onion_auth/<onion-address>.auth_private
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from torscope.crypto import shake256


@dataclass
class AuthClientEntry:
    """A single auth-client entry from the first layer."""

    client_id: bytes  # 8 bytes
    iv: bytes  # 16 bytes
    encrypted_cookie: bytes  # 32 bytes


@dataclass
class ClientAuthData:
    """Parsed client auth data from the first layer plaintext."""

    auth_type: str  # "x25519"
    ephemeral_key: bytes  # 32-byte X25519 public key
    auth_clients: list[AuthClientEntry] = field(default_factory=list)


def parse_client_auth_key(auth_key_str: str) -> bytes:
    """Parse a client authorization key string.

    Accepts formats:
        - "<address>:descriptor:x25519:<base32-key>"  (full Tor file format)
        - "descriptor:x25519:<base32-key>"            (standard Tor format)
        - "<base32-key>"                              (just the key)

    Args:
        auth_key_str: The auth key string

    Returns:
        32-byte X25519 private key

    Raises:
        ValueError: If the key format is invalid
    """
    key_str = auth_key_str.strip()

    # Handle full Tor file format: <address>:descriptor:x25519:<key>
    if ":descriptor:x25519:" in key_str.lower():
        parts = key_str.split(":")
        if len(parts) >= 4:
            # Last part is the key
            key_str = parts[-1]
    # Handle standard Tor format: descriptor:x25519:<key>
    elif key_str.lower().startswith("descriptor:x25519:"):
        key_str = key_str[18:]  # Remove prefix

    # Decode base32 (Tor uses RFC 4648 without padding)
    try:
        # Add padding for standard base32 decoder
        padded = key_str.upper() + "=" * ((8 - len(key_str) % 8) % 8)
        key_bytes = base64.b32decode(padded)
    except Exception as e:
        raise ValueError(f"Invalid base32 encoding in auth key: {e}") from e

    if len(key_bytes) != 32:
        raise ValueError(f"Auth key must be 32 bytes, got {len(key_bytes)}")

    return key_bytes


def read_client_auth_file(file_path: str) -> bytes:
    """Read client authorization key from a file.

    The file should contain a line in one of these formats:
        - <address>:descriptor:x25519:<base32-key>  (standard Tor format)
        - descriptor:x25519:<base32-key>
        - <base32-key>

    The file is typically stored at:
        ~/.tor/onion_auth/<onion-address>.auth_private

    Args:
        file_path: Path to the auth key file

    Returns:
        32-byte X25519 private key

    Raises:
        ValueError: If the file format is invalid
        FileNotFoundError: If the file doesn't exist
    """
    with open(file_path, encoding="utf-8") as f:
        content = f.read().strip()

    # Skip empty lines and comments, take first valid line
    for line in content.split("\n"):
        line = line.strip()
        if line and not line.startswith("#"):
            return parse_client_auth_key(line)

    raise ValueError(f"No valid auth key found in {file_path}")


def parse_client_auth_data(first_layer_text: str) -> ClientAuthData | None:
    """Parse client auth data from first layer plaintext.

    Extracts:
        - desc-auth-type (must be "x25519")
        - desc-auth-ephemeral-key (32-byte X25519 pubkey)
        - auth-client entries (client-id, iv, encrypted-cookie)

    Args:
        first_layer_text: Decrypted first layer as text

    Returns:
        ClientAuthData if auth is present, None if no auth required
    """
    lines = first_layer_text.strip().split("\n")

    auth_type: str | None = None
    ephemeral_key: bytes | None = None
    auth_clients: list[AuthClientEntry] = []

    for line in lines:
        line = line.strip()

        if line.startswith("desc-auth-type "):
            auth_type = line.split()[1]

        elif line.startswith("desc-auth-ephemeral-key "):
            key_b64 = line.split()[1]
            ephemeral_key = _decode_base64(key_b64)

        elif line.startswith("auth-client "):
            parts = line.split()
            if len(parts) >= 4:
                client_id = _decode_base64(parts[1])
                iv = _decode_base64(parts[2])
                encrypted_cookie = _decode_base64(parts[3])
                auth_clients.append(
                    AuthClientEntry(
                        client_id=client_id,
                        iv=iv,
                        encrypted_cookie=encrypted_cookie,
                    )
                )

    # If no auth data found, return None
    if auth_type is None:
        return None

    if auth_type != "x25519":
        raise ValueError(f"Unsupported auth type: {auth_type}")

    if ephemeral_key is None:
        raise ValueError("Missing desc-auth-ephemeral-key")

    if len(ephemeral_key) != 32:
        raise ValueError(f"Invalid ephemeral key length: {len(ephemeral_key)}")

    return ClientAuthData(
        auth_type=auth_type,
        ephemeral_key=ephemeral_key,
        auth_clients=auth_clients,
    )


def derive_client_id_and_cookie_key(
    client_privkey: bytes,
    ephemeral_pubkey: bytes,
    subcredential: bytes,
) -> tuple[bytes, bytes]:
    """Derive CLIENT-ID and COOKIE-KEY for client authorization.

    Per rend-spec-v3:
        SECRET_SEED = x25519(client_privkey, ephemeral_pubkey)
        KEYS = KDF(subcredential | SECRET_SEED, 40)
        CLIENT-ID = KEYS[0:8]
        COOKIE-KEY = KEYS[8:40]

    Args:
        client_privkey: 32-byte X25519 private key
        ephemeral_pubkey: 32-byte X25519 public key from descriptor
        subcredential: 32-byte subcredential

    Returns:
        Tuple of (client_id, cookie_key)
    """
    # Load keys
    privkey = X25519PrivateKey.from_private_bytes(client_privkey)
    pubkey = X25519PublicKey.from_public_bytes(ephemeral_pubkey)

    # Compute shared secret
    secret_seed = privkey.exchange(pubkey)

    # Derive keys: KDF(subcredential | SECRET_SEED, 40)
    kdf_input = subcredential + secret_seed
    keys = shake256(kdf_input, 40)

    client_id = keys[:8]
    cookie_key = keys[8:]

    return client_id, cookie_key


def decrypt_descriptor_cookie(
    auth_clients: list[AuthClientEntry],
    client_id: bytes,
    cookie_key: bytes,
) -> bytes | None:
    """Find matching auth-client entry and decrypt the descriptor cookie.

    Args:
        auth_clients: List of auth-client entries from descriptor
        client_id: 8-byte client identifier
        cookie_key: 32-byte key for decryption

    Returns:
        32-byte descriptor_cookie or None if no matching entry
    """
    # Find matching auth-client entry
    for entry in auth_clients:
        if entry.client_id == client_id:
            # Decrypt using AES-256-CTR
            # descriptor_cookie = AES-CTR(cookie_key, iv) XOR encrypted_cookie
            cipher = Cipher(algorithms.AES(cookie_key), modes.CTR(entry.iv))
            decryptor = cipher.decryptor()
            descriptor_cookie = decryptor.update(entry.encrypted_cookie) + decryptor.finalize()
            return descriptor_cookie

    return None


def get_descriptor_cookie(
    first_layer_text: str,
    client_privkey: bytes,
    subcredential: bytes,
) -> bytes | None:
    """Get descriptor cookie for a private hidden service.

    This is the main entry point for client authorization.

    Args:
        first_layer_text: Decrypted first layer plaintext
        client_privkey: 32-byte X25519 private key from auth file
        subcredential: 32-byte subcredential

    Returns:
        32-byte descriptor_cookie, or None if:
        - No client auth required (public service with no auth entries)
        - No matching auth-client entry found (service may still allow public access)

    Raises:
        ValueError: If auth data is malformed
    """
    # Parse auth data from first layer
    auth_data = parse_client_auth_data(first_layer_text)

    if auth_data is None:
        # No client auth required (public service)
        return None

    # Derive our client-id and cookie-key
    client_id, cookie_key = derive_client_id_and_cookie_key(
        client_privkey=client_privkey,
        ephemeral_pubkey=auth_data.ephemeral_key,
        subcredential=subcredential,
    )

    # Find and decrypt our cookie
    descriptor_cookie = decrypt_descriptor_cookie(
        auth_clients=auth_data.auth_clients,
        client_id=client_id,
        cookie_key=cookie_key,
    )

    # Return the cookie (or None if no match - caller will try public decryption)
    return descriptor_cookie


def _decode_base64(s: str) -> bytes:
    """Decode base64 with padding handling."""
    # Add padding if needed
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)
