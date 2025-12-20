"""Cryptographic utilities for Tor.

This module provides cryptographic functions for:
- RSA signature verification
- Ed25519 signature verification
- Key fingerprint computation
- Hash functions (SHA1, SHA256, SHA3-256, SHAKE-256)
"""

import base64
import hashlib
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


def load_rsa_public_key(pem_key: str) -> RSAPublicKey:
    """
    Load an RSA public key from PEM format.

    Args:
        pem_key: PEM-encoded RSA public key (including headers)

    Returns:
        RSAPublicKey object

    Raises:
        ValueError: If the key cannot be parsed
    """
    # Ensure proper PEM format
    key_data = pem_key.strip()
    if not key_data.startswith("-----BEGIN"):
        key_data = f"-----BEGIN RSA PUBLIC KEY-----\n{key_data}\n-----END RSA PUBLIC KEY-----"

    key_bytes = key_data.encode("utf-8")

    try:
        # Try loading as PKCS#1 RSA public key
        key = serialization.load_pem_public_key(key_bytes)
    # pylint: disable-next=broad-exception-caught
    except Exception:
        # Try loading as SubjectPublicKeyInfo (PKCS#8)
        try:
            # Convert from RSA PUBLIC KEY to PUBLIC KEY format if needed
            if "RSA PUBLIC KEY" in key_data:
                # This is PKCS#1 format, cryptography should handle it
                raise
            key = serialization.load_pem_public_key(key_bytes)
        # pylint: disable-next=broad-exception-caught
        except Exception as e:
            raise ValueError(f"Failed to load RSA public key: {e}") from e

    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("Key is not an RSA public key")

    return key


def compute_rsa_key_fingerprint(pem_key: str) -> str:
    """
    Compute the SHA1 fingerprint of an RSA public key.

    The fingerprint is the SHA1 hash of the DER-encoded key.

    Args:
        pem_key: PEM-encoded RSA public key

    Returns:
        Uppercase hex-encoded SHA1 fingerprint
    """
    key = load_rsa_public_key(pem_key)

    # Get DER encoding (PKCS#1 format for Tor compatibility)
    der_bytes = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.PKCS1,
    )

    # Compute SHA1 hash
    digest = hashlib.sha1(der_bytes).hexdigest().upper()
    return digest


def verify_rsa_signature(
    public_key: RSAPublicKey,
    signature: bytes,
    data: bytes,
    algorithm: str = "sha1",
) -> bool:
    """
    Verify an RSA signature using Tor's format.

    Tor uses PKCS#1 v1.5 padding but with raw hashes (no DigestInfo OID).
    Format: 00 01 [FF padding] 00 [raw hash]

    Args:
        public_key: RSA public key
        signature: The signature bytes
        data: The data that was signed
        algorithm: Hash algorithm ("sha1" or "sha256")

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        # Compute expected hash
        if algorithm == "sha256":
            expected_hash = hashlib.sha256(data).digest()
        else:
            expected_hash = hashlib.sha1(data).digest()

        # RSA decrypt to get the padded hash
        numbers = public_key.public_numbers()
        sig_int = int.from_bytes(signature, "big")
        decrypted_int = pow(sig_int, numbers.e, numbers.n)
        key_size_bytes = (public_key.key_size + 7) // 8
        decrypted = decrypted_int.to_bytes(key_size_bytes, "big")

        # Verify PKCS#1 v1.5 padding: 00 01 [FF...] 00 [hash]
        if len(decrypted) < 11:
            return False
        if decrypted[0] != 0 or decrypted[1] != 1:
            return False

        # Find the 00 separator after FF padding
        sep_idx = decrypted.find(b"\x00", 2)
        if sep_idx < 10:  # Must have at least 8 bytes of FF padding
            return False

        # Check padding is all FF
        if decrypted[2:sep_idx] != b"\xff" * (sep_idx - 2):
            return False

        # Extract hash from signature
        actual_hash = decrypted[sep_idx + 1 :]

        # Compare hashes
        return actual_hash == expected_hash
    # pylint: disable-next=broad-exception-caught
    except Exception:
        return False


def verify_consensus_signature(
    signing_key_pem: str,
    signature_b64: str,
    signed_data: bytes,
    algorithm: str = "sha1",
) -> bool:
    """
    Verify a consensus document signature.

    Args:
        signing_key_pem: PEM-encoded signing public key
        signature_b64: Base64-encoded signature (may include PEM headers)
        signed_data: The signed portion of the consensus
        algorithm: Hash algorithm ("sha1" or "sha256")

    Returns:
        True if signature is valid, False otherwise
    """
    # Load the signing key
    try:
        public_key = load_rsa_public_key(signing_key_pem)
    except ValueError:
        return False

    # Extract signature bytes from base64
    # Remove PEM headers if present
    sig_data = signature_b64.strip()
    if "-----BEGIN" in sig_data:
        lines = sig_data.split("\n")
        b64_lines = [line for line in lines if not line.startswith("-----") and line.strip()]
        sig_data = "".join(b64_lines)

    try:
        signature = base64.b64decode(sig_data)
    # pylint: disable-next=broad-exception-caught
    except Exception:
        return False

    return verify_rsa_signature(public_key, signature, signed_data, algorithm)


def extract_signed_portion(
    consensus_text: str,
    signature_identity: str,  # pylint: disable=unused-argument
    signature_algorithm: str = "sha1",  # pylint: disable=unused-argument
) -> bytes | None:
    """
    Extract the portion of a consensus document that was signed.

    According to Tor source code (router_get_networkstatus_v3_signed_boundaries),
    the signed portion is from "network-status-version" (at line start) through
    the first space after "\\ndirectory-signature". This is the SAME for all
    signatures regardless of algorithm (sha1/sha256).

    The algorithm parameter only indicates which hash function to use on the
    signed portion, not where the signed portion ends.

    Args:
        consensus_text: Full consensus document text
        signature_identity: The identity fingerprint (unused - kept for API compatibility)
        signature_algorithm: Algorithm used (unused - boundaries are same for all)

    Returns:
        The signed portion as bytes, or None if not found
    """
    # Find the start: "network-status-version" at line start
    start_marker = "network-status-version"
    start_idx = 0
    while True:
        idx = consensus_text.find(start_marker, start_idx)
        if idx == -1:
            return None
        # Check if at line start (idx == 0 or preceded by newline)
        if idx == 0 or consensus_text[idx - 1] == "\n":
            start_idx = idx
            break
        start_idx = idx + 1

    # Find end: "\ndirectory-signature" then first space after it
    end_marker = "\ndirectory-signature"
    end_str_idx = consensus_text.find(end_marker, start_idx)
    if end_str_idx == -1:
        return None

    # Find first space after the end marker
    space_idx = consensus_text.find(" ", end_str_idx + len(end_marker))
    if space_idx == -1:
        return None

    # End is right after the space (inclusive)
    end_idx = space_idx + 1
    signed_text = consensus_text[start_idx:end_idx]
    return signed_text.encode("utf-8")


# =============================================================================
# Ed25519 Functions
# =============================================================================


def load_ed25519_public_key(key_bytes: bytes) -> Ed25519PublicKey:
    """
    Load an Ed25519 public key from raw bytes.

    Args:
        key_bytes: 32-byte Ed25519 public key

    Returns:
        Ed25519PublicKey object

    Raises:
        ValueError: If the key cannot be parsed
    """
    if len(key_bytes) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(key_bytes)}")

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    return Ed25519PublicKey.from_public_bytes(key_bytes)


def verify_ed25519_signature(
    public_key: bytes | Ed25519PublicKey,
    signature: bytes,
    data: bytes,
) -> bool:
    """
    Verify an Ed25519 signature.

    Args:
        public_key: 32-byte Ed25519 public key or Ed25519PublicKey object
        signature: 64-byte Ed25519 signature
        data: The data that was signed

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        if isinstance(public_key, bytes):
            key = load_ed25519_public_key(public_key)
        else:
            key = public_key

        key.verify(signature, data)
        return True
    except (InvalidSignature, ValueError):
        return False


# =============================================================================
# SHA3 and SHAKE Functions
# =============================================================================


def sha3_256(data: bytes) -> bytes:
    """
    Compute SHA3-256 hash.

    Args:
        data: Data to hash

    Returns:
        32-byte hash digest
    """
    return hashlib.sha3_256(data).digest()


def shake256(data: bytes, length: int) -> bytes:
    """
    Compute SHAKE-256 extendable output.

    Args:
        data: Data to hash
        length: Output length in bytes

    Returns:
        Hash digest of specified length
    """
    return hashlib.shake_256(data).digest(length)
