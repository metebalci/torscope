"""Cryptographic utilities for Tor.

This module provides cryptographic functions for:
- RSA signature verification
- Key fingerprint computation
- Hash functions
"""

import base64
import hashlib
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
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
    Verify an RSA signature.

    Args:
        public_key: RSA public key
        signature: The signature bytes
        data: The data that was signed
        algorithm: Hash algorithm ("sha1" or "sha256")

    Returns:
        True if signature is valid, False otherwise
    """
    # Select hash algorithm
    hash_algo: hashes.HashAlgorithm
    if algorithm == "sha256":
        hash_algo = hashes.SHA256()
    else:
        hash_algo = hashes.SHA1()

    try:
        # Tor uses PKCS#1 v1.5 padding
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hash_algo,
        )
        return True
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
    signature_identity: str,
    signature_algorithm: str = "sha1",  # pylint: disable=unused-argument
) -> Optional[bytes]:
    """
    Extract the portion of a consensus document that was signed.

    According to Tor spec, the signed portion is from "network-status-version"
    through the space after "directory-signature" (before the newline).

    Args:
        consensus_text: Full consensus document text
        signature_identity: The identity fingerprint of the signing authority
        signature_algorithm: Algorithm used ("sha1" or "sha256")

    Returns:
        The signed portion as bytes, or None if not found
    """
    # Find the start: "network-status-version"
    start_marker = "network-status-version"
    start_idx = consensus_text.find(start_marker)
    if start_idx == -1:
        return None

    # Find the specific directory-signature line for this identity
    # Format: "directory-signature [algorithm] identity signing-key-digest"
    search_start = start_idx
    while True:
        sig_marker = "directory-signature"
        sig_idx = consensus_text.find(sig_marker, search_start)
        if sig_idx == -1:
            return None

        # Get the line
        line_end = consensus_text.find("\n", sig_idx)
        if line_end == -1:
            line_end = len(consensus_text)
        line = consensus_text[sig_idx:line_end]

        # Check if this signature line matches our identity
        parts = line.split()
        if len(parts) >= 3:
            # Check algorithm and identity
            if len(parts) == 3:
                # No algorithm specified: directory-signature identity signing-key
                line_identity = parts[1]
            else:
                # Algorithm specified: directory-signature algorithm identity signing-key
                line_identity = parts[2]

            if line_identity == signature_identity:
                # Found the right signature line
                # Signed portion ends after the space following "directory-signature ..."
                # but before the newline
                end_idx = line_end
                signed_text = consensus_text[start_idx:end_idx]
                # Add newline as per spec (through the newline after the sig line)
                signed_text += "\n"
                return signed_text.encode("utf-8")

        search_start = line_end + 1

    return None
