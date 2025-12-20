"""Tests for cryptographic utilities."""

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from torscope.crypto import (
    compute_rsa_key_fingerprint,
    extract_signed_portion,
    load_rsa_public_key,
    verify_consensus_signature,
    verify_rsa_signature,
)


# Generate a test RSA key pair for testing
def generate_test_keypair() -> tuple[rsa.RSAPrivateKey, str]:
    """Generate a test RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1,
    ).decode("utf-8")
    return private_key, pem


class TestLoadRsaPublicKey:
    """Tests for load_rsa_public_key function."""

    def test_load_valid_pem_key(self) -> None:
        """Test loading a valid PEM-encoded RSA public key."""
        _, pem = generate_test_keypair()
        key = load_rsa_public_key(pem)
        assert key is not None

    def test_load_key_without_headers(self) -> None:
        """Test loading a key without PEM headers."""
        _, pem = generate_test_keypair()
        # Remove headers
        lines = pem.strip().split("\n")
        base64_only = "\n".join(lines[1:-1])
        key = load_rsa_public_key(base64_only)
        assert key is not None

    def test_load_invalid_key(self) -> None:
        """Test loading invalid key data raises ValueError."""
        with pytest.raises(ValueError):
            load_rsa_public_key("not a valid key")


class TestComputeRsaKeyFingerprint:
    """Tests for compute_rsa_key_fingerprint function."""

    def test_fingerprint_format(self) -> None:
        """Test that fingerprint is uppercase hex."""
        _, pem = generate_test_keypair()
        fingerprint = compute_rsa_key_fingerprint(pem)
        assert fingerprint.isupper()
        assert all(c in "0123456789ABCDEF" for c in fingerprint)
        assert len(fingerprint) == 40  # SHA1 = 20 bytes = 40 hex chars

    def test_same_key_same_fingerprint(self) -> None:
        """Test that same key produces same fingerprint."""
        _, pem = generate_test_keypair()
        fp1 = compute_rsa_key_fingerprint(pem)
        fp2 = compute_rsa_key_fingerprint(pem)
        assert fp1 == fp2

    def test_different_keys_different_fingerprints(self) -> None:
        """Test that different keys produce different fingerprints."""
        _, pem1 = generate_test_keypair()
        _, pem2 = generate_test_keypair()
        fp1 = compute_rsa_key_fingerprint(pem1)
        fp2 = compute_rsa_key_fingerprint(pem2)
        assert fp1 != fp2


def create_tor_signature(
    private_key: rsa.RSAPrivateKey, data: bytes, algorithm: str = "sha1"
) -> bytes:
    """Create a signature in Tor's format (PKCS#1 v1.5 with raw hash, no DigestInfo OID)."""
    import hashlib

    # Compute the hash
    if algorithm == "sha256":
        hash_bytes = hashlib.sha256(data).digest()
    else:
        hash_bytes = hashlib.sha1(data).digest()

    # Get key size
    key_size_bytes = private_key.key_size // 8

    # Build PKCS#1 v1.5 padded message: 00 01 [FF...] 00 [hash]
    # Calculate padding length
    padding_len = key_size_bytes - 3 - len(hash_bytes)  # 3 = 00 01 ... 00

    # Build the padded message
    padded = bytes([0, 1]) + (b"\xff" * padding_len) + bytes([0]) + hash_bytes

    # RSA sign (raw RSA operation)
    padded_int = int.from_bytes(padded, "big")
    numbers = private_key.private_numbers()
    signature_int = pow(padded_int, numbers.d, numbers.public_numbers.n)
    signature = signature_int.to_bytes(key_size_bytes, "big")

    return signature


class TestVerifyRsaSignature:
    """Tests for verify_rsa_signature function.

    Note: Tor uses a non-standard PKCS#1 v1.5 format with raw hashes
    (no DigestInfo OID), so we need to create signatures in that format.
    """

    def test_valid_signature_sha1(self) -> None:
        """Test verifying a valid SHA1 signature in Tor format."""
        private_key, pem = generate_test_keypair()
        data = b"test data to sign"

        # Create signature in Tor's format (raw hash, no DigestInfo OID)
        signature = create_tor_signature(private_key, data, "sha1")

        # Verify
        public_key = load_rsa_public_key(pem)
        assert verify_rsa_signature(public_key, signature, data, "sha1") is True

    def test_valid_signature_sha256(self) -> None:
        """Test verifying a valid SHA256 signature in Tor format."""
        private_key, pem = generate_test_keypair()
        data = b"test data to sign"

        # Create signature in Tor's format (raw hash, no DigestInfo OID)
        signature = create_tor_signature(private_key, data, "sha256")

        # Verify
        public_key = load_rsa_public_key(pem)
        assert verify_rsa_signature(public_key, signature, data, "sha256") is True

    def test_invalid_signature(self) -> None:
        """Test that invalid signature returns False."""
        _, pem = generate_test_keypair()
        public_key = load_rsa_public_key(pem)
        data = b"test data"
        bad_signature = b"not a valid signature"

        assert verify_rsa_signature(public_key, bad_signature, data, "sha1") is False

    def test_wrong_data(self) -> None:
        """Test that signature doesn't verify with wrong data."""
        private_key, pem = generate_test_keypair()
        data = b"original data"
        wrong_data = b"different data"

        signature = create_tor_signature(private_key, data, "sha1")

        public_key = load_rsa_public_key(pem)
        assert verify_rsa_signature(public_key, signature, wrong_data, "sha1") is False


class TestVerifyConsensusSignature:
    """Tests for verify_consensus_signature function."""

    def test_valid_signature_with_pem_headers(self) -> None:
        """Test verifying signature with PEM-style headers."""
        private_key, pem = generate_test_keypair()
        data = b"network-status-version 3\ntest data\n"

        # Create signature in Tor's format
        signature = create_tor_signature(private_key, data, "sha1")

        sig_b64 = (
            "-----BEGIN SIGNATURE-----\n"
            + base64.b64encode(signature).decode()
            + "\n-----END SIGNATURE-----"
        )

        assert verify_consensus_signature(pem, sig_b64, data, "sha1") is True

    def test_invalid_key(self) -> None:
        """Test that invalid key returns False."""
        assert verify_consensus_signature("bad key", "sig", b"data", "sha1") is False


class TestExtractSignedPortion:
    """Tests for extract_signed_portion function.

    Note: The signed portion is the same for all signatures in a consensus document.
    The identity parameter is kept for API compatibility but is ignored.
    According to Tor spec, the signed portion is from 'network-status-version'
    through the space after 'directory-signature' (sha1) or
    'directory-signature sha256' (sha256).
    """

    def test_extract_simple_document(self) -> None:
        """Test extracting signed portion from simple document."""
        doc = """network-status-version 3
vote-status consensus
directory-signature ABC123 DEF456
-----BEGIN SIGNATURE-----
dGVzdA==
-----END SIGNATURE-----
"""
        signed = extract_signed_portion(doc, "ABC123", "sha1")
        assert signed is not None
        assert signed.startswith(b"network-status-version")
        # The signed portion ends at "directory-signature " (with space)
        assert signed.endswith(b"directory-signature ")

    def test_extract_with_algorithm(self) -> None:
        """Test extracting with algorithm in signature line.

        The signed portion always ends at 'directory-signature ' regardless
        of what algorithm is specified in the signature line. The algorithm
        only indicates which hash to use on the signed portion.
        """
        doc = """network-status-version 3
vote-status consensus
directory-signature sha256 ABC123 DEF456
-----BEGIN SIGNATURE-----
dGVzdA==
-----END SIGNATURE-----
"""
        signed = extract_signed_portion(doc, "ABC123", "sha256")
        assert signed is not None
        # The signed portion ends at "directory-signature " (with space)
        # NOT at "directory-signature sha256 " - the algorithm is part of the
        # unsigned portion
        assert signed.endswith(b"directory-signature ")

    def test_extract_multiple_signatures(self) -> None:
        """Test extracting when multiple signatures exist.

        The signed portion uses the FIRST occurrence of the end marker,
        regardless of which identity is specified.
        """
        doc = """network-status-version 3
vote-status consensus
directory-signature FIRST111 KEY111
-----BEGIN SIGNATURE-----
c2lnMQ==
-----END SIGNATURE-----
directory-signature SECOND22 KEY222
-----BEGIN SIGNATURE-----
c2lnMg==
-----END SIGNATURE-----
"""
        # Both identities should return the same signed portion
        # (ending at the FIRST "directory-signature ")
        signed1 = extract_signed_portion(doc, "FIRST111", "sha1")
        signed2 = extract_signed_portion(doc, "SECOND22", "sha1")
        assert signed1 is not None
        assert signed2 is not None
        assert signed1 == signed2
        assert signed1.endswith(b"directory-signature ")

    def test_extract_identity_ignored(self) -> None:
        """Test that identity parameter is ignored."""
        doc = """network-status-version 3
directory-signature ABC123 DEF456
"""
        # Identity is ignored, so any value (including non-existent) works
        signed = extract_signed_portion(doc, "NOTFOUND", "sha1")
        assert signed is not None
        assert signed.endswith(b"directory-signature ")

    def test_extract_no_version(self) -> None:
        """Test that missing network-status-version returns None."""
        doc = """vote-status consensus
directory-signature ABC123 DEF456
"""
        signed = extract_signed_portion(doc, "ABC123", "sha1")
        assert signed is None

    def test_extract_no_signature(self) -> None:
        """Test that missing directory-signature returns None."""
        doc = """network-status-version 3
vote-status consensus
"""
        signed = extract_signed_portion(doc, "ABC123", "sha1")
        assert signed is None
