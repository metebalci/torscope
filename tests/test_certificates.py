"""Tests for key certificate parsing."""

from datetime import datetime

from torscope.directory.certificates import KeyCertificateParser
from torscope.directory.models import KeyCertificate

# Sample key certificate for testing
SAMPLE_CERTIFICATE = """dir-key-certificate-version 3
fingerprint ABC123DEF456789012345678901234567890ABCD
dir-key-published 2024-01-15 12:00:00
dir-key-expires 2025-01-15 12:00:00
dir-address 192.0.2.1:9030
dir-identity-key
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA0cJv7O1G+JvKsEg6gWGFHn3D2tCw3VE9YCp9C7g5QxULzPPsOb3f
zCYPqX1Jv9HpMhQoFPLnL5Jj6VQq4yFbYpZc0q0Z8VaRfSdGqh7jN5P3M5k1JVKW
+gE5Y5wPEQl5M5A2J8K3S1+V0qP7R4B1nL2gQ5K0Z8X7H9Y6C4O3F1E2D3A4B5C6
D7E8F9G0H1I2J3K4L5M6N7O8P9Q0R1S2T3U4V5W6X7Y8Z9a0b1c2d3e4f5g6h7i8
j9k0l1m2n3o4p5q6r7s8t9u0v1w2x3y4z5A6B7C8D9E0F1G2H3I4J5K6L7M8N9O0
P1Q2R3S4T5U6V7W8X9Y0ZZIDAQAB
-----END RSA PUBLIC KEY-----
dir-signing-key
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA1dKv8O2G+JvKsEg6gWGFHn3D2tCw3VE9YCp9C7g5QxULzPPsOb3f
zCYPqX1Jv9HpMhQoFPLnL5Jj6VQq4yFbYpZc0q0Z8VaRfSdGqh7jN5P3M5k1JVKW
+gE5Y5wPEQl5M5A2J8K3S1+V0qP7R4B1nL2gQ5K0Z8X7H9Y6C4O3F1E2D3A4B5C6
D7E8F9G0H1I2J3K4L5M6N7O8P9Q0R1S2T3U4V5W6X7Y8Z9a0b1c2d3e4f5g6h7i8
j9k0l1m2n3o4p5q6r7s8t9u0v1w2x3y4z5A6B7C8D9E0F1G2H3I4J5K6L7M8N9O0
P1Q2R3S4T5U6V7W8X9Y0ZZSIGNING
-----END RSA PUBLIC KEY-----
dir-key-crosscert
-----BEGIN ID SIGNATURE-----
dGVzdGNyb3NzY2VydA==
-----END ID SIGNATURE-----
dir-key-certification
-----BEGIN SIGNATURE-----
dGVzdGNlcnRpZmljYXRpb24=
-----END SIGNATURE-----
"""


class TestKeyCertificateParser:
    """Tests for KeyCertificateParser class."""

    def test_parse_single_certificate(self) -> None:
        """Test parsing a single certificate."""
        certs = KeyCertificateParser.parse(SAMPLE_CERTIFICATE.encode("utf-8"))
        assert len(certs) == 1

        cert = certs[0]
        assert cert.version == 3
        assert cert.fingerprint == "ABC123DEF456789012345678901234567890ABCD"
        assert cert.address == "192.0.2.1:9030"
        assert "RSA PUBLIC KEY" in cert.identity_key
        assert "RSA PUBLIC KEY" in cert.signing_key

    def test_parse_datetime_fields(self) -> None:
        """Test parsing datetime fields."""
        certs = KeyCertificateParser.parse(SAMPLE_CERTIFICATE.encode("utf-8"))
        cert = certs[0]

        assert cert.published.year == 2024
        assert cert.published.month == 1
        assert cert.published.day == 15
        assert cert.expires.year == 2025

    def test_parse_multiple_certificates(self) -> None:
        """Test parsing multiple certificates."""
        multi_cert = (
            SAMPLE_CERTIFICATE
            + "\n"
            + SAMPLE_CERTIFICATE.replace(
                "ABC123DEF456789012345678901234567890ABCD",
                "XYZ789DEF456789012345678901234567890WXYZ",
            )
        )
        certs = KeyCertificateParser.parse(multi_cert.encode("utf-8"))
        assert len(certs) == 2
        assert certs[0].fingerprint != certs[1].fingerprint

    def test_parse_empty_content(self) -> None:
        """Test parsing empty content."""
        certs = KeyCertificateParser.parse(b"")
        assert certs == []

    def test_parse_invalid_content(self) -> None:
        """Test parsing invalid content."""
        certs = KeyCertificateParser.parse(b"not a certificate")
        assert certs == []

    def test_parse_missing_required_fields(self) -> None:
        """Test that missing required fields returns empty."""
        incomplete = """dir-key-certificate-version 3
fingerprint ABC123DEF456789012345678901234567890ABCD
dir-key-published 2024-01-15 12:00:00
"""
        certs = KeyCertificateParser.parse(incomplete.encode("utf-8"))
        # Should be empty because identity_key and signing_key are missing
        assert certs == []

    def test_parse_crosscert_and_certification(self) -> None:
        """Test parsing cross-cert and certification signatures."""
        certs = KeyCertificateParser.parse(SAMPLE_CERTIFICATE.encode("utf-8"))
        cert = certs[0]

        assert cert.dir_key_crosscert is not None
        assert "ID SIGNATURE" in cert.dir_key_crosscert
        assert cert.dir_key_certification is not None
        assert "SIGNATURE" in cert.dir_key_certification


class TestKeyCertificateModel:
    """Tests for KeyCertificate model."""

    def test_key_certificate_creation(self) -> None:
        """Test creating a KeyCertificate."""
        cert = KeyCertificate(
            version=3,
            fingerprint="ABCD1234",
            published=datetime(2024, 1, 1),
            expires=datetime(2025, 1, 1),
            identity_key="-----BEGIN RSA PUBLIC KEY-----\ntest\n-----END RSA PUBLIC KEY-----",
            signing_key="-----BEGIN RSA PUBLIC KEY-----\ntest\n-----END RSA PUBLIC KEY-----",
        )
        assert cert.version == 3
        assert cert.fingerprint == "ABCD1234"
