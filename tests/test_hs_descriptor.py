"""Tests for hidden service descriptor parsing and decryption."""

import base64
import struct
from unittest.mock import MagicMock, patch

import pytest

from torscope.directory.hs_descriptor import (
    HSDescriptor,
    HSDescriptorOuter,
    IntroductionPoint,
    _decrypt_layer,
    _parse_first_layer,
    _parse_link_specifiers,
    _parse_second_layer,
    decrypt_inner_layer,
    decrypt_outer_layer,
    decrypt_descriptor,
    parse_hs_descriptor,
    S_KEY_LEN,
    S_IV_LEN,
    MAC_KEY_LEN,
)


# =============================================================================
# Sample Test Data
# =============================================================================

# Minimal valid HS descriptor (outer layer)
# Using valid base64 for all fields
SAMPLE_OUTER_DESCRIPTOR = """hs-descriptor 3
descriptor-lifetime 180
descriptor-signing-key-cert
-----BEGIN ED25519 CERT-----
AQQABrWpAYd7cpSBCOZuHN8WQU5Y7xFp3YoAF6I2nnIACCGwCEKjAQAgBABXv7iK
Y5TmXxmIwp3vJWiPLgx0iqFD0Y8w5QOgBQZ5SFnVwLJKqqq7oiLyBz0tJtKgEaLN
FaGJCKAhMjAi4gdeLRRCGxqWPT4=
-----END ED25519 CERT-----
revision-counter 12345
superencrypted
-----BEGIN MESSAGE-----
dGVzdCBzdXBlcmVuY3J5cHRlZCBibG9i
-----END MESSAGE-----
signature c2lnbmF0dXJlX2RhdGFfZm9yX3Rlc3Rpbmdfb25seQ
"""


class TestHSDescriptorOuterParse:
    """Tests for HSDescriptorOuter.parse()."""

    def test_parse_valid_descriptor(self):
        """Test parsing a valid outer descriptor."""
        outer = HSDescriptorOuter.parse(SAMPLE_OUTER_DESCRIPTOR)

        assert outer.version == 3
        assert outer.descriptor_lifetime == 180
        assert outer.revision_counter == 12345
        assert outer.signing_key_cert is not None
        assert outer.superencrypted_blob == b"test superencrypted blob"
        assert outer.signature is not None
        assert outer.raw_descriptor == SAMPLE_OUTER_DESCRIPTOR

    def test_parse_missing_version(self):
        """Test parsing fails without version."""
        content = """descriptor-lifetime 180
revision-counter 1
superencrypted
-----BEGIN MESSAGE-----
dGVzdA==
-----END MESSAGE-----
signature abcd
"""
        with pytest.raises(ValueError, match="Missing hs-descriptor version"):
            HSDescriptorOuter.parse(content)

    def test_parse_unsupported_version(self):
        """Test parsing fails with unsupported version."""
        content = """hs-descriptor 2
descriptor-lifetime 180
revision-counter 1
superencrypted
-----BEGIN MESSAGE-----
dGVzdA==
-----END MESSAGE-----
signature abcd
"""
        with pytest.raises(ValueError, match="Unsupported descriptor version: 2"):
            HSDescriptorOuter.parse(content)

    def test_parse_missing_lifetime(self):
        """Test parsing fails without descriptor-lifetime."""
        content = """hs-descriptor 3
revision-counter 1
superencrypted
-----BEGIN MESSAGE-----
dGVzdA==
-----END MESSAGE-----
signature abcd
"""
        with pytest.raises(ValueError, match="Missing descriptor-lifetime"):
            HSDescriptorOuter.parse(content)

    def test_parse_missing_signing_cert(self):
        """Test parsing fails without signing key cert."""
        content = """hs-descriptor 3
descriptor-lifetime 180
revision-counter 1
superencrypted
-----BEGIN MESSAGE-----
dGVzdA==
-----END MESSAGE-----
signature abcd
"""
        with pytest.raises(ValueError, match="Missing descriptor-signing-key-cert"):
            HSDescriptorOuter.parse(content)

    def test_parse_missing_revision_counter(self):
        """Test parsing fails without revision-counter."""
        content = """hs-descriptor 3
descriptor-lifetime 180
descriptor-signing-key-cert
-----BEGIN ED25519 CERT-----
dGVzdA==
-----END ED25519 CERT-----
superencrypted
-----BEGIN MESSAGE-----
dGVzdA==
-----END MESSAGE-----
signature abcd
"""
        with pytest.raises(ValueError, match="Missing revision-counter"):
            HSDescriptorOuter.parse(content)

    def test_parse_missing_superencrypted(self):
        """Test parsing fails without superencrypted blob."""
        content = """hs-descriptor 3
descriptor-lifetime 180
descriptor-signing-key-cert
-----BEGIN ED25519 CERT-----
dGVzdA==
-----END ED25519 CERT-----
revision-counter 1
signature abcd
"""
        with pytest.raises(ValueError, match="Missing superencrypted blob"):
            HSDescriptorOuter.parse(content)

    def test_parse_missing_signature(self):
        """Test parsing fails without signature."""
        content = """hs-descriptor 3
descriptor-lifetime 180
descriptor-signing-key-cert
-----BEGIN ED25519 CERT-----
dGVzdA==
-----END ED25519 CERT-----
revision-counter 1
superencrypted
-----BEGIN MESSAGE-----
dGVzdA==
-----END MESSAGE-----
"""
        with pytest.raises(ValueError, match="Missing signature"):
            HSDescriptorOuter.parse(content)

    def test_parse_signature_padding(self):
        """Test signature base64 padding is handled."""
        # Signature with different lengths (testing padding logic)
        content = """hs-descriptor 3
descriptor-lifetime 180
descriptor-signing-key-cert
-----BEGIN ED25519 CERT-----
dGVzdA==
-----END ED25519 CERT-----
revision-counter 1
superencrypted
-----BEGIN MESSAGE-----
dGVzdA==
-----END MESSAGE-----
signature abc
"""
        outer = HSDescriptorOuter.parse(content)
        assert outer.signature is not None


class TestIntroductionPoint:
    """Tests for IntroductionPoint dataclass."""

    def test_ip_address_from_ipv4_specifier(self):
        """Test extracting IPv4 address from link specifiers."""
        ip = IntroductionPoint(
            link_specifiers=[
                (0, bytes([192, 0, 2, 1, 0x1F, 0x90]))  # 192.0.2.1:8080
            ]
        )
        assert ip.ip_address == "192.0.2.1"

    def test_port_from_ipv4_specifier(self):
        """Test extracting port from IPv4 link specifier."""
        ip = IntroductionPoint(
            link_specifiers=[
                (0, bytes([192, 0, 2, 1, 0x1F, 0x90]))  # port 8080
            ]
        )
        assert ip.port == 8080

    def test_port_from_ipv6_specifier(self):
        """Test extracting port from IPv6 link specifier."""
        ipv6_data = bytes(16) + bytes([0x01, 0xBB])  # ::0:443
        ip = IntroductionPoint(link_specifiers=[(1, ipv6_data)])
        assert ip.port == 443

    def test_fingerprint_from_legacy_id(self):
        """Test extracting fingerprint from legacy ID specifier."""
        fp_bytes = bytes.fromhex("ABCD" * 10)  # 20 bytes
        ip = IntroductionPoint(link_specifiers=[(2, fp_bytes)])
        assert ip.fingerprint == "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD"

    def test_ip_address_missing(self):
        """Test ip_address returns None when no IPv4 specifier."""
        ip = IntroductionPoint(link_specifiers=[(2, b"x" * 20)])
        assert ip.ip_address is None

    def test_port_missing(self):
        """Test port returns None when no address specifier."""
        ip = IntroductionPoint(link_specifiers=[(2, b"x" * 20)])
        assert ip.port is None

    def test_fingerprint_missing(self):
        """Test fingerprint returns None when no legacy ID specifier."""
        ip = IntroductionPoint(
            link_specifiers=[(0, bytes([192, 0, 2, 1, 0, 80]))]
        )
        assert ip.fingerprint is None

    def test_wrong_length_specifiers_ignored(self):
        """Test specifiers with wrong length are ignored."""
        # IPv4 specifier with wrong length
        ip = IntroductionPoint(
            link_specifiers=[
                (0, b"short"),  # Should be 6 bytes
                (2, b"short"),  # Should be 20 bytes
            ]
        )
        assert ip.ip_address is None
        assert ip.fingerprint is None


class TestParseLinkSpecifiers:
    """Tests for _parse_link_specifiers()."""

    def test_parse_single_ipv4(self):
        """Test parsing single IPv4 link specifier."""
        # NSPEC=1, TYPE=0, LEN=6, DATA=192.0.2.1:8080
        data = bytes([1, 0, 6, 192, 0, 2, 1, 0x1F, 0x90])
        specs = _parse_link_specifiers(data)

        assert len(specs) == 1
        assert specs[0][0] == 0  # TLS_TCP_IPV4
        assert specs[0][1] == bytes([192, 0, 2, 1, 0x1F, 0x90])

    def test_parse_multiple_specifiers(self):
        """Test parsing multiple link specifiers."""
        # NSPEC=2
        # Spec1: TYPE=0, LEN=6 (IPv4)
        # Spec2: TYPE=2, LEN=20 (legacy ID)
        data = bytes([2])
        data += bytes([0, 6, 192, 0, 2, 1, 0, 80])
        data += bytes([2, 20]) + b"A" * 20

        specs = _parse_link_specifiers(data)

        assert len(specs) == 2
        assert specs[0][0] == 0
        assert specs[1][0] == 2
        assert len(specs[1][1]) == 20

    def test_parse_empty_data(self):
        """Test parsing empty data."""
        specs = _parse_link_specifiers(b"")
        assert specs == []

    def test_parse_truncated_header(self):
        """Test parsing truncated data stops gracefully."""
        # NSPEC=2 but only partial data
        data = bytes([2, 0, 6, 192, 0, 2])  # Incomplete IPv4 specifier
        specs = _parse_link_specifiers(data)
        # Should parse what it can, stop on truncation
        assert len(specs) == 0  # First spec truncated

    def test_parse_ed25519_specifier(self):
        """Test parsing Ed25519 identity specifier."""
        # NSPEC=1, TYPE=3, LEN=32, DATA=32 bytes
        data = bytes([1, 3, 32]) + b"X" * 32
        specs = _parse_link_specifiers(data)

        assert len(specs) == 1
        assert specs[0][0] == 3  # Ed25519 identity
        assert len(specs[0][1]) == 32


class TestDecryptLayer:
    """Tests for _decrypt_layer()."""

    def test_blob_too_small(self):
        """Test that too-small blobs are rejected."""
        # Minimum is 48 bytes (16 salt + 32 mac)
        with pytest.raises(ValueError, match="too small"):
            _decrypt_layer(
                b"x" * 47,  # Too small
                b"secret" * 6,  # secret_data
                b"s" * 32,  # subcredential
                1,  # revision_counter
                b"test-constant",
            )

    def test_mac_verification_fails(self):
        """Test MAC verification failure is reported."""
        # Create a blob with wrong MAC
        salt = b"s" * 16
        ciphertext = b"c" * 100
        wrong_mac = b"m" * 32
        blob = salt + ciphertext + wrong_mac

        with pytest.raises(ValueError, match="MAC verification failed"):
            _decrypt_layer(
                blob,
                b"secret" * 6,
                b"subcred" * 5,  # Need at least 32 bytes
                1,
                b"test-constant",
            )


class TestDecryptOuterLayer:
    """Tests for decrypt_outer_layer()."""

    def test_calls_decrypt_layer_correctly(self):
        """Test decrypt_outer_layer uses correct parameters."""
        # We can't easily test the full decryption without real data,
        # but we can verify it's called with the right constant
        with patch("torscope.directory.hs_descriptor._decrypt_layer") as mock:
            mock.return_value = b"decrypted"

            decrypt_outer_layer(
                b"x" * 100,  # blob
                b"b" * 32,  # blinded_key
                b"s" * 32,  # subcredential
                12345,  # revision_counter
            )

            mock.assert_called_once()
            args = mock.call_args[0]
            assert args[4] == b"hsdir-superencrypted-data"


class TestDecryptInnerLayer:
    """Tests for decrypt_inner_layer()."""

    def test_without_cookie(self):
        """Test inner layer decryption without descriptor cookie."""
        with patch("torscope.directory.hs_descriptor._decrypt_layer") as mock:
            mock.return_value = b"decrypted"

            decrypt_inner_layer(
                b"x" * 100,
                b"b" * 32,
                b"s" * 32,
                12345,
                descriptor_cookie=None,
            )

            mock.assert_called_once()
            args = mock.call_args[0]
            # secret_data should be just blinded_key
            assert args[1] == b"b" * 32
            assert args[4] == b"hsdir-encrypted-data"

    def test_with_cookie(self):
        """Test inner layer decryption with descriptor cookie."""
        with patch("torscope.directory.hs_descriptor._decrypt_layer") as mock:
            mock.return_value = b"decrypted"

            decrypt_inner_layer(
                b"x" * 100,
                b"b" * 32,
                b"s" * 32,
                12345,
                descriptor_cookie=b"c" * 32,
            )

            mock.assert_called_once()
            args = mock.call_args[0]
            # secret_data should be blinded_key + cookie
            assert args[1] == b"b" * 32 + b"c" * 32


class TestParseFirstLayer:
    """Tests for _parse_first_layer()."""

    def test_extracts_encrypted_blob(self):
        """Test extracting encrypted blob from first layer."""
        plaintext = b"""desc-auth-type x25519
desc-auth-ephemeral-key abc123
auth-client client1 data1 data2
encrypted
-----BEGIN MESSAGE-----
dGVzdCBlbmNyeXB0ZWQ=
-----END MESSAGE-----
"""
        blob, text = _parse_first_layer(plaintext)
        assert blob == b"test encrypted"
        assert "desc-auth-type" in text

    def test_missing_encrypted_section(self):
        """Test error when encrypted section is missing."""
        plaintext = b"""desc-auth-type x25519
auth-client client1 data1 data2
"""
        with pytest.raises(ValueError, match="No encrypted blob found"):
            _parse_first_layer(plaintext)


class TestParseSecondLayer:
    """Tests for _parse_second_layer()."""

    def test_parse_introduction_points(self):
        """Test parsing introduction points from second layer."""
        # Create link specifier data: NSPEC=1, TYPE=0, LEN=6, IPv4
        link_spec = bytes([1, 0, 6, 192, 0, 2, 1, 0x1F, 0x90])
        link_spec_b64 = base64.b64encode(link_spec).decode("ascii").rstrip("=")

        # Create ntor key (32 bytes)
        ntor_key = b"n" * 32
        ntor_key_b64 = base64.b64encode(ntor_key).decode("ascii").rstrip("=")

        plaintext = f"""create2-formats 2
introduction-point {link_spec_b64}
onion-key ntor {ntor_key_b64}
auth-key
-----BEGIN ED25519 CERT-----
{base64.b64encode(b"cert" * 20).decode()}
-----END ED25519 CERT-----
""".encode()

        intro_points, pow_params = _parse_second_layer(plaintext)

        assert len(intro_points) == 1
        assert intro_points[0].ip_address == "192.0.2.1"
        assert intro_points[0].port == 8080
        assert intro_points[0].onion_key_ntor == ntor_key
        assert pow_params is None

    def test_parse_multiple_intro_points(self):
        """Test parsing multiple introduction points."""
        link_spec = bytes([1, 0, 6, 192, 0, 2, 1, 0, 80])
        link_spec_b64 = base64.b64encode(link_spec).decode("ascii").rstrip("=")

        plaintext = f"""create2-formats 2
introduction-point {link_spec_b64}
onion-key ntor {base64.b64encode(b"k" * 32).decode().rstrip("=")}
introduction-point {link_spec_b64}
onion-key ntor {base64.b64encode(b"j" * 32).decode().rstrip("=")}
""".encode()

        intro_points, _ = _parse_second_layer(plaintext)
        assert len(intro_points) == 2

    def test_parse_enc_key(self):
        """Test parsing enc-key field."""
        link_spec = bytes([1, 0, 6, 192, 0, 2, 1, 0, 80])
        link_spec_b64 = base64.b64encode(link_spec).decode("ascii").rstrip("=")
        enc_key = b"e" * 32
        enc_key_b64 = base64.b64encode(enc_key).decode("ascii").rstrip("=")

        plaintext = f"""create2-formats 2
introduction-point {link_spec_b64}
enc-key ntor {enc_key_b64}
""".encode()

        intro_points, _ = _parse_second_layer(plaintext)
        assert intro_points[0].enc_key == enc_key

    def test_parse_pow_params(self):
        """Test parsing pow-params field."""
        link_spec = bytes([1, 0, 6, 192, 0, 2, 1, 0, 80])
        link_spec_b64 = base64.b64encode(link_spec).decode("ascii").rstrip("=")
        seed = base64.b64encode(b"s" * 32).decode("ascii")

        plaintext = f"""create2-formats 2
pow-params v1 {seed} 1000 2024-12-31T23:59:59
introduction-point {link_spec_b64}
""".encode()

        with patch("torscope.directory.hs_descriptor.PowParams.parse") as mock_parse:
            mock_params = MagicMock()
            mock_parse.return_value = mock_params

            _, pow_params = _parse_second_layer(plaintext)
            assert pow_params is mock_params


class TestParseHsDescriptor:
    """Tests for parse_hs_descriptor()."""

    def test_parse_without_keys(self):
        """Test parsing without decryption keys."""
        descriptor = parse_hs_descriptor(SAMPLE_OUTER_DESCRIPTOR)

        assert descriptor.outer.version == 3
        assert descriptor.decrypted is False
        assert descriptor.decryption_error == "Keys not provided for decryption"
        assert descriptor.introduction_points == []

    def test_parse_with_keys_success(self):
        """Test parsing with decryption keys (mocked)."""
        with patch("torscope.directory.hs_descriptor.decrypt_descriptor") as mock:
            mock.return_value = ([], None)

            descriptor = parse_hs_descriptor(
                SAMPLE_OUTER_DESCRIPTOR,
                blinded_key=b"b" * 32,
                subcredential=b"s" * 32,
            )

            assert descriptor.decrypted is True
            assert descriptor.decryption_error is None

    def test_parse_with_keys_failure(self):
        """Test parsing when decryption fails."""
        with patch("torscope.directory.hs_descriptor.decrypt_descriptor") as mock:
            mock.side_effect = ValueError("Decryption failed")

            descriptor = parse_hs_descriptor(
                SAMPLE_OUTER_DESCRIPTOR,
                blinded_key=b"b" * 32,
                subcredential=b"s" * 32,
            )

            assert descriptor.decrypted is False
            assert "Decryption failed" in descriptor.decryption_error


class TestDecryptDescriptor:
    """Tests for decrypt_descriptor()."""

    def test_client_auth_required_error(self):
        """Test error when client auth is required but not provided."""
        with patch("torscope.directory.hs_descriptor.decrypt_outer_layer") as mock_outer:
            mock_outer.return_value = b"""desc-auth-type x25519
encrypted
-----BEGIN MESSAGE-----
dGVzdA==
-----END MESSAGE-----
"""
            with patch("torscope.directory.hs_descriptor.decrypt_inner_layer") as mock_inner:
                mock_inner.side_effect = ValueError("MAC verification failed")

                with patch("torscope.directory.client_auth.get_descriptor_cookie") as mock_cookie:
                    mock_cookie.return_value = None

                    with pytest.raises(ValueError, match="Client authorization required"):
                        decrypt_descriptor(
                            b"x" * 100,
                            b"b" * 32,
                            b"s" * 32,
                            1,
                        )

    def test_client_key_not_authorized(self):
        """Test error when client key is not authorized."""
        with patch("torscope.directory.hs_descriptor.decrypt_outer_layer") as mock_outer:
            mock_outer.return_value = b"""desc-auth-type x25519
encrypted
-----BEGIN MESSAGE-----
dGVzdA==
-----END MESSAGE-----
"""
            with patch("torscope.directory.hs_descriptor.decrypt_inner_layer") as mock_inner:
                mock_inner.side_effect = ValueError("MAC verification failed")

                with patch("torscope.directory.client_auth.get_descriptor_cookie") as mock_cookie:
                    mock_cookie.return_value = None

                    with pytest.raises(ValueError, match="Client key not authorized"):
                        decrypt_descriptor(
                            b"x" * 100,
                            b"b" * 32,
                            b"s" * 32,
                            1,
                            client_privkey=b"p" * 32,
                        )

    def test_successful_decryption(self):
        """Test successful two-layer decryption."""
        link_spec = bytes([1, 0, 6, 192, 0, 2, 1, 0, 80])
        link_spec_b64 = base64.b64encode(link_spec).decode("ascii").rstrip("=")

        second_layer = f"""create2-formats 2
introduction-point {link_spec_b64}
onion-key ntor {base64.b64encode(b"k" * 32).decode().rstrip("=")}
""".encode()

        with patch("torscope.directory.hs_descriptor.decrypt_outer_layer") as mock_outer:
            mock_outer.return_value = b"""desc-auth-type x25519
encrypted
-----BEGIN MESSAGE-----
dGVzdA==
-----END MESSAGE-----
"""
            with patch("torscope.directory.hs_descriptor.decrypt_inner_layer") as mock_inner:
                mock_inner.return_value = second_layer

                with patch("torscope.directory.client_auth.get_descriptor_cookie") as mock_cookie:
                    mock_cookie.return_value = None

                    intro_points, pow_params = decrypt_descriptor(
                        b"x" * 100,
                        b"b" * 32,
                        b"s" * 32,
                        1,
                    )

                    assert len(intro_points) == 1
                    assert intro_points[0].ip_address == "192.0.2.1"


class TestHSDescriptor:
    """Tests for HSDescriptor dataclass."""

    def test_default_values(self):
        """Test HSDescriptor default values."""
        outer = HSDescriptorOuter(
            version=3,
            descriptor_lifetime=180,
            signing_key_cert=b"cert",
            revision_counter=1,
            superencrypted_blob=b"blob",
            signature=b"sig",
        )
        desc = HSDescriptor(outer=outer)

        assert desc.introduction_points == []
        assert desc.decrypted is False
        assert desc.decryption_error is None
        assert desc.pow_params is None

    def test_with_intro_points(self):
        """Test HSDescriptor with introduction points."""
        outer = HSDescriptorOuter(
            version=3,
            descriptor_lifetime=180,
            signing_key_cert=b"cert",
            revision_counter=1,
            superencrypted_blob=b"blob",
            signature=b"sig",
        )
        ip = IntroductionPoint(
            link_specifiers=[(0, bytes([192, 0, 2, 1, 0, 80]))]
        )
        desc = HSDescriptor(
            outer=outer,
            introduction_points=[ip],
            decrypted=True,
        )

        assert len(desc.introduction_points) == 1
        assert desc.decrypted is True
