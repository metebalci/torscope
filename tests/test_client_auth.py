"""Tests for v3 hidden service client authorization."""

import base64
import os
import tempfile
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from torscope.directory.client_auth import (
    AuthClientEntry,
    ClientAuthData,
    _decode_base64,
    decrypt_descriptor_cookie,
    derive_client_id_and_cookie_key,
    get_descriptor_cookie,
    parse_client_auth_data,
    parse_client_auth_key,
    read_client_auth_file,
)


# =============================================================================
# Test Data
# =============================================================================

# Generate a deterministic test key (32 bytes)
TEST_PRIVKEY = bytes(range(32))

# Base32 encoding of TEST_PRIVKEY
TEST_PRIVKEY_B32 = base64.b32encode(TEST_PRIVKEY).decode().rstrip("=")


# =============================================================================
# Tests for parse_client_auth_key()
# =============================================================================


class TestParseClientAuthKey:
    """Tests for parse_client_auth_key()."""

    def test_parse_just_key(self):
        """Test parsing just the base32 key."""
        result = parse_client_auth_key(TEST_PRIVKEY_B32)
        assert result == TEST_PRIVKEY

    def test_parse_standard_tor_format(self):
        """Test parsing standard Tor format: descriptor:x25519:<key>."""
        key_str = f"descriptor:x25519:{TEST_PRIVKEY_B32}"
        result = parse_client_auth_key(key_str)
        assert result == TEST_PRIVKEY

    def test_parse_full_tor_format(self):
        """Test parsing full Tor file format: <address>:descriptor:x25519:<key>."""
        key_str = f"duckduckgo.onion:descriptor:x25519:{TEST_PRIVKEY_B32}"
        result = parse_client_auth_key(key_str)
        assert result == TEST_PRIVKEY

    def test_parse_case_insensitive_prefix(self):
        """Test that prefix matching is case insensitive."""
        key_str = f"DESCRIPTOR:X25519:{TEST_PRIVKEY_B32}"
        result = parse_client_auth_key(key_str)
        assert result == TEST_PRIVKEY

    def test_parse_with_whitespace(self):
        """Test parsing with leading/trailing whitespace."""
        key_str = f"  {TEST_PRIVKEY_B32}  "
        result = parse_client_auth_key(key_str)
        assert result == TEST_PRIVKEY

    def test_parse_invalid_base32(self):
        """Test parsing invalid base32 raises ValueError."""
        with pytest.raises(ValueError, match="Invalid base32"):
            parse_client_auth_key("!!invalid!!")

    def test_parse_wrong_length(self):
        """Test parsing key with wrong length raises ValueError."""
        # Only 16 bytes
        short_key = base64.b32encode(bytes(16)).decode().rstrip("=")
        with pytest.raises(ValueError, match="must be 32 bytes"):
            parse_client_auth_key(short_key)


# =============================================================================
# Tests for read_client_auth_file()
# =============================================================================


class TestReadClientAuthFile:
    """Tests for read_client_auth_file()."""

    def test_read_simple_key(self):
        """Test reading file with just the key."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".auth_private", delete=False) as f:
            f.write(TEST_PRIVKEY_B32)
            f.flush()
            try:
                result = read_client_auth_file(f.name)
                assert result == TEST_PRIVKEY
            finally:
                os.unlink(f.name)

    def test_read_tor_format(self):
        """Test reading file with Tor format."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".auth_private", delete=False) as f:
            f.write(f"test.onion:descriptor:x25519:{TEST_PRIVKEY_B32}\n")
            f.flush()
            try:
                result = read_client_auth_file(f.name)
                assert result == TEST_PRIVKEY
            finally:
                os.unlink(f.name)

    def test_read_with_comments(self):
        """Test reading file with comments."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".auth_private", delete=False) as f:
            f.write("# This is a comment\n")
            f.write("# Another comment\n")
            f.write(f"{TEST_PRIVKEY_B32}\n")
            f.flush()
            try:
                result = read_client_auth_file(f.name)
                assert result == TEST_PRIVKEY
            finally:
                os.unlink(f.name)

    def test_read_with_empty_lines(self):
        """Test reading file with empty lines."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".auth_private", delete=False) as f:
            f.write("\n\n")
            f.write(f"{TEST_PRIVKEY_B32}\n")
            f.write("\n")
            f.flush()
            try:
                result = read_client_auth_file(f.name)
                assert result == TEST_PRIVKEY
            finally:
                os.unlink(f.name)

    def test_read_empty_file(self):
        """Test reading empty file raises ValueError."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".auth_private", delete=False) as f:
            f.write("")
            f.flush()
            try:
                with pytest.raises(ValueError, match="No valid auth key"):
                    read_client_auth_file(f.name)
            finally:
                os.unlink(f.name)

    def test_read_nonexistent_file(self):
        """Test reading nonexistent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            read_client_auth_file("/nonexistent/path/to/file.auth_private")


# =============================================================================
# Tests for parse_client_auth_data()
# =============================================================================


class TestParseClientAuthData:
    """Tests for parse_client_auth_data()."""

    def test_parse_no_auth_data(self):
        """Test parsing text without auth data returns None."""
        text = """encrypted
hs-descriptor 3
some-other-field value
"""
        result = parse_client_auth_data(text)
        assert result is None

    def test_parse_valid_auth_data(self):
        """Test parsing valid auth data."""
        ephemeral_key = base64.b64encode(b"E" * 32).decode()
        client_id = base64.b64encode(b"C" * 8).decode()
        iv = base64.b64encode(b"I" * 16).decode()
        encrypted_cookie = base64.b64encode(b"K" * 32).decode()

        text = f"""desc-auth-type x25519
desc-auth-ephemeral-key {ephemeral_key}
auth-client {client_id} {iv} {encrypted_cookie}
encrypted
"""
        result = parse_client_auth_data(text)

        assert result is not None
        assert result.auth_type == "x25519"
        assert result.ephemeral_key == b"E" * 32
        assert len(result.auth_clients) == 1
        assert result.auth_clients[0].client_id == b"C" * 8
        assert result.auth_clients[0].iv == b"I" * 16
        assert result.auth_clients[0].encrypted_cookie == b"K" * 32

    def test_parse_multiple_auth_clients(self):
        """Test parsing multiple auth-client entries."""
        ephemeral_key = base64.b64encode(b"E" * 32).decode()

        text = f"""desc-auth-type x25519
desc-auth-ephemeral-key {ephemeral_key}
auth-client {base64.b64encode(b"A" * 8).decode()} {base64.b64encode(b"1" * 16).decode()} {base64.b64encode(b"X" * 32).decode()}
auth-client {base64.b64encode(b"B" * 8).decode()} {base64.b64encode(b"2" * 16).decode()} {base64.b64encode(b"Y" * 32).decode()}
auth-client {base64.b64encode(b"C" * 8).decode()} {base64.b64encode(b"3" * 16).decode()} {base64.b64encode(b"Z" * 32).decode()}
encrypted
"""
        result = parse_client_auth_data(text)

        assert result is not None
        assert len(result.auth_clients) == 3

    def test_parse_unsupported_auth_type(self):
        """Test parsing unsupported auth type raises ValueError."""
        text = """desc-auth-type rsa1024
desc-auth-ephemeral-key somekey
"""
        with pytest.raises(ValueError, match="Unsupported auth type"):
            parse_client_auth_data(text)

    def test_parse_missing_ephemeral_key(self):
        """Test parsing with missing ephemeral key raises ValueError."""
        text = """desc-auth-type x25519
auth-client abc def ghi
"""
        with pytest.raises(ValueError, match="Missing desc-auth-ephemeral-key"):
            parse_client_auth_data(text)

    def test_parse_invalid_ephemeral_key_length(self):
        """Test parsing with wrong ephemeral key length raises ValueError."""
        short_key = base64.b64encode(b"E" * 16).decode()  # Only 16 bytes

        text = f"""desc-auth-type x25519
desc-auth-ephemeral-key {short_key}
"""
        with pytest.raises(ValueError, match="Invalid ephemeral key length"):
            parse_client_auth_data(text)


# =============================================================================
# Tests for derive_client_id_and_cookie_key()
# =============================================================================


class TestDeriveClientIdAndCookeyKey:
    """Tests for derive_client_id_and_cookie_key()."""

    def test_derives_correct_lengths(self):
        """Test derived values have correct lengths."""
        # Generate real X25519 keys
        privkey = X25519PrivateKey.generate()
        privkey_bytes = privkey.private_bytes_raw()

        ephemeral_privkey = X25519PrivateKey.generate()
        ephemeral_pubkey_bytes = ephemeral_privkey.public_key().public_bytes_raw()

        subcredential = b"S" * 32

        client_id, cookie_key = derive_client_id_and_cookie_key(
            client_privkey=privkey_bytes,
            ephemeral_pubkey=ephemeral_pubkey_bytes,
            subcredential=subcredential,
        )

        assert len(client_id) == 8
        assert len(cookie_key) == 32

    def test_deterministic(self):
        """Test derivation is deterministic."""
        privkey = X25519PrivateKey.generate()
        privkey_bytes = privkey.private_bytes_raw()

        ephemeral_privkey = X25519PrivateKey.generate()
        ephemeral_pubkey_bytes = ephemeral_privkey.public_key().public_bytes_raw()

        subcredential = b"S" * 32

        result1 = derive_client_id_and_cookie_key(
            privkey_bytes, ephemeral_pubkey_bytes, subcredential
        )
        result2 = derive_client_id_and_cookie_key(
            privkey_bytes, ephemeral_pubkey_bytes, subcredential
        )

        assert result1 == result2

    def test_different_subcredentials(self):
        """Test different subcredentials produce different results."""
        privkey = X25519PrivateKey.generate()
        privkey_bytes = privkey.private_bytes_raw()

        ephemeral_privkey = X25519PrivateKey.generate()
        ephemeral_pubkey_bytes = ephemeral_privkey.public_key().public_bytes_raw()

        result1 = derive_client_id_and_cookie_key(privkey_bytes, ephemeral_pubkey_bytes, b"A" * 32)
        result2 = derive_client_id_and_cookie_key(privkey_bytes, ephemeral_pubkey_bytes, b"B" * 32)

        assert result1 != result2


# =============================================================================
# Tests for decrypt_descriptor_cookie()
# =============================================================================


class TestDecryptDescriptorCookie:
    """Tests for decrypt_descriptor_cookie()."""

    def test_decrypt_matching_entry(self):
        """Test decrypting with matching client_id."""
        client_id = b"clientid"  # 8 bytes
        iv = bytes(16)  # 16 bytes of zeros
        cookie_key = bytes(32)  # 32 bytes of zeros

        # For AES-CTR with zero key and IV, encryption is XOR with keystream
        # Create a simple test cookie
        original_cookie = b"X" * 32

        # Encrypt with AES-CTR
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        cipher = Cipher(algorithms.AES(cookie_key), modes.CTR(iv))
        encryptor = cipher.encryptor()
        encrypted_cookie = encryptor.update(original_cookie) + encryptor.finalize()

        auth_clients = [
            AuthClientEntry(client_id=client_id, iv=iv, encrypted_cookie=encrypted_cookie)
        ]

        result = decrypt_descriptor_cookie(auth_clients, client_id, cookie_key)

        assert result == original_cookie

    def test_no_matching_entry(self):
        """Test returns None when no matching client_id."""
        auth_clients = [
            AuthClientEntry(client_id=b"other123", iv=bytes(16), encrypted_cookie=bytes(32))
        ]

        result = decrypt_descriptor_cookie(auth_clients, b"clientid", bytes(32))

        assert result is None

    def test_empty_auth_clients(self):
        """Test returns None with empty auth_clients list."""
        result = decrypt_descriptor_cookie([], b"clientid", bytes(32))

        assert result is None

    def test_multiple_entries_finds_correct(self):
        """Test finds correct entry among multiple."""
        target_id = b"target!!"  # 8 bytes
        iv = bytes(16)
        cookie_key = bytes(32)

        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        original_cookie = b"found!" + b"0" * 26  # 32 bytes

        cipher = Cipher(algorithms.AES(cookie_key), modes.CTR(iv))
        encryptor = cipher.encryptor()
        encrypted_cookie = encryptor.update(original_cookie) + encryptor.finalize()

        auth_clients = [
            AuthClientEntry(client_id=b"client01", iv=bytes(16), encrypted_cookie=bytes(32)),
            AuthClientEntry(client_id=target_id, iv=iv, encrypted_cookie=encrypted_cookie),
            AuthClientEntry(client_id=b"client03", iv=bytes(16), encrypted_cookie=bytes(32)),
        ]

        result = decrypt_descriptor_cookie(auth_clients, target_id, cookie_key)

        assert result == original_cookie


# =============================================================================
# Tests for get_descriptor_cookie()
# =============================================================================


class TestGetDescriptorCookie:
    """Tests for get_descriptor_cookie()."""

    def test_no_auth_required(self):
        """Test returns None when no auth data in first layer."""
        text = """encrypted
some-data here
"""
        result = get_descriptor_cookie(text, TEST_PRIVKEY, b"S" * 32)
        assert result is None

    @patch("torscope.directory.client_auth.decrypt_descriptor_cookie")
    @patch("torscope.directory.client_auth.derive_client_id_and_cookie_key")
    @patch("torscope.directory.client_auth.parse_client_auth_data")
    def test_returns_decrypted_cookie(self, mock_parse, mock_derive, mock_decrypt):
        """Test returns decrypted cookie when everything works."""
        mock_auth_data = ClientAuthData(
            auth_type="x25519",
            ephemeral_key=b"E" * 32,
            auth_clients=[],
        )
        mock_parse.return_value = mock_auth_data
        mock_derive.return_value = (b"clientid", b"K" * 32)
        mock_decrypt.return_value = b"cookie!!" + b"0" * 24

        result = get_descriptor_cookie("first layer text", TEST_PRIVKEY, b"S" * 32)

        assert result == b"cookie!!" + b"0" * 24

    @patch("torscope.directory.client_auth.decrypt_descriptor_cookie")
    @patch("torscope.directory.client_auth.derive_client_id_and_cookie_key")
    @patch("torscope.directory.client_auth.parse_client_auth_data")
    def test_returns_none_when_no_match(self, mock_parse, mock_derive, mock_decrypt):
        """Test returns None when no matching auth-client entry."""
        mock_auth_data = ClientAuthData(
            auth_type="x25519",
            ephemeral_key=b"E" * 32,
            auth_clients=[],
        )
        mock_parse.return_value = mock_auth_data
        mock_derive.return_value = (b"clientid", b"K" * 32)
        mock_decrypt.return_value = None

        result = get_descriptor_cookie("first layer text", TEST_PRIVKEY, b"S" * 32)

        assert result is None


# =============================================================================
# Tests for _decode_base64()
# =============================================================================


class TestDecodeBase64:
    """Tests for _decode_base64()."""

    def test_decode_with_padding(self):
        """Test decoding base64 with proper padding."""
        encoded = base64.b64encode(b"hello").decode()
        result = _decode_base64(encoded)
        assert result == b"hello"

    def test_decode_without_padding(self):
        """Test decoding base64 without padding."""
        encoded = base64.b64encode(b"hello").decode().rstrip("=")
        result = _decode_base64(encoded)
        assert result == b"hello"

    def test_decode_empty(self):
        """Test decoding empty string."""
        result = _decode_base64("")
        assert result == b""


# =============================================================================
# Tests for AuthClientEntry
# =============================================================================


class TestAuthClientEntry:
    """Tests for AuthClientEntry dataclass."""

    def test_create_entry(self):
        """Test creating an auth client entry."""
        entry = AuthClientEntry(
            client_id=b"clientid",
            iv=b"0" * 16,
            encrypted_cookie=b"X" * 32,
        )

        assert entry.client_id == b"clientid"
        assert entry.iv == b"0" * 16
        assert entry.encrypted_cookie == b"X" * 32


# =============================================================================
# Tests for ClientAuthData
# =============================================================================


class TestClientAuthData:
    """Tests for ClientAuthData dataclass."""

    def test_create_auth_data(self):
        """Test creating client auth data."""
        entry = AuthClientEntry(
            client_id=b"clientid",
            iv=b"0" * 16,
            encrypted_cookie=b"X" * 32,
        )

        data = ClientAuthData(
            auth_type="x25519",
            ephemeral_key=b"E" * 32,
            auth_clients=[entry],
        )

        assert data.auth_type == "x25519"
        assert data.ephemeral_key == b"E" * 32
        assert len(data.auth_clients) == 1

    def test_default_empty_auth_clients(self):
        """Test default empty auth_clients list."""
        data = ClientAuthData(
            auth_type="x25519",
            ephemeral_key=b"E" * 32,
        )

        assert data.auth_clients == []
