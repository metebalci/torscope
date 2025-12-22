"""Tests for ntor-v3 handshake implementation."""

import pytest
import secrets

from torscope.onion.ntor_v3 import (
    NTOR_V3_HTYPE,
    PROTOID,
    NtorV3CircuitKeys,
    NtorV3ClientState,
    _aes256_ctr_decrypt,
    _aes256_ctr_encrypt,
    _encap,
    _h,
    _kdf,
    _mac,
    node_id_from_ed25519,
)


class TestEncapsulation:
    """Tests for the ENCAP function."""

    def test_encap_empty(self):
        """Test encapsulating empty data."""
        result = _encap(b"")
        # Length is 8 bytes little-endian
        assert result == b"\x00\x00\x00\x00\x00\x00\x00\x00"
        assert len(result) == 8

    def test_encap_with_data(self):
        """Test encapsulating some data."""
        data = b"hello"
        result = _encap(data)
        # 8 bytes length (5 in little-endian) + 5 bytes data
        assert result[:8] == b"\x05\x00\x00\x00\x00\x00\x00\x00"
        assert result[8:] == b"hello"
        assert len(result) == 13

    def test_encap_deterministic(self):
        """Test that ENCAP is deterministic."""
        data = b"test data"
        assert _encap(data) == _encap(data)


class TestHash:
    """Tests for the tagged hash function."""

    def test_h_basic(self):
        """Test basic tagged hash."""
        result = _h(b"data", b"tag")
        assert len(result) == 32  # SHA3-256 output

    def test_h_deterministic(self):
        """Test that H is deterministic."""
        result1 = _h(b"data", b"tag")
        result2 = _h(b"data", b"tag")
        assert result1 == result2

    def test_h_different_tags(self):
        """Test that different tags produce different hashes."""
        result1 = _h(b"data", b"tag1")
        result2 = _h(b"data", b"tag2")
        assert result1 != result2

    def test_h_different_data(self):
        """Test that different data produces different hashes."""
        result1 = _h(b"data1", b"tag")
        result2 = _h(b"data2", b"tag")
        assert result1 != result2


class TestMAC:
    """Tests for the tagged MAC function."""

    def test_mac_basic(self):
        """Test basic MAC computation."""
        result = _mac(b"key", b"message", b"tag")
        assert len(result) == 32  # SHA3-256 output

    def test_mac_deterministic(self):
        """Test that MAC is deterministic."""
        result1 = _mac(b"key", b"msg", b"tag")
        result2 = _mac(b"key", b"msg", b"tag")
        assert result1 == result2

    def test_mac_different_keys(self):
        """Test that different keys produce different MACs."""
        result1 = _mac(b"key1", b"msg", b"tag")
        result2 = _mac(b"key2", b"msg", b"tag")
        assert result1 != result2


class TestKDF:
    """Tests for the SHAKE-256 KDF."""

    def test_kdf_basic(self):
        """Test basic KDF."""
        result = _kdf(b"seed", b"tag", 64)
        assert len(result) == 64

    def test_kdf_variable_length(self):
        """Test KDF with different output lengths."""
        result32 = _kdf(b"seed", b"tag", 32)
        result64 = _kdf(b"seed", b"tag", 64)
        assert len(result32) == 32
        assert len(result64) == 64
        # First 32 bytes should match
        assert result32 == result64[:32]

    def test_kdf_deterministic(self):
        """Test that KDF is deterministic."""
        result1 = _kdf(b"seed", b"tag", 100)
        result2 = _kdf(b"seed", b"tag", 100)
        assert result1 == result2


class TestAES256CTR:
    """Tests for AES-256-CTR encryption/decryption."""

    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption followed by decryption."""
        key = secrets.token_bytes(32)
        plaintext = b"Hello, ntor-v3!"

        ciphertext = _aes256_ctr_encrypt(key, plaintext)
        decrypted = _aes256_ctr_decrypt(key, ciphertext)

        assert decrypted == plaintext

    def test_ciphertext_differs_from_plaintext(self):
        """Test that ciphertext is different from plaintext."""
        key = secrets.token_bytes(32)
        plaintext = b"Secret message"

        ciphertext = _aes256_ctr_encrypt(key, plaintext)
        assert ciphertext != plaintext

    def test_encrypt_deterministic(self):
        """Test that encryption is deterministic (same key + plaintext)."""
        key = secrets.token_bytes(32)
        plaintext = b"test"

        ct1 = _aes256_ctr_encrypt(key, plaintext)
        ct2 = _aes256_ctr_encrypt(key, plaintext)
        assert ct1 == ct2

    def test_invalid_key_length(self):
        """Test that wrong key length raises error."""
        with pytest.raises(ValueError, match="32 bytes"):
            _aes256_ctr_encrypt(b"short_key", b"data")


class TestNtorV3ClientState:
    """Tests for NtorV3ClientState."""

    def test_create_valid(self):
        """Test creating client state with valid inputs."""
        node_id = secrets.token_bytes(32)
        relay_key = secrets.token_bytes(32)

        state = NtorV3ClientState.create(node_id, relay_key)

        assert state.node_id == node_id
        assert state.relay_ntor_key == relay_key
        assert state.verification == b""

    def test_create_with_verification(self):
        """Test creating client state with verification data."""
        node_id = secrets.token_bytes(32)
        relay_key = secrets.token_bytes(32)
        verification = b"custom_verification"

        state = NtorV3ClientState.create(node_id, relay_key, verification)

        assert state.verification == verification

    def test_create_invalid_node_id(self):
        """Test that wrong node_id length raises error."""
        with pytest.raises(ValueError, match="32 bytes"):
            NtorV3ClientState.create(b"short", secrets.token_bytes(32))

    def test_create_invalid_relay_key(self):
        """Test that wrong relay_key length raises error."""
        with pytest.raises(ValueError, match="32 bytes"):
            NtorV3ClientState.create(secrets.token_bytes(32), b"short")

    def test_create_onion_skin_no_message(self):
        """Test creating onion skin without extension message."""
        node_id = secrets.token_bytes(32)
        relay_key = secrets.token_bytes(32)
        state = NtorV3ClientState.create(node_id, relay_key)

        skin = state.create_onion_skin()

        # Without message: NODEID(32) + KEYID(32) + X(32) + MAC(32) = 128 bytes
        assert len(skin) == 128
        assert skin[:32] == node_id
        assert skin[32:64] == relay_key

    def test_create_onion_skin_with_message(self):
        """Test creating onion skin with extension message."""
        node_id = secrets.token_bytes(32)
        relay_key = secrets.token_bytes(32)
        state = NtorV3ClientState.create(node_id, relay_key)

        message = b"extension data"
        skin = state.create_onion_skin(message)

        # With message: NODEID(32) + KEYID(32) + X(32) + MSG(14) + MAC(32) = 142 bytes
        assert len(skin) == 128 + len(message)

    def test_create_onion_skin_sets_state(self):
        """Test that creating onion skin sets internal state."""
        state = NtorV3ClientState.create(
            secrets.token_bytes(32),
            secrets.token_bytes(32),
        )

        assert state.enc_key is None
        assert state.mac_key is None
        assert state.client_pubkey is None

        state.create_onion_skin()

        assert state.enc_key is not None
        assert len(state.enc_key) == 32
        assert state.mac_key is not None
        assert len(state.mac_key) == 32
        assert state.client_pubkey is not None
        assert len(state.client_pubkey) == 32


class TestNtorV3CircuitKeys:
    """Tests for NtorV3CircuitKeys."""

    def test_from_key_material(self):
        """Test creating circuit keys from key material."""
        key_material = secrets.token_bytes(128)
        keys = NtorV3CircuitKeys.from_key_material(key_material)

        assert len(keys.digest_forward) == 32
        assert len(keys.digest_backward) == 32
        assert len(keys.key_forward) == 32
        assert len(keys.key_backward) == 32

        # Verify correct partitioning
        assert keys.digest_forward == key_material[0:32]
        assert keys.digest_backward == key_material[32:64]
        assert keys.key_forward == key_material[64:96]
        assert keys.key_backward == key_material[96:128]

    def test_from_key_material_wrong_length(self):
        """Test that wrong key material length raises error."""
        with pytest.raises(ValueError, match="128 bytes"):
            NtorV3CircuitKeys.from_key_material(secrets.token_bytes(100))


class TestNodeIdFromEd25519:
    """Tests for node_id_from_ed25519."""

    def test_valid_key(self):
        """Test with valid Ed25519 key."""
        ed_key = secrets.token_bytes(32)
        node_id = node_id_from_ed25519(ed_key)
        # For ntor-v3, node_id is the same as the Ed25519 key
        assert node_id == ed_key

    def test_invalid_length(self):
        """Test that wrong key length raises error."""
        with pytest.raises(ValueError, match="32 bytes"):
            node_id_from_ed25519(b"short")


class TestConstants:
    """Tests for protocol constants."""

    def test_htype(self):
        """Test ntor-v3 HTYPE value."""
        assert NTOR_V3_HTYPE == 0x0003

    def test_protoid(self):
        """Test protocol identifier."""
        assert PROTOID == b"ntor3-curve25519-sha3_256-1"
