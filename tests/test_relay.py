"""Tests for relay cell implementation."""

import os

import pytest

from torscope.onion.relay import (
    RELAY_BODY_LEN,
    RELAY_DATA_LEN,
    RELAY_HEADER_LEN,
    RelayCell,
    RelayCommand,
    RelayCrypto,
    parse_extended2_payload,
)


class TestRelayConstants:
    """Tests for relay cell constants."""

    def test_relay_body_len(self):
        """Test RELAY_BODY_LEN is correct."""
        assert RELAY_BODY_LEN == 509

    def test_relay_header_len(self):
        """Test RELAY_HEADER_LEN is correct (1+2+2+4+2)."""
        assert RELAY_HEADER_LEN == 11

    def test_relay_data_len(self):
        """Test RELAY_DATA_LEN is body - header."""
        assert RELAY_DATA_LEN == RELAY_BODY_LEN - RELAY_HEADER_LEN
        assert RELAY_DATA_LEN == 498


class TestRelayCell:
    """Tests for RelayCell dataclass."""

    def test_create_relay_cell(self):
        """Test creating a relay cell."""
        cell = RelayCell(
            relay_command=RelayCommand.DATA,
            stream_id=1,
            data=b"Hello, Tor!",
        )

        assert cell.relay_command == RelayCommand.DATA
        assert cell.stream_id == 1
        assert cell.data == b"Hello, Tor!"
        assert cell.recognized == 0
        assert cell.digest == b"\x00\x00\x00\x00"

    def test_pack_payload(self):
        """Test packing a relay cell payload."""
        cell = RelayCell(
            relay_command=RelayCommand.DATA,
            stream_id=1,
            data=b"test",
        )

        payload = cell.pack_payload()

        # Should be exactly 509 bytes
        assert len(payload) == RELAY_BODY_LEN

    def test_unpack_payload(self):
        """Test unpacking a relay cell payload."""
        original = RelayCell(
            relay_command=RelayCommand.DATA,
            stream_id=42,
            data=b"Hello!",
        )

        payload = original.pack_payload()
        recovered = RelayCell.unpack_payload(payload)

        assert recovered.relay_command == RelayCommand.DATA
        assert recovered.stream_id == 42
        assert recovered.data == b"Hello!"

    def test_max_data_length(self):
        """Test that data can be up to RELAY_DATA_LEN bytes."""
        max_data = b"x" * RELAY_DATA_LEN
        cell = RelayCell(
            relay_command=RelayCommand.DATA,
            stream_id=1,
            data=max_data,
        )

        payload = cell.pack_payload()
        assert len(payload) == RELAY_BODY_LEN

    def test_oversized_data_raises_error(self):
        """Test that oversized data raises ValueError."""
        large_data = b"x" * (RELAY_DATA_LEN + 100)
        cell = RelayCell(
            relay_command=RelayCommand.DATA,
            stream_id=1,
            data=large_data,
        )

        # Pack should raise ValueError for oversized data
        with pytest.raises(ValueError, match="Data too long"):
            cell.pack_payload()


class TestRelayCrypto:
    """Tests for RelayCrypto encryption/decryption."""

    @pytest.fixture
    def crypto_layer(self):
        """Create a RelayCrypto layer with test keys."""
        key_forward = os.urandom(16)
        key_backward = os.urandom(16)
        digest_forward = os.urandom(20)
        digest_backward = os.urandom(20)

        return RelayCrypto.create(
            key_forward=key_forward,
            key_backward=key_backward,
            digest_forward=digest_forward,
            digest_backward=digest_backward,
        )

    @pytest.fixture
    def matched_crypto_pair(self):
        """Create a matched pair of RelayCrypto layers for testing."""
        key_forward = os.urandom(16)
        key_backward = os.urandom(16)
        digest_forward = os.urandom(20)
        digest_backward = os.urandom(20)

        # "Client" encrypts forward, decrypts backward
        client = RelayCrypto.create(
            key_forward=key_forward,
            key_backward=key_backward,
            digest_forward=digest_forward,
            digest_backward=digest_backward,
        )

        # "Server" encrypts backward, decrypts forward
        # Note: server uses opposite direction keys
        server = RelayCrypto.create(
            key_forward=key_backward,  # Swapped!
            key_backward=key_forward,  # Swapped!
            digest_forward=digest_backward,  # Swapped!
            digest_backward=digest_forward,  # Swapped!
        )

        return client, server

    def test_encrypt_raw_preserves_length(self, crypto_layer):
        """Test that encrypt_raw produces same length output."""
        payload = os.urandom(RELAY_BODY_LEN)
        encrypted = crypto_layer.encrypt_raw(payload)

        assert len(encrypted) == RELAY_BODY_LEN

    def test_decrypt_raw_preserves_length(self, crypto_layer):
        """Test that decrypt_raw produces same length output."""
        payload = os.urandom(RELAY_BODY_LEN)
        decrypted = crypto_layer.decrypt_raw(payload)

        assert len(decrypted) == RELAY_BODY_LEN

    def test_raw_roundtrip(self):
        """Test that raw encrypt/decrypt roundtrips."""
        key = os.urandom(16)
        digest = os.urandom(20)

        # Create two separate crypto layers with same keys
        # (simulating client and relay)
        crypto1 = RelayCrypto.create(
            key_forward=key,
            key_backward=key,
            digest_forward=digest,
            digest_backward=digest,
        )
        crypto2 = RelayCrypto.create(
            key_forward=key,
            key_backward=key,
            digest_forward=digest,
            digest_backward=digest,
        )

        original = os.urandom(RELAY_BODY_LEN)
        encrypted = crypto1.encrypt_raw(original)
        decrypted = crypto2.decrypt_raw(encrypted)

        assert decrypted == original


class TestParseExtended2Payload:
    """Tests for parse_extended2_payload function."""

    def test_valid_payload(self):
        """Test parsing a valid EXTENDED2 payload."""
        hdata = b"test handshake data"
        # EXTENDED2 format: HLEN(2 bytes) + HDATA
        import struct

        payload = struct.pack(">H", len(hdata)) + hdata

        result = parse_extended2_payload(payload)
        assert result == hdata

    def test_payload_too_short(self):
        """Test that short payload raises ValueError."""
        with pytest.raises(ValueError, match="too short"):
            parse_extended2_payload(b"\x00")

    def test_truncated_hdata(self):
        """Test that truncated hdata raises ValueError."""
        import struct

        # Claim 100 bytes but only provide 5
        payload = struct.pack(">H", 100) + b"short"

        with pytest.raises(ValueError, match="truncated"):
            parse_extended2_payload(payload)


class TestTimingSafeComparison:
    """Tests to verify constant-time comparison is used."""

    def test_hmac_compare_digest_used(self):
        """
        Verify that hmac.compare_digest is used for digest comparison.

        This is a documentation test - the actual check was done during
        the code review. This test exists to ensure the fix isn't reverted.
        """
        # The fix was applied to relay.py:389 and hs_ntor.py:260
        # We can't easily test timing, but we can verify the code structure

        import inspect

        from torscope.onion.relay import RelayCrypto

        source = inspect.getsource(RelayCrypto.decrypt_backward)
        assert (
            "hmac.compare_digest" in source
        ), "RelayCrypto.decrypt_backward should use hmac.compare_digest"
