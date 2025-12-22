"""Tests for CREATE_FAST/CREATED_FAST cells and KDF-TOR."""

import pytest

from torscope.onion.cell import (
    CellCommand,
    CreateFastCell,
    CreatedFastCell,
    FastCircuitKeys,
    kdf_tor,
    SHA1_LEN,
    KEY_LEN,
)


class TestKdfTor:
    """Tests for KDF-TOR key derivation function."""

    def test_kdf_tor_basic(self):
        """Test basic KDF-TOR output."""
        k0 = b"A" * 40  # Simulated X | Y
        result = kdf_tor(k0, 100)
        assert len(result) == 100

    def test_kdf_tor_deterministic(self):
        """Test that KDF-TOR is deterministic."""
        k0 = b"test_key_material" + b"\x00" * 23  # 40 bytes
        result1 = kdf_tor(k0, 100)
        result2 = kdf_tor(k0, 100)
        assert result1 == result2

    def test_kdf_tor_different_inputs(self):
        """Test that different inputs produce different outputs."""
        k0_a = b"A" * 40
        k0_b = b"B" * 40
        result_a = kdf_tor(k0_a, 100)
        result_b = kdf_tor(k0_b, 100)
        assert result_a != result_b

    def test_kdf_tor_max_length(self):
        """Test KDF-TOR with maximum length."""
        k0 = b"X" * 40
        max_len = SHA1_LEN * 256  # 5120
        result = kdf_tor(k0, max_len)
        assert len(result) == max_len

    def test_kdf_tor_exceeds_max_length(self):
        """Test that exceeding max length raises error."""
        k0 = b"X" * 40
        with pytest.raises(ValueError, match="cannot generate more than"):
            kdf_tor(k0, SHA1_LEN * 256 + 1)


class TestFastCircuitKeys:
    """Tests for FastCircuitKeys derivation."""

    def test_key_derivation(self):
        """Test circuit key derivation from X and Y."""
        x = bytes(range(20))  # Client's random bytes
        y = bytes(range(20, 40))  # Server's random bytes

        keys = FastCircuitKeys.from_key_material(x, y)

        # Verify all keys have correct lengths
        assert len(keys.kh) == SHA1_LEN
        assert len(keys.digest_forward) == SHA1_LEN
        assert len(keys.digest_backward) == SHA1_LEN
        assert len(keys.key_forward) == KEY_LEN
        assert len(keys.key_backward) == KEY_LEN

    def test_key_verification_success(self):
        """Test KH verification with correct value."""
        x = b"client_random_bytes!"  # 20 bytes
        y = b"server_random_bytes!"  # 20 bytes

        keys = FastCircuitKeys.from_key_material(x, y)
        assert keys.verify(keys.kh) is True

    def test_key_verification_failure(self):
        """Test KH verification with wrong value."""
        x = b"client_random_bytes!"
        y = b"server_random_bytes!"

        keys = FastCircuitKeys.from_key_material(x, y)
        wrong_kh = b"\x00" * SHA1_LEN
        assert keys.verify(wrong_kh) is False

    def test_keys_are_unique(self):
        """Test that different X/Y produce different keys."""
        x1 = b"client_random_bytes1"
        y1 = b"server_random_bytes1"
        x2 = b"client_random_bytes2"
        y2 = b"server_random_bytes2"

        keys1 = FastCircuitKeys.from_key_material(x1, y1)
        keys2 = FastCircuitKeys.from_key_material(x2, y2)

        assert keys1.kh != keys2.kh
        assert keys1.key_forward != keys2.key_forward


class TestCreateFastCell:
    """Tests for CREATE_FAST cell packing/unpacking."""

    def test_pack_unpack_roundtrip(self):
        """Test CREATE_FAST cell round-trip."""
        x = b"X" * SHA1_LEN
        cell = CreateFastCell(circ_id=0x12345678, x=x)

        packed = cell.pack(link_protocol=4)
        unpacked = CreateFastCell.unpack(packed, link_protocol=4)

        assert unpacked.circ_id == cell.circ_id
        assert unpacked.x == cell.x

    def test_pack_invalid_x_length(self):
        """Test that wrong X length raises error."""
        with pytest.raises(ValueError, match="must be 20 bytes"):
            cell = CreateFastCell(circ_id=1, x=b"too short")
            cell.pack()

    def test_cell_command(self):
        """Test that CREATE_FAST uses correct command."""
        cell = CreateFastCell(circ_id=1, x=b"X" * SHA1_LEN)
        packed = cell.pack()

        # Command byte is at offset 4 for link protocol 4
        assert packed[4] == CellCommand.CREATE_FAST


class TestCreatedFastCell:
    """Tests for CREATED_FAST cell packing/unpacking."""

    def test_pack_unpack_roundtrip(self):
        """Test CREATED_FAST cell round-trip."""
        y = b"Y" * SHA1_LEN
        kh = b"K" * SHA1_LEN
        cell = CreatedFastCell(circ_id=0x12345678, y=y, kh=kh)

        packed = cell.pack(link_protocol=4)
        unpacked = CreatedFastCell.unpack(packed, link_protocol=4)

        assert unpacked.circ_id == cell.circ_id
        assert unpacked.y == cell.y
        assert unpacked.kh == cell.kh

    def test_pack_invalid_y_length(self):
        """Test that wrong Y length raises error."""
        with pytest.raises(ValueError, match="y must be 20 bytes"):
            cell = CreatedFastCell(circ_id=1, y=b"short", kh=b"K" * SHA1_LEN)
            cell.pack()

    def test_pack_invalid_kh_length(self):
        """Test that wrong KH length raises error."""
        with pytest.raises(ValueError, match="kh must be 20 bytes"):
            cell = CreatedFastCell(circ_id=1, y=b"Y" * SHA1_LEN, kh=b"short")
            cell.pack()

    def test_unpack_too_short(self):
        """Test unpacking truncated payload."""
        # The cell payload gets padded to 509 bytes when packed,
        # but if we manually create a cell with truncated raw data,
        # it should fail. Let's test with just the header.
        # For link protocol 4: 4 bytes circ_id + 1 byte command + short payload
        truncated_data = b"\x00\x00\x00\x01" + bytes([CellCommand.CREATED_FAST]) + b"short"

        # This should fail because payload is too short for CREATED_FAST
        with pytest.raises(ValueError, match="too short"):
            CreatedFastCell.unpack(truncated_data)

    def test_cell_command(self):
        """Test that CREATED_FAST uses correct command."""
        cell = CreatedFastCell(circ_id=1, y=b"Y" * SHA1_LEN, kh=b"K" * SHA1_LEN)
        packed = cell.pack()

        # Command byte is at offset 4 for link protocol 4
        assert packed[4] == CellCommand.CREATED_FAST


class TestCreateFastHandshake:
    """Integration tests for the full CREATE_FAST handshake."""

    def test_simulated_handshake(self):
        """Test a simulated CREATE_FAST handshake flow."""
        import secrets

        # Client generates X
        x = secrets.token_bytes(SHA1_LEN)
        client_cell = CreateFastCell(circ_id=0x80001234, x=x)

        # "Send" to server (pack)
        packed_create = client_cell.pack()
        received_create = CreateFastCell.unpack(packed_create)

        # Server generates Y and derives keys
        y = secrets.token_bytes(SHA1_LEN)
        server_keys = FastCircuitKeys.from_key_material(received_create.x, y)

        # Server sends CREATED_FAST with Y and KH
        server_cell = CreatedFastCell(
            circ_id=received_create.circ_id,
            y=y,
            kh=server_keys.kh,
        )
        packed_created = server_cell.pack()

        # Client receives and derives keys
        received_created = CreatedFastCell.unpack(packed_created)
        client_keys = FastCircuitKeys.from_key_material(x, received_created.y)

        # Client verifies KH
        assert client_keys.verify(received_created.kh)

        # Both sides should have same keys
        assert client_keys.key_forward == server_keys.key_forward
        assert client_keys.key_backward == server_keys.key_backward
        assert client_keys.digest_forward == server_keys.digest_forward
        assert client_keys.digest_backward == server_keys.digest_backward
