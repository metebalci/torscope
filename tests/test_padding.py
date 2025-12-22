"""Tests for circuit padding negotiation cells."""

import pytest

from torscope.onion.relay import (
    CircpadCommand,
    CircpadMachineType,
    CircpadResponse,
    PaddingNegotiate,
    PaddingNegotiated,
    create_padding_negotiate_payload,
    parse_padding_negotiated_payload,
)


class TestPaddingNegotiate:
    """Tests for PADDING_NEGOTIATE cell."""

    def test_pack_start(self):
        """Test packing a START command."""
        negotiate = PaddingNegotiate(
            command=CircpadCommand.START,
            machine_type=CircpadMachineType.CIRC_SETUP,
            machine_ctr=0,
        )
        packed = negotiate.pack()
        assert len(packed) == 8
        assert packed[0] == 0  # version
        assert packed[1] == CircpadCommand.START
        assert packed[2] == CircpadMachineType.CIRC_SETUP
        assert packed[3] == 0  # unused

    def test_pack_stop(self):
        """Test packing a STOP command."""
        negotiate = PaddingNegotiate(
            command=CircpadCommand.STOP,
            machine_type=CircpadMachineType.CIRC_SETUP,
            machine_ctr=123,
        )
        packed = negotiate.pack()
        assert len(packed) == 8
        assert packed[1] == CircpadCommand.STOP

    def test_pack_unpack_roundtrip(self):
        """Test round-trip packing and unpacking."""
        original = PaddingNegotiate(
            command=CircpadCommand.START,
            machine_type=CircpadMachineType.CIRC_SETUP,
            machine_ctr=42,
        )
        packed = original.pack()
        unpacked = PaddingNegotiate.unpack(packed)

        assert unpacked.version == original.version
        assert unpacked.command == original.command
        assert unpacked.machine_type == original.machine_type
        assert unpacked.machine_ctr == original.machine_ctr

    def test_unpack_too_short(self):
        """Test unpacking too-short payload."""
        with pytest.raises(ValueError, match="too short"):
            PaddingNegotiate.unpack(b"\x00" * 7)


class TestPaddingNegotiated:
    """Tests for PADDING_NEGOTIATED cell."""

    def test_pack_ok_response(self):
        """Test packing an OK response."""
        negotiated = PaddingNegotiated(
            command=CircpadCommand.START,
            response=CircpadResponse.OK,
            machine_type=CircpadMachineType.CIRC_SETUP,
            machine_ctr=0,
        )
        packed = negotiated.pack()
        assert len(packed) == 8
        assert packed[0] == 0  # version
        assert packed[1] == CircpadCommand.START
        assert packed[2] == CircpadResponse.OK
        assert packed[3] == CircpadMachineType.CIRC_SETUP

    def test_pack_err_response(self):
        """Test packing an ERR response."""
        negotiated = PaddingNegotiated(
            command=CircpadCommand.START,
            response=CircpadResponse.ERR,
            machine_type=CircpadMachineType.CIRC_SETUP,
            machine_ctr=0,
        )
        packed = negotiated.pack()
        assert packed[2] == CircpadResponse.ERR

    def test_pack_unpack_roundtrip(self):
        """Test round-trip packing and unpacking."""
        original = PaddingNegotiated(
            command=CircpadCommand.STOP,
            response=CircpadResponse.OK,
            machine_type=CircpadMachineType.CIRC_SETUP,
            machine_ctr=99,
        )
        packed = original.pack()
        unpacked = PaddingNegotiated.unpack(packed)

        assert unpacked.version == original.version
        assert unpacked.command == original.command
        assert unpacked.response == original.response
        assert unpacked.machine_type == original.machine_type
        assert unpacked.machine_ctr == original.machine_ctr

    def test_is_ok_true(self):
        """Test is_ok property when response is OK."""
        negotiated = PaddingNegotiated(
            command=CircpadCommand.START,
            response=CircpadResponse.OK,
        )
        assert negotiated.is_ok is True

    def test_is_ok_false(self):
        """Test is_ok property when response is ERR."""
        negotiated = PaddingNegotiated(
            command=CircpadCommand.START,
            response=CircpadResponse.ERR,
        )
        assert negotiated.is_ok is False

    def test_unpack_too_short(self):
        """Test unpacking too-short payload."""
        with pytest.raises(ValueError, match="too short"):
            PaddingNegotiated.unpack(b"\x00" * 7)


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_create_padding_negotiate_payload_start(self):
        """Test creating START negotiate payload."""
        payload = create_padding_negotiate_payload(CircpadCommand.START)
        assert len(payload) == 8
        assert payload[1] == CircpadCommand.START

    def test_create_padding_negotiate_payload_stop(self):
        """Test creating STOP negotiate payload."""
        payload = create_padding_negotiate_payload(CircpadCommand.STOP)
        assert len(payload) == 8
        assert payload[1] == CircpadCommand.STOP

    def test_create_padding_negotiate_payload_with_machine_ctr(self):
        """Test creating negotiate payload with machine counter."""
        payload = create_padding_negotiate_payload(
            CircpadCommand.START,
            machine_ctr=12345,
        )
        negotiate = PaddingNegotiate.unpack(payload)
        assert negotiate.machine_ctr == 12345

    def test_parse_padding_negotiated_payload(self):
        """Test parsing negotiated payload."""
        negotiated = PaddingNegotiated(
            command=CircpadCommand.START,
            response=CircpadResponse.OK,
        )
        packed = negotiated.pack()
        parsed = parse_padding_negotiated_payload(packed)
        assert parsed.is_ok is True


class TestEnums:
    """Tests for enum values."""

    def test_circpad_command_values(self):
        """Test CircpadCommand enum values match spec."""
        assert CircpadCommand.STOP == 1
        assert CircpadCommand.START == 2

    def test_circpad_machine_type_values(self):
        """Test CircpadMachineType enum values match spec."""
        assert CircpadMachineType.CIRC_SETUP == 1

    def test_circpad_response_values(self):
        """Test CircpadResponse enum values match spec."""
        assert CircpadResponse.OK == 1
        assert CircpadResponse.ERR == 2
