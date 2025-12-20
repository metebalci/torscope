"""Tests for Tor cell format implementation."""

from torscope.onion.cell import (
    CELL_LEN_V3,
    CELL_LEN_V4,
    AuthChallengeCell,
    Cell,
    CellCommand,
    CertsCell,
    NetInfoCell,
    VersionsCell,
)


class TestCellCommand:
    """Tests for CellCommand enum."""

    def test_fixed_length_commands(self):
        """Test that fixed-length commands are correctly identified."""
        assert not CellCommand.is_variable_length(CellCommand.PADDING)
        assert not CellCommand.is_variable_length(CellCommand.CREATE)
        assert not CellCommand.is_variable_length(CellCommand.RELAY)
        assert not CellCommand.is_variable_length(CellCommand.DESTROY)
        assert not CellCommand.is_variable_length(CellCommand.NETINFO)

    def test_variable_length_commands(self):
        """Test that variable-length commands are correctly identified."""
        # VERSIONS is special - variable length despite being < 128
        assert CellCommand.is_variable_length(CellCommand.VERSIONS)
        # Commands >= 128 are variable length
        assert CellCommand.is_variable_length(CellCommand.VPADDING)
        assert CellCommand.is_variable_length(CellCommand.CERTS)
        assert CellCommand.is_variable_length(CellCommand.AUTH_CHALLENGE)

    def test_command_values(self):
        """Test that command values match Tor specification."""
        assert CellCommand.PADDING == 0
        assert CellCommand.CREATE == 1
        assert CellCommand.RELAY == 3
        assert CellCommand.DESTROY == 4
        assert CellCommand.VERSIONS == 7
        assert CellCommand.NETINFO == 8
        assert CellCommand.CERTS == 129
        assert CellCommand.AUTH_CHALLENGE == 130


class TestCell:
    """Tests for base Cell class."""

    def test_pack_fixed_cell_v4(self):
        """Test packing a fixed-length cell for link protocol 4."""
        cell = Cell(circ_id=0, command=CellCommand.PADDING, payload=b"")
        packed = cell.pack(link_protocol=4)
        assert len(packed) == CELL_LEN_V4
        # CircID (4 bytes) + Command (1 byte) + padding
        assert packed[:4] == b"\x00\x00\x00\x00"  # CircID = 0
        assert packed[4] == CellCommand.PADDING

    def test_pack_fixed_cell_v3(self):
        """Test packing a fixed-length cell for link protocol 3."""
        cell = Cell(circ_id=0, command=CellCommand.PADDING, payload=b"")
        packed = cell.pack(link_protocol=3)
        assert len(packed) == CELL_LEN_V3
        # CircID (2 bytes) + Command (1 byte) + padding
        assert packed[:2] == b"\x00\x00"  # CircID = 0
        assert packed[2] == CellCommand.PADDING

    def test_pack_variable_cell_v4(self):
        """Test packing a variable-length cell for link protocol 4."""
        payload = b"test payload"
        cell = Cell(circ_id=0, command=CellCommand.VERSIONS, payload=payload)
        packed = cell.pack(link_protocol=4)
        # CircID (4 bytes) + Command (1 byte) + Length (2 bytes) + payload
        assert len(packed) == 4 + 1 + 2 + len(payload)
        assert packed[:4] == b"\x00\x00\x00\x00"  # CircID = 0
        assert packed[4] == CellCommand.VERSIONS
        assert packed[5:7] == b"\x00\x0c"  # Length = 12
        assert packed[7:] == payload

    def test_unpack_fixed_cell_v4(self):
        """Test unpacking a fixed-length cell for link protocol 4."""
        # Create a NETINFO cell
        packed = b"\x00\x00\x00\x00" + bytes([CellCommand.NETINFO]) + b"\x00" * (CELL_LEN_V4 - 5)
        cell = Cell.unpack(packed, link_protocol=4)
        assert cell.circ_id == 0
        assert cell.command == CellCommand.NETINFO

    def test_unpack_fixed_cell_v3(self):
        """Test unpacking a fixed-length cell for link protocol 3."""
        packed = b"\x00\x00" + bytes([CellCommand.NETINFO]) + b"\x00" * (CELL_LEN_V3 - 3)
        cell = Cell.unpack(packed, link_protocol=3)
        assert cell.circ_id == 0
        assert cell.command == CellCommand.NETINFO

    def test_roundtrip_fixed_cell(self):
        """Test that packing and unpacking a fixed cell preserves data."""
        payload = b"test data"
        cell = Cell(circ_id=123, command=CellCommand.PADDING, payload=payload)
        packed = cell.pack(link_protocol=4)
        unpacked = Cell.unpack(packed, link_protocol=4)
        assert unpacked.circ_id == cell.circ_id
        assert unpacked.command == cell.command

    def test_roundtrip_variable_cell(self):
        """Test that packing and unpacking a variable cell preserves data."""
        payload = b"test data"
        cell = Cell(circ_id=0, command=CellCommand.VPADDING, payload=payload)
        packed = cell.pack(link_protocol=4)
        unpacked = Cell.unpack(packed, link_protocol=4)
        assert unpacked.circ_id == cell.circ_id
        assert unpacked.command == cell.command
        assert unpacked.payload == payload


class TestVersionsCell:
    """Tests for VERSIONS cell."""

    def test_pack_versions_cell(self):
        """Test packing a VERSIONS cell."""
        cell = VersionsCell(versions=[4, 5])
        packed = cell.pack()
        # VERSIONS always uses 2-byte CircID
        # CircID (2 bytes) + Command (1 byte) + Length (2 bytes) + versions (2 bytes each)
        assert len(packed) == 2 + 1 + 2 + 4
        assert packed[:2] == b"\x00\x00"  # CircID = 0
        assert packed[2] == CellCommand.VERSIONS
        assert packed[3:5] == b"\x00\x04"  # Length = 4

    def test_unpack_versions_cell(self):
        """Test unpacking a VERSIONS cell."""
        # CircID (2 bytes) + Command + Length + versions [3, 4, 5]
        packed = b"\x00\x00\x07\x00\x06\x00\x03\x00\x04\x00\x05"
        cell = VersionsCell.unpack(packed)
        assert cell.versions == [3, 4, 5]

    def test_roundtrip_versions_cell(self):
        """Test packing and unpacking a VERSIONS cell."""
        original = VersionsCell(versions=[3, 4, 5])
        packed = original.pack()
        unpacked = VersionsCell.unpack(packed)
        assert unpacked.versions == original.versions


class TestNetInfoCell:
    """Tests for NETINFO cell."""

    def test_pack_netinfo_cell(self):
        """Test packing a NETINFO cell."""
        cell = NetInfoCell(
            timestamp=1234567890,
            other_address=(4, b"\x7f\x00\x00\x01"),  # 127.0.0.1
            my_addresses=[],
        )
        packed = cell.pack(link_protocol=4)
        # Should be a fixed-length cell
        assert len(packed) == CELL_LEN_V4

    def test_unpack_netinfo_cell(self):
        """Test unpacking a NETINFO cell."""
        # Create a simple NETINFO cell
        cell = NetInfoCell(
            timestamp=1234567890,
            other_address=(4, b"\x7f\x00\x00\x01"),
            my_addresses=[(4, b"\xc0\xa8\x01\x01")],  # 192.168.1.1
        )
        packed = cell.pack(link_protocol=4)
        unpacked = NetInfoCell.unpack(packed, link_protocol=4)
        assert unpacked.timestamp == 1234567890
        assert unpacked.other_address == (4, b"\x7f\x00\x00\x01")
        assert len(unpacked.my_addresses) == 1


class TestCertsCell:
    """Tests for CERTS cell."""

    def test_pack_certs_cell(self):
        """Test packing a CERTS cell."""
        cell = CertsCell(
            certificates=[
                (1, b"certificate1"),
                (2, b"certificate2"),
            ]
        )
        packed = cell.pack(link_protocol=4)
        # Variable-length cell
        # CircID (4) + Command (1) + Length (2) + NumCerts (1) + certs
        assert packed[4] == CellCommand.CERTS

    def test_unpack_certs_cell(self):
        """Test unpacking a CERTS cell."""
        cell = CertsCell(
            certificates=[
                (1, b"cert1"),
                (2, b"cert2"),
            ]
        )
        packed = cell.pack(link_protocol=4)
        unpacked = CertsCell.unpack(packed, link_protocol=4)
        assert len(unpacked.certificates) == 2
        assert unpacked.certificates[0] == (1, b"cert1")
        assert unpacked.certificates[1] == (2, b"cert2")


class TestAuthChallengeCell:
    """Tests for AUTH_CHALLENGE cell."""

    def test_pack_auth_challenge_cell(self):
        """Test packing an AUTH_CHALLENGE cell."""
        cell = AuthChallengeCell(
            challenge=b"\x00" * 32,
            methods=[1, 3],
        )
        packed = cell.pack(link_protocol=4)
        assert packed[4] == CellCommand.AUTH_CHALLENGE

    def test_unpack_auth_challenge_cell(self):
        """Test unpacking an AUTH_CHALLENGE cell."""
        challenge = bytes(range(32))
        cell = AuthChallengeCell(challenge=challenge, methods=[1, 3])
        packed = cell.pack(link_protocol=4)
        unpacked = AuthChallengeCell.unpack(packed, link_protocol=4)
        assert unpacked.challenge == challenge
        assert unpacked.methods == [1, 3]
