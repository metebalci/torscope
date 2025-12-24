"""Tests for TLS connection implementation."""

import struct
from unittest.mock import MagicMock, patch

import pytest

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
from torscope.onion.connection import RelayConnection


class TestRelayConnectionInit:
    """Tests for RelayConnection initialization."""

    def test_create_connection(self):
        """Test creating a RelayConnection."""
        conn = RelayConnection(host="192.0.2.1", port=9001)

        assert conn.host == "192.0.2.1"
        assert conn.port == 9001
        assert conn.transport is None
        assert conn.link_protocol == 0
        assert conn.their_versions == []

    def test_create_connection_with_timeout(self):
        """Test creating connection with custom timeout."""
        conn = RelayConnection(host="192.0.2.1", port=9001, timeout=60.0)

        assert conn.timeout == 60.0

    def test_supported_versions(self):
        """Test supported link protocol versions."""
        conn = RelayConnection(host="192.0.2.1", port=9001)

        assert 4 in conn.SUPPORTED_VERSIONS
        assert 5 in conn.SUPPORTED_VERSIONS


class TestRelayConnectionConnect:
    """Tests for RelayConnection.connect() method."""

    @patch("torscope.onion.connection.socket.socket")
    @patch("torscope.onion.connection.ssl.SSLContext")
    def test_connect_creates_socket(self, mock_ssl_ctx_class, mock_socket_class):
        """Test that connect() creates a TCP socket."""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket

        mock_ssl_ctx = MagicMock()
        mock_ssl_ctx_class.return_value = mock_ssl_ctx
        mock_tls_socket = MagicMock()
        mock_ssl_ctx.wrap_socket.return_value = mock_tls_socket
        mock_tls_socket.version.return_value = "TLSv1.3"

        conn = RelayConnection(host="192.0.2.1", port=9001)
        conn.connect()

        mock_socket.connect.assert_called_once_with(("192.0.2.1", 9001))

    @patch("torscope.onion.connection.socket.socket")
    @patch("torscope.onion.connection.ssl.SSLContext")
    def test_connect_wraps_with_tls(self, mock_ssl_ctx_class, mock_socket_class):
        """Test that connect() wraps socket with TLS."""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket

        mock_ssl_ctx = MagicMock()
        mock_ssl_ctx_class.return_value = mock_ssl_ctx
        mock_tls_socket = MagicMock()
        mock_ssl_ctx.wrap_socket.return_value = mock_tls_socket
        mock_tls_socket.version.return_value = "TLSv1.3"

        conn = RelayConnection(host="192.0.2.1", port=9001)
        conn.connect()

        mock_ssl_ctx.wrap_socket.assert_called_once()

    def test_connect_with_transport(self):
        """Test that connect() uses transport when configured."""
        mock_transport = MagicMock()
        mock_tls_socket = MagicMock()
        mock_transport.connect.return_value = mock_tls_socket

        conn = RelayConnection(host="192.0.2.1", port=9001, transport=mock_transport)
        conn.connect()

        mock_transport.connect.assert_called_once()
        assert conn._tls_socket is mock_tls_socket


class TestRelayConnectionClose:
    """Tests for RelayConnection.close() method."""

    def test_close_closes_sockets(self):
        """Test that close() closes both sockets."""
        mock_tls = MagicMock()
        mock_socket = MagicMock()

        conn = RelayConnection(host="192.0.2.1", port=9001)
        conn._tls_socket = mock_tls
        conn._socket = mock_socket

        conn.close()

        mock_tls.close.assert_called_once()
        mock_socket.close.assert_called_once()
        assert conn._tls_socket is None
        assert conn._socket is None

    def test_close_with_transport(self):
        """Test that close() closes transport when configured."""
        mock_transport = MagicMock()

        conn = RelayConnection(host="192.0.2.1", port=9001, transport=mock_transport)
        conn._tls_socket = MagicMock()

        conn.close()

        mock_transport.close.assert_called_once()
        assert conn._tls_socket is None


class TestRelayConnectionHandshake:
    """Tests for RelayConnection.handshake() method."""

    def test_handshake_raises_when_not_connected(self):
        """Test that handshake() raises when not connected."""
        conn = RelayConnection(host="192.0.2.1", port=9001)

        with pytest.raises(ConnectionError, match="Not connected"):
            conn.handshake()

    def test_handshake_negotiates_version(self):
        """Test that handshake() negotiates highest common version."""
        conn = RelayConnection(host="192.0.2.1", port=9001)
        mock_tls = MagicMock()
        conn._tls_socket = mock_tls

        # Create response cells
        their_versions_cell = VersionsCell(versions=[3, 4, 5])
        certs_cell = CertsCell(certificates=[(1, b"cert1")])
        auth_challenge_cell = AuthChallengeCell(challenge=b"x" * 32, methods=[1])
        netinfo_cell = NetInfoCell(other_address=(4, b"\x00" * 4), my_addresses=[])

        # Set up recv_exact to return appropriate data
        def make_recv_generator():
            # First call: VERSIONS cell (variable-length, 2-byte circ_id)
            versions_data = their_versions_cell.pack()
            yield versions_data[:3]  # Header
            yield versions_data[3:5]  # Length
            yield versions_data[5:]  # Payload

            # Next: CERTS cell (variable-length, 4-byte circ_id for v4+)
            certs_data = certs_cell.pack(4)
            yield certs_data[:5]  # Header
            yield certs_data[5:7]  # Length
            yield certs_data[7:]  # Payload

            # Next: AUTH_CHALLENGE cell (variable-length)
            auth_data = auth_challenge_cell.pack(4)
            yield auth_data[:5]  # Header
            yield auth_data[5:7]  # Length
            yield auth_data[7:]  # Payload

            # Next: NETINFO cell (fixed-length)
            netinfo_data = netinfo_cell.pack(4)
            yield netinfo_data

        recv_gen = make_recv_generator()

        def mock_recv(length):
            return next(recv_gen)

        mock_tls.recv = mock_recv

        result = conn.handshake()

        assert result is True
        assert conn.link_protocol in [4, 5]
        assert conn.their_versions == [3, 4, 5]

    def test_handshake_fails_no_common_version(self):
        """Test that handshake() fails when no common version."""
        conn = RelayConnection(host="192.0.2.1", port=9001)
        mock_tls = MagicMock()
        conn._tls_socket = mock_tls

        # They only support version 3, we support 4,5
        their_versions_cell = VersionsCell(versions=[3])

        def make_recv_generator():
            versions_data = their_versions_cell.pack()
            yield versions_data[:3]
            yield versions_data[3:5]
            yield versions_data[5:]

        recv_gen = make_recv_generator()

        def mock_recv(length):
            return next(recv_gen)

        mock_tls.recv = mock_recv

        result = conn.handshake()

        assert result is False


class TestRelayConnectionSendCell:
    """Tests for RelayConnection.send_cell() method."""

    def test_send_cell_uses_link_protocol(self):
        """Test that send_cell() uses negotiated link protocol."""
        conn = RelayConnection(host="192.0.2.1", port=9001)
        mock_tls = MagicMock()
        conn._tls_socket = mock_tls
        conn.link_protocol = 4

        cell = MagicMock()
        conn.send_cell(cell)

        cell.pack.assert_called_once_with(4)
        mock_tls.sendall.assert_called_once()


class TestRelayConnectionRecvCell:
    """Tests for RelayConnection.recv_cell() method."""

    def test_recv_cell_fixed_length_v4(self):
        """Test receiving fixed-length cell with v4 protocol."""
        conn = RelayConnection(host="192.0.2.1", port=9001)
        mock_tls = MagicMock()
        conn._tls_socket = mock_tls
        conn.link_protocol = 4

        # Create a PADDING cell (fixed length, command 0)
        cell_data = struct.pack(">IB", 0, CellCommand.PADDING) + b"\x00" * (CELL_LEN_V4 - 5)

        def mock_recv(length):
            if length == 5:
                return cell_data[:5]
            return cell_data[5 : 5 + length]

        mock_tls.recv = mock_recv

        cell = conn.recv_cell()

        assert cell.command == CellCommand.PADDING

    def test_recv_cell_variable_length_v4(self):
        """Test receiving variable-length cell with v4 protocol."""
        conn = RelayConnection(host="192.0.2.1", port=9001)
        mock_tls = MagicMock()
        conn._tls_socket = mock_tls
        conn.link_protocol = 4

        # Create a VERSIONS cell (variable length, command 7)
        payload = struct.pack(">HH", 4, 5)  # versions 4, 5
        header = struct.pack(">IB", 0, CellCommand.VERSIONS)
        length = struct.pack(">H", len(payload))
        cell_data = header + length + payload

        def mock_recv(length):
            nonlocal cell_data
            result = cell_data[:length]
            cell_data = cell_data[length:]
            return result

        mock_tls.recv = mock_recv

        cell = conn.recv_cell()

        assert cell.command == CellCommand.VERSIONS


class TestRelayConnectionSendVpadding:
    """Tests for RelayConnection.send_vpadding() method."""

    def test_send_vpadding_random_length(self):
        """Test send_vpadding() with random length."""
        conn = RelayConnection(host="192.0.2.1", port=9001)
        mock_tls = MagicMock()
        conn._tls_socket = mock_tls
        conn.link_protocol = 4

        conn.send_vpadding()

        mock_tls.sendall.assert_called_once()

    def test_send_vpadding_specific_length(self):
        """Test send_vpadding() with specific length."""
        conn = RelayConnection(host="192.0.2.1", port=9001)
        mock_tls = MagicMock()
        conn._tls_socket = mock_tls
        conn.link_protocol = 4

        conn.send_vpadding(100)

        mock_tls.sendall.assert_called_once()
        # Check that the sent data has correct length
        sent_data = mock_tls.sendall.call_args[0][0]
        # Variable cell: circ_id(4) + cmd(1) + len(2) + payload(100)
        assert len(sent_data) == 4 + 1 + 2 + 100

    def test_send_vpadding_rejects_too_long(self):
        """Test send_vpadding() rejects length > 65535."""
        conn = RelayConnection(host="192.0.2.1", port=9001)
        mock_tls = MagicMock()
        conn._tls_socket = mock_tls
        conn.link_protocol = 4

        with pytest.raises(ValueError, match="65535"):
            conn.send_vpadding(70000)

    def test_send_vpadding_rejects_too_short(self):
        """Test send_vpadding() rejects length < 1."""
        conn = RelayConnection(host="192.0.2.1", port=9001)
        mock_tls = MagicMock()
        conn._tls_socket = mock_tls
        conn.link_protocol = 4

        with pytest.raises(ValueError, match="at least 1"):
            conn.send_vpadding(-1)


class TestRelayConnectionContextManager:
    """Tests for RelayConnection context manager support."""

    @patch("torscope.onion.connection.socket.socket")
    @patch("torscope.onion.connection.ssl.SSLContext")
    def test_context_manager_connects_on_enter(self, mock_ssl_ctx_class, mock_socket_class):
        """Test context manager __enter__ calls connect()."""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket

        mock_ssl_ctx = MagicMock()
        mock_ssl_ctx_class.return_value = mock_ssl_ctx
        mock_tls_socket = MagicMock()
        mock_ssl_ctx.wrap_socket.return_value = mock_tls_socket
        mock_tls_socket.version.return_value = "TLSv1.3"

        with RelayConnection(host="192.0.2.1", port=9001) as conn:
            mock_socket.connect.assert_called_once()
            assert conn is not None

    def test_context_manager_closes_on_exit(self):
        """Test context manager __exit__ calls close()."""
        conn = RelayConnection(host="192.0.2.1", port=9001)
        mock_tls = MagicMock()
        mock_socket = MagicMock()
        conn._tls_socket = mock_tls
        conn._socket = mock_socket

        conn.__exit__(None, None, None)

        mock_tls.close.assert_called_once()


class TestRelayConnectionRecvExact:
    """Tests for RelayConnection._recv_exact() method."""

    def test_recv_exact_raises_when_not_connected(self):
        """Test _recv_exact() raises when not connected."""
        conn = RelayConnection(host="192.0.2.1", port=9001)

        with pytest.raises(ConnectionError, match="Not connected"):
            conn._recv_exact(100)

    def test_recv_exact_handles_partial_recv(self):
        """Test _recv_exact() handles partial receives."""
        conn = RelayConnection(host="192.0.2.1", port=9001)
        mock_tls = MagicMock()
        conn._tls_socket = mock_tls

        # Return data in chunks
        mock_tls.recv.side_effect = [b"abc", b"de", b"fghij"]

        result = conn._recv_exact(10)

        assert result == b"abcdefghij"

    def test_recv_exact_raises_on_connection_closed(self):
        """Test _recv_exact() raises when connection closed."""
        conn = RelayConnection(host="192.0.2.1", port=9001)
        mock_tls = MagicMock()
        conn._tls_socket = mock_tls

        # Return empty bytes (connection closed)
        mock_tls.recv.return_value = b""

        with pytest.raises(ConnectionError, match="closed"):
            conn._recv_exact(100)


class TestRelayConnectionRecvFixedCell:
    """Tests for RelayConnection._recv_fixed_cell() method."""

    def test_recv_fixed_cell_v3(self):
        """Test _recv_fixed_cell() with v3 protocol."""
        conn = RelayConnection(host="192.0.2.1", port=9001)
        mock_tls = MagicMock()
        conn._tls_socket = mock_tls
        conn.link_protocol = 3

        cell_data = b"x" * CELL_LEN_V3
        mock_tls.recv.return_value = cell_data

        result = conn._recv_fixed_cell()

        assert len(result) == CELL_LEN_V3

    def test_recv_fixed_cell_v4(self):
        """Test _recv_fixed_cell() with v4 protocol."""
        conn = RelayConnection(host="192.0.2.1", port=9001)
        mock_tls = MagicMock()
        conn._tls_socket = mock_tls
        conn.link_protocol = 4

        cell_data = b"x" * CELL_LEN_V4
        mock_tls.recv.return_value = cell_data

        result = conn._recv_fixed_cell()

        assert len(result) == CELL_LEN_V4


class TestRelayConnectionSendRaw:
    """Tests for RelayConnection._send_raw() method."""

    def test_send_raw_raises_when_not_connected(self):
        """Test _send_raw() raises when not connected."""
        conn = RelayConnection(host="192.0.2.1", port=9001)

        with pytest.raises(ConnectionError, match="Not connected"):
            conn._send_raw(b"test")

    def test_send_raw_sends_data(self):
        """Test _send_raw() sends data."""
        conn = RelayConnection(host="192.0.2.1", port=9001)
        mock_tls = MagicMock()
        conn._tls_socket = mock_tls

        conn._send_raw(b"test data")

        mock_tls.sendall.assert_called_once_with(b"test data")
