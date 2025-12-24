"""Tests for circuit implementation."""

import struct
from unittest.mock import MagicMock, patch

import pytest

from torscope.onion.cell import Cell, CellCommand, Create2Cell, DestroyCell
from torscope.onion.circuit import (
    Circuit,
    CircuitHop,
    CircuitState,
    StreamState,
)
from torscope.onion.ntor import CircuitKeys
from torscope.onion.relay import (
    CIRCUIT_SENDME_THRESHOLD,
    CIRCUIT_WINDOW_INCREMENT,
    CIRCUIT_WINDOW_INITIAL,
    RELAY_BODY_LEN,
    STREAM_WINDOW_INITIAL,
    RelayCell,
    RelayCommand,
    RelayCrypto,
)


class TestCircuitState:
    """Tests for CircuitState enum."""

    def test_circuit_states_exist(self):
        """Test all circuit states are defined."""
        assert CircuitState.NEW is not None
        assert CircuitState.BUILDING is not None
        assert CircuitState.OPEN is not None
        assert CircuitState.CLOSED is not None
        assert CircuitState.FAILED is not None

    def test_circuit_states_are_unique(self):
        """Test all states have unique values."""
        states = [
            CircuitState.NEW,
            CircuitState.BUILDING,
            CircuitState.OPEN,
            CircuitState.CLOSED,
            CircuitState.FAILED,
        ]
        values = [s.value for s in states]
        assert len(values) == len(set(values))


class TestStreamState:
    """Tests for StreamState dataclass."""

    def test_create_stream_state(self):
        """Test creating a stream state."""
        state = StreamState(stream_id=42)
        assert state.stream_id == 42
        assert state.deliver_window == STREAM_WINDOW_INITIAL

    def test_stream_state_custom_window(self):
        """Test creating stream state with custom window."""
        state = StreamState(stream_id=1, deliver_window=100)
        assert state.stream_id == 1
        assert state.deliver_window == 100


class TestCircuitHop:
    """Tests for CircuitHop dataclass."""

    def test_create_circuit_hop(self):
        """Test creating a circuit hop."""
        hop = CircuitHop(
            fingerprint="A" * 40,
            ntor_onion_key=b"x" * 32,
        )
        assert hop.fingerprint == "A" * 40
        assert hop.ntor_onion_key == b"x" * 32
        assert hop.keys is None

    def test_circuit_hop_with_keys(self):
        """Test creating circuit hop with derived keys."""
        # Create mock keys
        keys = CircuitKeys(
            key_forward=b"f" * 16,
            key_backward=b"b" * 16,
            digest_forward=b"df" * 10,
            digest_backward=b"db" * 10,
        )
        hop = CircuitHop(
            fingerprint="B" * 40,
            ntor_onion_key=b"y" * 32,
            keys=keys,
        )
        assert hop.keys is not None
        assert hop.keys.key_forward == b"f" * 16


class TestCircuitCreate:
    """Tests for Circuit.create() factory method."""

    def test_create_allocates_circuit_id(self):
        """Test that create() allocates a circuit ID."""
        mock_conn = MagicMock()
        mock_conn.link_protocol = 4

        circuit = Circuit.create(mock_conn)

        assert circuit.circ_id != 0
        assert circuit.circ_id & 0x80000000  # High bit should be set

    def test_create_sets_initial_state(self):
        """Test that create() sets initial state to NEW."""
        mock_conn = MagicMock()

        circuit = Circuit.create(mock_conn)

        assert circuit.state == CircuitState.NEW
        assert len(circuit.hops) == 0

    def test_create_unique_circuit_ids(self):
        """Test that multiple creates get different IDs."""
        mock_conn = MagicMock()

        circuit1 = Circuit.create(mock_conn)
        circuit2 = Circuit.create(mock_conn)

        # IDs should be different (with high probability)
        assert circuit1.circ_id != circuit2.circ_id


class TestCircuitDestroy:
    """Tests for Circuit.destroy() method."""

    def test_destroy_sends_destroy_cell(self):
        """Test that destroy() sends a DESTROY cell."""
        mock_conn = MagicMock()
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)

        circuit.destroy()

        mock_conn.send_cell.assert_called_once()
        sent_cell = mock_conn.send_cell.call_args[0][0]
        assert isinstance(sent_cell, DestroyCell)
        assert sent_cell.circ_id == 0x80001234

    def test_destroy_sets_state_closed(self):
        """Test that destroy() sets state to CLOSED."""
        mock_conn = MagicMock()
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)

        circuit.destroy()

        assert circuit.state == CircuitState.CLOSED

    def test_destroy_no_op_when_new(self):
        """Test that destroy() does nothing when circuit is NEW."""
        mock_conn = MagicMock()
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.NEW)

        circuit.destroy()

        mock_conn.send_cell.assert_not_called()

    def test_destroy_no_op_when_already_closed(self):
        """Test that destroy() does nothing when already CLOSED."""
        mock_conn = MagicMock()
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.CLOSED)

        circuit.destroy()

        mock_conn.send_cell.assert_not_called()


class TestCircuitIsOpen:
    """Tests for Circuit.is_open property."""

    def test_is_open_when_open(self):
        """Test is_open returns True when state is OPEN."""
        mock_conn = MagicMock()
        circuit = Circuit(connection=mock_conn, state=CircuitState.OPEN)
        assert circuit.is_open is True

    def test_is_open_when_new(self):
        """Test is_open returns False when state is NEW."""
        mock_conn = MagicMock()
        circuit = Circuit(connection=mock_conn, state=CircuitState.NEW)
        assert circuit.is_open is False

    def test_is_open_when_building(self):
        """Test is_open returns False when state is BUILDING."""
        mock_conn = MagicMock()
        circuit = Circuit(connection=mock_conn, state=CircuitState.BUILDING)
        assert circuit.is_open is False

    def test_is_open_when_closed(self):
        """Test is_open returns False when state is CLOSED."""
        mock_conn = MagicMock()
        circuit = Circuit(connection=mock_conn, state=CircuitState.CLOSED)
        assert circuit.is_open is False


class TestCircuitExtendTo:
    """Tests for Circuit.extend_to() method."""

    def test_extend_to_raises_when_closed(self):
        """Test that extend_to() raises when circuit is closed."""
        mock_conn = MagicMock()
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.CLOSED)

        with pytest.raises(RuntimeError, match="closed"):
            circuit.extend_to("A" * 40, b"x" * 32)

    def test_extend_to_requires_ip_port_for_extending(self):
        """Test that extend_to() requires ip/port for non-first hop."""
        mock_conn = MagicMock()
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)
        # Add a fake first hop
        circuit.hops.append(CircuitHop(fingerprint="B" * 40, ntor_onion_key=b"y" * 32))

        with pytest.raises(ValueError, match="ip and port required"):
            circuit.extend_to("A" * 40, b"x" * 32)


class TestCircuitCreateFast:
    """Tests for Circuit.create_fast() method."""

    def test_create_fast_raises_when_closed(self):
        """Test that create_fast() raises when circuit is closed."""
        mock_conn = MagicMock()
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.CLOSED)

        with pytest.raises(RuntimeError, match="closed"):
            circuit.create_fast("A" * 40)

    def test_create_fast_raises_when_not_first_hop(self):
        """Test that create_fast() raises when hops already exist."""
        mock_conn = MagicMock()
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)
        circuit.hops.append(CircuitHop(fingerprint="B" * 40, ntor_onion_key=b"y" * 32))

        with pytest.raises(RuntimeError, match="first hop"):
            circuit.create_fast("A" * 40)


class TestCircuitSendRelay:
    """Tests for Circuit.send_relay() method."""

    def test_send_relay_raises_when_not_open(self):
        """Test that send_relay() raises when circuit is not open."""
        mock_conn = MagicMock()
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.NEW)

        relay_cell = RelayCell(relay_command=RelayCommand.DATA, stream_id=1, data=b"test")

        with pytest.raises(RuntimeError, match="not open"):
            circuit.send_relay(relay_cell)

    def test_send_relay_raises_when_no_crypto(self):
        """Test that send_relay() raises when crypto not initialized."""
        mock_conn = MagicMock()
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)
        # No crypto layers added

        relay_cell = RelayCell(relay_command=RelayCommand.DATA, stream_id=1, data=b"test")

        with pytest.raises(RuntimeError, match="crypto not initialized"):
            circuit.send_relay(relay_cell)

    def test_send_relay_single_hop(self):
        """Test send_relay() with single hop circuit."""
        mock_conn = MagicMock()
        mock_conn.link_protocol = 4
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)

        # Add a crypto layer
        crypto = RelayCrypto.create(
            key_forward=b"f" * 16,
            key_backward=b"b" * 16,
            digest_forward=b"df" * 10,
            digest_backward=b"db" * 10,
        )
        circuit._crypto_layers.append(crypto)

        relay_cell = RelayCell(relay_command=RelayCommand.DATA, stream_id=1, data=b"test")
        circuit.send_relay(relay_cell)

        # Verify send_cell was called
        mock_conn.send_cell.assert_called_once()
        sent_cell = mock_conn.send_cell.call_args[0][0]
        assert isinstance(sent_cell, Cell)
        assert sent_cell.command == CellCommand.RELAY
        assert sent_cell.circ_id == 0x80001234

    def test_send_relay_early_flag(self):
        """Test send_relay() with early=True sends RELAY_EARLY."""
        mock_conn = MagicMock()
        mock_conn.link_protocol = 4
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)

        # Add a crypto layer
        crypto = RelayCrypto.create(
            key_forward=b"f" * 16,
            key_backward=b"b" * 16,
            digest_forward=b"df" * 10,
            digest_backward=b"db" * 10,
        )
        circuit._crypto_layers.append(crypto)

        relay_cell = RelayCell(relay_command=RelayCommand.EXTEND2, stream_id=0, data=b"extend")
        circuit.send_relay(relay_cell, early=True)

        sent_cell = mock_conn.send_cell.call_args[0][0]
        assert sent_cell.command == CellCommand.RELAY_EARLY


class TestCircuitRecvRelay:
    """Tests for Circuit.recv_relay() method."""

    def test_recv_relay_raises_when_not_open(self):
        """Test that recv_relay() raises when circuit is not open."""
        mock_conn = MagicMock()
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.NEW)

        with pytest.raises(RuntimeError, match="not open"):
            circuit.recv_relay()

    def test_recv_relay_raises_when_no_crypto(self):
        """Test that recv_relay() raises when crypto not initialized."""
        mock_conn = MagicMock()
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)

        with pytest.raises(RuntimeError, match="crypto not initialized"):
            circuit.recv_relay()

    def test_recv_relay_handles_destroy(self):
        """Test that recv_relay() handles DESTROY cells."""
        mock_conn = MagicMock()
        mock_conn.timeout = 30.0

        # Return a DESTROY cell
        destroy_cell = Cell(circ_id=0x80001234, command=CellCommand.DESTROY, payload=b"\x09")
        mock_conn.recv_cell.return_value = destroy_cell

        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)
        crypto = RelayCrypto.create(
            key_forward=b"f" * 16,
            key_backward=b"b" * 16,
            digest_forward=b"df" * 10,
            digest_backward=b"db" * 10,
        )
        circuit._crypto_layers.append(crypto)

        result = circuit.recv_relay()

        assert result is None
        assert circuit.state == CircuitState.CLOSED


class TestCircuitBeginStream:
    """Tests for Circuit.begin_stream() method."""

    def test_begin_stream_allocates_stream_id(self):
        """Test that begin_stream() allocates a stream ID."""
        mock_conn = MagicMock()
        mock_conn.link_protocol = 4
        mock_conn.timeout = 30.0
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)

        # Add crypto layer
        crypto = RelayCrypto.create(
            key_forward=b"f" * 16,
            key_backward=b"b" * 16,
            digest_forward=b"df" * 10,
            digest_backward=b"db" * 10,
        )
        circuit._crypto_layers.append(crypto)

        # Mock receiving CONNECTED response
        # We need to mock recv_relay to return a CONNECTED cell
        with patch.object(circuit, "recv_relay") as mock_recv:
            mock_recv.return_value = RelayCell(
                relay_command=RelayCommand.CONNECTED,
                stream_id=1,
                data=b"\x00\x00\x00\x00\x00\x00\x00\x00",
            )

            stream_id = circuit.begin_stream("example.com", 80)

            assert stream_id == 1
            assert 1 in circuit._streams


class TestCircuitBeginDir:
    """Tests for Circuit.begin_dir() method."""

    def test_begin_dir_allocates_stream_id(self):
        """Test that begin_dir() allocates a stream ID."""
        mock_conn = MagicMock()
        mock_conn.link_protocol = 4
        mock_conn.timeout = 30.0
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)

        crypto = RelayCrypto.create(
            key_forward=b"f" * 16,
            key_backward=b"b" * 16,
            digest_forward=b"df" * 10,
            digest_backward=b"db" * 10,
        )
        circuit._crypto_layers.append(crypto)

        with patch.object(circuit, "recv_relay") as mock_recv:
            mock_recv.return_value = RelayCell(
                relay_command=RelayCommand.CONNECTED,
                stream_id=1,
                data=b"",
            )

            stream_id = circuit.begin_dir()

            assert stream_id == 1


class TestCircuitEndStream:
    """Tests for Circuit.end_stream() method."""

    def test_end_stream_sends_end_cell(self):
        """Test that end_stream() sends an END cell."""
        mock_conn = MagicMock()
        mock_conn.link_protocol = 4
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)

        crypto = RelayCrypto.create(
            key_forward=b"f" * 16,
            key_backward=b"b" * 16,
            digest_forward=b"df" * 10,
            digest_backward=b"db" * 10,
        )
        circuit._crypto_layers.append(crypto)
        circuit._streams[42] = StreamState(stream_id=42)

        circuit.end_stream(42)

        # Verify send_cell was called
        mock_conn.send_cell.assert_called_once()
        # Stream should be removed from tracking
        assert 42 not in circuit._streams


class TestCircuitSendData:
    """Tests for Circuit.send_data() method."""

    def test_send_data_small_payload(self):
        """Test sending small data payload."""
        mock_conn = MagicMock()
        mock_conn.link_protocol = 4
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)

        crypto = RelayCrypto.create(
            key_forward=b"f" * 16,
            key_backward=b"b" * 16,
            digest_forward=b"df" * 10,
            digest_backward=b"db" * 10,
        )
        circuit._crypto_layers.append(crypto)

        circuit.send_data(stream_id=1, data=b"Hello, Tor!")

        mock_conn.send_cell.assert_called_once()


class TestCircuitSendDrop:
    """Tests for Circuit.send_drop() method."""

    def test_send_drop_raises_when_not_open(self):
        """Test that send_drop() raises when circuit is not open."""
        mock_conn = MagicMock()
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.NEW)

        with pytest.raises(RuntimeError, match="not open"):
            circuit.send_drop()

    def test_send_drop_sends_drop_cell(self):
        """Test that send_drop() sends a DROP cell."""
        mock_conn = MagicMock()
        mock_conn.link_protocol = 4
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)

        crypto = RelayCrypto.create(
            key_forward=b"f" * 16,
            key_backward=b"b" * 16,
            digest_forward=b"df" * 10,
            digest_backward=b"db" * 10,
        )
        circuit._crypto_layers.append(crypto)

        circuit.send_drop()

        mock_conn.send_cell.assert_called_once()


class TestCircuitResolve:
    """Tests for Circuit.resolve() method."""

    def test_resolve_returns_empty_on_no_response(self):
        """Test that resolve() returns empty list when no response."""
        mock_conn = MagicMock()
        mock_conn.link_protocol = 4
        mock_conn.timeout = 30.0
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)

        crypto = RelayCrypto.create(
            key_forward=b"f" * 16,
            key_backward=b"b" * 16,
            digest_forward=b"df" * 10,
            digest_backward=b"db" * 10,
        )
        circuit._crypto_layers.append(crypto)

        with patch.object(circuit, "recv_relay") as mock_recv:
            mock_recv.return_value = None

            answers = circuit.resolve("example.com")

            assert answers == []


class TestCircuitFlowControl:
    """Tests for circuit flow control."""

    def test_initial_circuit_window(self):
        """Test initial circuit deliver window value."""
        mock_conn = MagicMock()
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234)

        assert circuit._circuit_deliver_window == CIRCUIT_WINDOW_INITIAL

    def test_stream_state_initial_window(self):
        """Test initial stream window value."""
        state = StreamState(stream_id=1)
        assert state.deliver_window == STREAM_WINDOW_INITIAL


class TestCircuitContextManager:
    """Tests for Circuit context manager support."""

    def test_context_manager_enter(self):
        """Test context manager __enter__ returns circuit."""
        mock_conn = MagicMock()
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234)

        result = circuit.__enter__()

        assert result is circuit

    def test_context_manager_exit_destroys(self):
        """Test context manager __exit__ destroys circuit."""
        mock_conn = MagicMock()
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)

        circuit.__exit__(None, None, None)

        assert circuit.state == CircuitState.CLOSED


class TestCircuitAllocateStreamId:
    """Tests for Circuit._allocate_stream_id() method."""

    def test_allocate_stream_id_starts_at_one(self):
        """Test stream ID allocation starts at 1."""
        mock_conn = MagicMock()
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234)

        stream_id = circuit._allocate_stream_id()

        assert stream_id == 1

    def test_allocate_stream_id_increments(self):
        """Test stream ID allocation increments."""
        mock_conn = MagicMock()
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234)

        id1 = circuit._allocate_stream_id()
        id2 = circuit._allocate_stream_id()
        id3 = circuit._allocate_stream_id()

        assert id1 == 1
        assert id2 == 2
        assert id3 == 3

    def test_allocate_stream_id_wraps(self):
        """Test stream ID allocation wraps around at 0xFFFF."""
        mock_conn = MagicMock()
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234)
        circuit._next_stream_id = 0xFFFF

        id1 = circuit._allocate_stream_id()
        id2 = circuit._allocate_stream_id()

        assert id1 == 0xFFFF
        assert id2 == 1  # Wrapped around


# =============================================================================
# Helper functions for ntor handshake simulation
# =============================================================================


def simulate_ntor_server_response(
    node_id: bytes, relay_ntor_key_bytes: bytes, client_pubkey_bytes: bytes
) -> bytes:
    """
    Simulate a relay's response to an ntor handshake.

    This generates a valid CREATED2/EXTENDED2 HDATA response.

    Args:
        node_id: 20-byte relay node ID
        relay_ntor_key_bytes: 32-byte relay's ntor-onion-key (B)
        client_pubkey_bytes: 32-byte client's ephemeral public key (X)

    Returns:
        64-byte server response: server_pubkey (32) | auth (32)
    """
    import hashlib
    import hmac

    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )

    # Protocol constants (same as in ntor.py)
    PROTOID = b"ntor-curve25519-sha256-1"
    T_MAC = PROTOID + b":mac"
    T_KEY = PROTOID + b":key_extract"
    T_VERIFY = PROTOID + b":verify"

    # Server generates ephemeral keypair (y, Y)
    server_keypair = X25519PrivateKey.generate()
    server_pubkey = server_keypair.public_key().public_bytes_raw()

    # Load keys
    client_pubkey = X25519PublicKey.from_public_bytes(client_pubkey_bytes)
    relay_privkey = X25519PrivateKey.generate()  # This won't match, but we'll use the provided pubkey

    # For testing, we need to actually perform the handshake properly
    # Since we can't access the relay's private key, we'll create a matching pair
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    # Generate a new relay keypair that we control
    relay_keypair = X25519PrivateKey.generate()
    actual_relay_ntor_key = relay_keypair.public_key().public_bytes_raw()

    # Compute shared secrets from server side
    # EXP(X, y) - shared secret with client's ephemeral key
    shared_xy = server_keypair.exchange(client_pubkey)
    # EXP(X, b) - shared secret with relay's ntor key
    shared_xb = relay_keypair.exchange(client_pubkey)

    # Compute secret_input
    secret_input = (
        shared_xy
        + shared_xb
        + node_id
        + actual_relay_ntor_key
        + client_pubkey_bytes
        + server_pubkey
        + PROTOID
    )

    # Derive verify value
    verify = hmac.new(T_VERIFY, secret_input, hashlib.sha256).digest()

    # Compute auth
    auth_input = (
        verify
        + node_id
        + actual_relay_ntor_key
        + server_pubkey
        + client_pubkey_bytes
        + PROTOID
        + b"Server"
    )
    auth = hmac.new(T_MAC, auth_input, hashlib.sha256).digest()

    return server_pubkey + auth, actual_relay_ntor_key


# =============================================================================
# Tests for CREATE_FAST success path
# =============================================================================


class TestCircuitCreateFastSuccess:
    """Tests for Circuit.create_fast() success path."""

    def test_create_fast_success(self):
        """Test successful CREATE_FAST handshake."""
        from torscope.onion.cell import CreatedFastCell, FastCircuitKeys

        mock_conn = MagicMock()
        mock_conn.link_protocol = 4

        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.NEW)

        # We need to intercept the X value sent and create a matching CREATED_FAST response
        sent_cells = []

        def capture_send(cell):
            sent_cells.append(cell)

        mock_conn.send_cell.side_effect = capture_send

        # Setup the response - we'll return a CREATED_FAST cell
        # We need to compute Y and KH that match X
        # Since we don't know X until send_cell is called, we use a side_effect

        def mock_recv():
            # Get the X value from the sent CREATE_FAST cell
            from torscope.onion.cell import CreateFastCell

            sent_create = sent_cells[0]
            # Unpack to get X
            packed = sent_create.pack(4)
            unpacked = CreateFastCell.unpack(packed, 4)
            x = unpacked.x

            # Generate Y and derive keys
            import secrets

            y = secrets.token_bytes(20)
            keys = FastCircuitKeys.from_key_material(x, y)

            # Return CREATED_FAST cell
            created_fast = CreatedFastCell(circ_id=0x80001234, y=y, kh=keys.kh)
            return Cell(
                circ_id=0x80001234,
                command=CellCommand.CREATED_FAST,
                payload=created_fast.pack(4)[5:],  # Extract payload only
            )

        mock_conn.recv_cell.side_effect = mock_recv

        # Perform the handshake
        result = circuit.create_fast("A" * 40)

        assert result is True
        assert circuit.state == CircuitState.OPEN
        assert len(circuit.hops) == 1
        assert circuit.hops[0].fingerprint == "A" * 40
        assert len(circuit._crypto_layers) == 1

    def test_create_fast_destroy_response(self):
        """Test CREATE_FAST with DESTROY response."""
        mock_conn = MagicMock()
        mock_conn.link_protocol = 4

        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.NEW)

        # Return DESTROY cell
        mock_conn.recv_cell.return_value = Cell(
            circ_id=0x80001234,
            command=CellCommand.DESTROY,
            payload=b"\x01",  # PROTOCOL error
        )

        result = circuit.create_fast("A" * 40)

        assert result is False
        assert circuit.state == CircuitState.FAILED

    def test_create_fast_kh_verification_failure(self):
        """Test CREATE_FAST with wrong KH (verification failure)."""
        from torscope.onion.cell import CreatedFastCell

        mock_conn = MagicMock()
        mock_conn.link_protocol = 4

        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.NEW)

        # Return CREATED_FAST with wrong KH
        wrong_kh = b"\x00" * 20  # This won't match the derived KH
        created_fast = CreatedFastCell(
            circ_id=0x80001234,
            y=b"Y" * 20,
            kh=wrong_kh,
        )
        packed = created_fast.pack(4)

        mock_conn.recv_cell.return_value = Cell(
            circ_id=0x80001234,
            command=CellCommand.CREATED_FAST,
            payload=packed[5:],
        )

        result = circuit.create_fast("A" * 40)

        assert result is False
        assert circuit.state == CircuitState.FAILED


# =============================================================================
# Tests for extend_to first hop (CREATE2) success path
# =============================================================================


class TestCircuitExtendToFirstHop:
    """Tests for Circuit.extend_to() first hop via CREATE2."""

    def test_extend_to_first_hop_destroy_response(self):
        """Test extend_to first hop with DESTROY response."""
        mock_conn = MagicMock()
        mock_conn.link_protocol = 4

        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.NEW)

        # Return DESTROY cell
        mock_conn.recv_cell.return_value = Cell(
            circ_id=0x80001234,
            command=CellCommand.DESTROY,
            payload=b"\x01",
        )

        result = circuit.extend_to("A" * 40, b"x" * 32)

        assert result is False
        assert circuit.state == CircuitState.FAILED

    def test_extend_to_first_hop_truncated_created2(self):
        """Test extend_to first hop with truncated CREATED2."""
        mock_conn = MagicMock()
        mock_conn.link_protocol = 4

        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.NEW)

        # Return CREATED2 cell with truncated payload (only 1 byte)
        mock_conn.recv_cell.return_value = Cell(
            circ_id=0x80001234,
            command=CellCommand.CREATED2,
            payload=b"\x00",  # Too short
        )

        result = circuit.extend_to("A" * 40, b"x" * 32)

        assert result is False
        assert circuit.state == CircuitState.FAILED


# =============================================================================
# Tests for multi-hop relay encryption/decryption
# =============================================================================


class TestMultiHopRelayCrypto:
    """Tests for multi-hop relay cell encryption and decryption."""

    def test_send_relay_multi_hop(self):
        """Test send_relay() with multi-hop circuit encrypts in reverse order."""
        mock_conn = MagicMock()
        mock_conn.link_protocol = 4
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)

        # Add multiple crypto layers (simulating 3-hop circuit)
        for i in range(3):
            crypto = RelayCrypto.create(
                key_forward=bytes([i]) * 16,
                key_backward=bytes([i + 10]) * 16,
                digest_forward=bytes([i + 20]) * 20,
                digest_backward=bytes([i + 30]) * 20,
            )
            circuit._crypto_layers.append(crypto)

        relay_cell = RelayCell(relay_command=RelayCommand.DATA, stream_id=1, data=b"test")
        circuit.send_relay(relay_cell)

        # Verify send_cell was called
        mock_conn.send_cell.assert_called_once()
        sent_cell = mock_conn.send_cell.call_args[0][0]
        assert isinstance(sent_cell, Cell)
        assert sent_cell.command == CellCommand.RELAY
        # Payload should be encrypted (509 bytes for relay cell body)
        assert len(sent_cell.payload) == RELAY_BODY_LEN

    def test_recv_relay_skips_padding(self):
        """Test recv_relay() skips PADDING cells."""
        mock_conn = MagicMock()
        mock_conn.link_protocol = 4
        mock_conn.timeout = 30.0

        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)
        crypto = RelayCrypto.create(
            key_forward=b"f" * 16,
            key_backward=b"b" * 16,
            digest_forward=b"df" * 10,
            digest_backward=b"db" * 10,
        )
        circuit._crypto_layers.append(crypto)

        # Return PADDING first, then DESTROY
        padding_cell = Cell(circ_id=0x80001234, command=CellCommand.PADDING, payload=b"\x00" * 509)
        destroy_cell = Cell(circ_id=0x80001234, command=CellCommand.DESTROY, payload=b"\x09")

        mock_conn.recv_cell.side_effect = [padding_cell, destroy_cell]

        result = circuit.recv_relay()

        # Should have skipped PADDING and received DESTROY
        assert result is None
        assert circuit.state == CircuitState.CLOSED
        assert mock_conn.recv_cell.call_count == 2

    def test_recv_relay_skips_vpadding(self):
        """Test recv_relay() skips VPADDING cells."""
        mock_conn = MagicMock()
        mock_conn.link_protocol = 4
        mock_conn.timeout = 30.0

        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)
        crypto = RelayCrypto.create(
            key_forward=b"f" * 16,
            key_backward=b"b" * 16,
            digest_forward=b"df" * 10,
            digest_backward=b"db" * 10,
        )
        circuit._crypto_layers.append(crypto)

        # Return VPADDING first, then DESTROY
        vpadding_cell = Cell(circ_id=0x80001234, command=CellCommand.VPADDING, payload=b"\x00" * 100)
        destroy_cell = Cell(circ_id=0x80001234, command=CellCommand.DESTROY, payload=b"\x09")

        mock_conn.recv_cell.side_effect = [vpadding_cell, destroy_cell]

        result = circuit.recv_relay()

        # Should have skipped VPADDING and received DESTROY
        assert result is None
        assert circuit.state == CircuitState.CLOSED
        assert mock_conn.recv_cell.call_count == 2


# =============================================================================
# Tests for recv_data flow control
# =============================================================================


class TestCircuitRecvData:
    """Tests for Circuit.recv_data() method."""

    def test_recv_data_returns_data(self):
        """Test recv_data() returns data from DATA cell."""
        mock_conn = MagicMock()
        mock_conn.link_protocol = 4
        mock_conn.timeout = 30.0
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)

        crypto = RelayCrypto.create(
            key_forward=b"f" * 16,
            key_backward=b"b" * 16,
            digest_forward=b"df" * 10,
            digest_backward=b"db" * 10,
        )
        circuit._crypto_layers.append(crypto)

        with patch.object(circuit, "recv_relay") as mock_recv:
            mock_recv.return_value = RelayCell(
                relay_command=RelayCommand.DATA,
                stream_id=1,
                data=b"Hello, Tor!",
            )

            result = circuit.recv_data(stream_id=1)

            assert result == b"Hello, Tor!"

    def test_recv_data_returns_none_on_end(self):
        """Test recv_data() returns None on END cell."""
        mock_conn = MagicMock()
        mock_conn.link_protocol = 4
        mock_conn.timeout = 30.0
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)

        crypto = RelayCrypto.create(
            key_forward=b"f" * 16,
            key_backward=b"b" * 16,
            digest_forward=b"df" * 10,
            digest_backward=b"db" * 10,
        )
        circuit._crypto_layers.append(crypto)
        circuit._streams[1] = StreamState(stream_id=1)

        with patch.object(circuit, "recv_relay") as mock_recv:
            mock_recv.return_value = RelayCell(
                relay_command=RelayCommand.END,
                stream_id=1,
                data=b"\x06",  # DONE reason
            )

            result = circuit.recv_data(stream_id=1)

            assert result is None
            assert 1 not in circuit._streams

    def test_recv_data_skips_sendme(self):
        """Test recv_data() skips SENDME cells and gets next data."""
        mock_conn = MagicMock()
        mock_conn.link_protocol = 4
        mock_conn.timeout = 30.0
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)

        crypto = RelayCrypto.create(
            key_forward=b"f" * 16,
            key_backward=b"b" * 16,
            digest_forward=b"df" * 10,
            digest_backward=b"db" * 10,
        )
        circuit._crypto_layers.append(crypto)

        with patch.object(circuit, "recv_relay") as mock_recv:
            # Return SENDME first, then DATA
            mock_recv.side_effect = [
                RelayCell(relay_command=RelayCommand.SENDME, stream_id=0, data=b""),
                RelayCell(relay_command=RelayCommand.DATA, stream_id=1, data=b"Hello!"),
            ]

            result = circuit.recv_data(stream_id=1)

            assert result == b"Hello!"
            assert mock_recv.call_count == 2

    def test_recv_data_wrong_stream_id(self):
        """Test recv_data() returns None for wrong stream ID."""
        mock_conn = MagicMock()
        mock_conn.link_protocol = 4
        mock_conn.timeout = 30.0
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)

        crypto = RelayCrypto.create(
            key_forward=b"f" * 16,
            key_backward=b"b" * 16,
            digest_forward=b"df" * 10,
            digest_backward=b"db" * 10,
        )
        circuit._crypto_layers.append(crypto)

        with patch.object(circuit, "recv_relay") as mock_recv:
            mock_recv.return_value = RelayCell(
                relay_command=RelayCommand.DATA,
                stream_id=99,  # Wrong stream ID
                data=b"Hello!",
            )

            result = circuit.recv_data(stream_id=1)

            assert result is None


# =============================================================================
# Tests for negotiate_padding
# =============================================================================


class TestCircuitNegotiatePadding:
    """Tests for Circuit.negotiate_padding() method."""

    def test_negotiate_padding_raises_when_not_open(self):
        """Test negotiate_padding() raises when circuit is not open."""
        mock_conn = MagicMock()
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.NEW)

        with pytest.raises(RuntimeError, match="not open"):
            circuit.negotiate_padding()

    def test_negotiate_padding_no_response(self):
        """Test negotiate_padding() returns None when no response."""
        mock_conn = MagicMock()
        mock_conn.link_protocol = 4
        mock_conn.timeout = 30.0
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)

        crypto = RelayCrypto.create(
            key_forward=b"f" * 16,
            key_backward=b"b" * 16,
            digest_forward=b"df" * 10,
            digest_backward=b"db" * 10,
        )
        circuit._crypto_layers.append(crypto)

        with patch.object(circuit, "recv_relay") as mock_recv:
            mock_recv.return_value = None

            result = circuit.negotiate_padding()

            assert result is None


# =============================================================================
# Tests for send_data chunking
# =============================================================================


class TestCircuitSendDataChunking:
    """Tests for Circuit.send_data() with large payloads."""

    def test_send_data_large_payload_chunks(self):
        """Test send_data() chunks large payloads."""
        from torscope.onion.relay import RELAY_DATA_LEN

        mock_conn = MagicMock()
        mock_conn.link_protocol = 4
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)

        crypto = RelayCrypto.create(
            key_forward=b"f" * 16,
            key_backward=b"b" * 16,
            digest_forward=b"df" * 10,
            digest_backward=b"db" * 10,
        )
        circuit._crypto_layers.append(crypto)

        # Send data larger than one relay cell (498 bytes max)
        large_data = b"x" * 1500  # Should require 4 cells (498 + 498 + 498 + 6)

        circuit.send_data(stream_id=1, data=large_data)

        # Should have sent 4 cells (ceil(1500 / 498) = 4)
        expected_cells = (len(large_data) + RELAY_DATA_LEN - 1) // RELAY_DATA_LEN
        assert mock_conn.send_cell.call_count == expected_cells


# =============================================================================
# Tests for begin_stream with flags
# =============================================================================


class TestCircuitBeginStreamWithFlags:
    """Tests for Circuit.begin_stream() with BEGIN flags."""

    def test_begin_stream_with_ipv6_ok_flag(self):
        """Test begin_stream() with IPv6_OK flag."""
        from torscope.onion.relay import BEGIN_FLAG_IPV6_OK

        mock_conn = MagicMock()
        mock_conn.link_protocol = 4
        mock_conn.timeout = 30.0
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)

        crypto = RelayCrypto.create(
            key_forward=b"f" * 16,
            key_backward=b"b" * 16,
            digest_forward=b"df" * 10,
            digest_backward=b"db" * 10,
        )
        circuit._crypto_layers.append(crypto)

        with patch.object(circuit, "recv_relay") as mock_recv:
            mock_recv.return_value = RelayCell(
                relay_command=RelayCommand.CONNECTED,
                stream_id=1,
                data=b"\x00" * 8,
            )

            stream_id = circuit.begin_stream("example.com", 80, flags=BEGIN_FLAG_IPV6_OK)

            assert stream_id == 1
            # Verify send_cell was called (BEGIN cell sent)
            mock_conn.send_cell.assert_called_once()

    def test_begin_stream_rejection(self):
        """Test begin_stream() when stream is rejected."""
        mock_conn = MagicMock()
        mock_conn.link_protocol = 4
        mock_conn.timeout = 30.0
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)

        crypto = RelayCrypto.create(
            key_forward=b"f" * 16,
            key_backward=b"b" * 16,
            digest_forward=b"df" * 10,
            digest_backward=b"db" * 10,
        )
        circuit._crypto_layers.append(crypto)

        with patch.object(circuit, "recv_relay") as mock_recv:
            mock_recv.return_value = RelayCell(
                relay_command=RelayCommand.END,
                stream_id=1,
                data=b"\x04",  # EXITPOLICY
            )

            stream_id = circuit.begin_stream("example.com", 80)

            assert stream_id is None


# =============================================================================
# Tests for resolve with responses
# =============================================================================


class TestCircuitResolveResponses:
    """Tests for Circuit.resolve() with various responses."""

    def test_resolve_with_end_response(self):
        """Test resolve() with END response returns empty list."""
        mock_conn = MagicMock()
        mock_conn.link_protocol = 4
        mock_conn.timeout = 30.0
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)

        crypto = RelayCrypto.create(
            key_forward=b"f" * 16,
            key_backward=b"b" * 16,
            digest_forward=b"df" * 10,
            digest_backward=b"db" * 10,
        )
        circuit._crypto_layers.append(crypto)

        with patch.object(circuit, "recv_relay") as mock_recv:
            mock_recv.return_value = RelayCell(
                relay_command=RelayCommand.END,
                stream_id=1,
                data=b"\x02",  # RESOLVEFAILED
            )

            answers = circuit.resolve("example.com")

            assert answers == []

    def test_resolve_stream_id_mismatch(self):
        """Test resolve() with mismatched stream ID."""
        mock_conn = MagicMock()
        mock_conn.link_protocol = 4
        mock_conn.timeout = 30.0
        circuit = Circuit(connection=mock_conn, circ_id=0x80001234, state=CircuitState.OPEN)

        crypto = RelayCrypto.create(
            key_forward=b"f" * 16,
            key_backward=b"b" * 16,
            digest_forward=b"df" * 10,
            digest_backward=b"db" * 10,
        )
        circuit._crypto_layers.append(crypto)

        with patch.object(circuit, "recv_relay") as mock_recv:
            # Return RESOLVED but with wrong stream ID
            mock_recv.return_value = RelayCell(
                relay_command=RelayCommand.RESOLVED,
                stream_id=999,  # Wrong stream ID
                data=b"\x04\x04\x01\x02\x03\x04\x00\x00\x01\x00",  # IPv4 answer
            )

            answers = circuit.resolve("example.com")

            assert answers == []
