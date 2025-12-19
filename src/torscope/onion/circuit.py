"""
Tor circuit implementation.

A circuit is a path through the Tor network, consisting of multiple
hops (relays). Each hop is established using the ntor handshake.
"""

import secrets
import struct
from dataclasses import dataclass, field
from enum import Enum, auto
from types import TracebackType

from torscope.onion.cell import (
    HTYPE_NTOR,
    Cell,
    CellCommand,
    Create2Cell,
    DestroyCell,
)
from torscope.onion.connection import RelayConnection
from torscope.onion.ntor import CircuitKeys, NtorClientState, node_id_from_fingerprint
from torscope.onion.relay import (
    RELAY_BODY_LEN,
    RELAY_DATA_LEN,
    RelayCell,
    RelayCommand,
    RelayCrypto,
    RelayEndReason,
    create_begin_payload,
    create_end_payload,
)


class CircuitState(Enum):
    """Circuit lifecycle states."""

    NEW = auto()  # Just created, not yet built
    BUILDING = auto()  # Handshake in progress
    OPEN = auto()  # Ready for use
    CLOSED = auto()  # Torn down
    FAILED = auto()  # Creation failed


@dataclass
class CircuitHop:
    """A single hop in a circuit."""

    fingerprint: str  # Relay fingerprint (hex)
    ntor_onion_key: bytes  # 32-byte ntor-onion-key
    keys: CircuitKeys | None = None  # Derived keys after handshake


@dataclass
class Circuit:
    """
    A Tor circuit through one or more relays.

    Currently supports single-hop circuits for testing.
    """

    connection: RelayConnection
    circ_id: int = 0
    state: CircuitState = CircuitState.NEW
    hops: list[CircuitHop] = field(default_factory=list)
    _crypto: RelayCrypto | None = field(default=None, repr=False)
    _next_stream_id: int = field(default=1, repr=False)

    @classmethod
    def create(cls, connection: RelayConnection) -> "Circuit":
        """
        Create a new circuit on an established connection.

        Args:
            connection: An established RelayConnection

        Returns:
            New Circuit instance with a unique circuit ID
        """
        # Generate a random circuit ID
        # For link protocol 4+, circ_id is 4 bytes
        # High bit indicates who created the circuit (1 = we did)
        circ_id = secrets.randbits(31) | 0x80000000

        return cls(connection=connection, circ_id=circ_id)

    def extend_to(
        self,
        fingerprint: str,
        ntor_onion_key: bytes,
    ) -> bool:
        """
        Extend circuit to a relay (create first hop or extend).

        For now, only supports creating the first hop.

        Args:
            fingerprint: Relay's fingerprint (40 hex chars)
            ntor_onion_key: Relay's ntor-onion-key (32 bytes, base64 decoded)

        Returns:
            True if handshake succeeded, False otherwise
        """
        if self.state == CircuitState.CLOSED:
            raise RuntimeError("Circuit is closed")

        if len(self.hops) > 0:
            raise NotImplementedError("Multi-hop circuits not yet implemented")

        self.state = CircuitState.BUILDING

        # Get node ID from fingerprint
        node_id = node_id_from_fingerprint(fingerprint)

        # Create ntor handshake state
        ntor_state = NtorClientState.create(node_id, ntor_onion_key)

        # Create onion skin (client's handshake data)
        onion_skin = ntor_state.create_onion_skin()

        # Send CREATE2 cell
        create2 = Create2Cell(
            circ_id=self.circ_id,
            htype=HTYPE_NTOR,
            hdata=onion_skin,
        )
        self.connection.send_cell(create2)

        # Receive response
        response = self.connection.recv_cell()

        if response.command == CellCommand.CREATED2:
            # Extract HDATA from CREATED2 payload
            # Payload format: HLEN (2 bytes) + HDATA
            hlen = struct.unpack(">H", response.payload[0:2])[0]
            hdata = response.payload[2 : 2 + hlen]

            # Complete handshake and derive keys
            key_material = ntor_state.complete_handshake(hdata)

            if key_material is None:
                self.state = CircuitState.FAILED
                return False

            # Store hop with keys
            keys = CircuitKeys.from_key_material(key_material)
            hop = CircuitHop(
                fingerprint=fingerprint,
                ntor_onion_key=ntor_onion_key,
                keys=keys,
            )
            self.hops.append(hop)

            # Initialize crypto for relay cells
            self._crypto = RelayCrypto.create(
                key_forward=keys.key_forward,
                key_backward=keys.key_backward,
                digest_forward=keys.digest_forward,
                digest_backward=keys.digest_backward,
            )

            self.state = CircuitState.OPEN
            return True

        if response.command == CellCommand.DESTROY:
            # Circuit creation was rejected
            self.state = CircuitState.FAILED
            return False

        # Unexpected response
        self.state = CircuitState.FAILED
        return False

    def destroy(self) -> None:
        """Tear down the circuit."""
        if self.state in (CircuitState.CLOSED, CircuitState.NEW):
            return

        try:
            destroy = DestroyCell(
                circ_id=self.circ_id,
                reason=DestroyCell.REASON_FINISHED,
            )
            self.connection.send_cell(destroy)
        except Exception:  # pylint: disable=broad-exception-caught
            pass

        self.state = CircuitState.CLOSED

    @property
    def is_open(self) -> bool:
        """Check if circuit is ready for use."""
        return self.state == CircuitState.OPEN

    def _allocate_stream_id(self) -> int:
        """Allocate a new stream ID."""
        stream_id = self._next_stream_id
        self._next_stream_id += 1
        if self._next_stream_id > 0xFFFF:
            self._next_stream_id = 1  # Wrap around (0 is reserved for control)
        return stream_id

    def send_relay(self, relay_cell: RelayCell) -> None:
        """
        Send an encrypted relay cell on this circuit.

        Args:
            relay_cell: RelayCell to send
        """
        if not self.is_open:
            raise RuntimeError("Circuit is not open")
        if self._crypto is None:
            raise RuntimeError("Circuit crypto not initialized")

        # Encrypt the relay cell
        encrypted_payload = self._crypto.encrypt_forward(relay_cell)

        # Wrap in a RELAY cell
        cell = Cell(
            circ_id=self.circ_id,
            command=CellCommand.RELAY,
            payload=encrypted_payload,
        )
        self.connection.send_cell(cell)

    def recv_relay(self) -> RelayCell | None:
        """
        Receive and decrypt a relay cell from this circuit.

        Returns:
            Decrypted RelayCell, or None if decryption failed
        """
        if not self.is_open:
            raise RuntimeError("Circuit is not open")
        if self._crypto is None:
            raise RuntimeError("Circuit crypto not initialized")

        # Receive cell
        cell = self.connection.recv_cell()

        if cell.command == CellCommand.DESTROY:
            self.state = CircuitState.CLOSED
            return None

        if cell.command not in (CellCommand.RELAY, CellCommand.RELAY_EARLY):
            # Unexpected cell type
            return None

        # Decrypt relay cell
        return self._crypto.decrypt_backward(cell.payload[:RELAY_BODY_LEN])

    def begin_stream(self, address: str, port: int) -> int | None:
        """
        Open a stream to a remote address.

        Args:
            address: Hostname or IP address
            port: Port number

        Returns:
            Stream ID if successful, None if failed
        """
        stream_id = self._allocate_stream_id()

        # Send RELAY_BEGIN
        begin_cell = RelayCell(
            relay_command=RelayCommand.BEGIN,
            stream_id=stream_id,
            data=create_begin_payload(address, port),
        )
        self.send_relay(begin_cell)

        # Wait for RELAY_CONNECTED or RELAY_END
        response = self.recv_relay()
        if response is None:
            return None

        if response.relay_command == RelayCommand.CONNECTED:
            return stream_id

        if response.relay_command == RelayCommand.END:
            # Stream was rejected
            return None

        # Unexpected response
        return None

    def end_stream(self, stream_id: int, reason: RelayEndReason = RelayEndReason.DONE) -> None:
        """
        Close a stream.

        Args:
            stream_id: Stream ID to close
            reason: Reason for closing
        """
        end_cell = RelayCell(
            relay_command=RelayCommand.END,
            stream_id=stream_id,
            data=create_end_payload(reason),
        )
        self.send_relay(end_cell)

    def send_data(self, stream_id: int, data: bytes) -> None:
        """
        Send data on a stream.

        Args:
            stream_id: Stream ID
            data: Data to send (will be chunked if necessary)
        """
        # Send in chunks
        offset = 0
        while offset < len(data):
            chunk = data[offset : offset + RELAY_DATA_LEN]
            data_cell = RelayCell(
                relay_command=RelayCommand.DATA,
                stream_id=stream_id,
                data=chunk,
            )
            self.send_relay(data_cell)
            offset += RELAY_DATA_LEN

    def recv_data(self, stream_id: int) -> bytes | None:
        """
        Receive data from a stream.

        Args:
            stream_id: Stream ID

        Returns:
            Data bytes, or None if stream ended or error
        """
        response = self.recv_relay()
        if response is None:
            return None

        if response.stream_id != stream_id:
            # Data for different stream (shouldn't happen in single-stream use)
            return None

        if response.relay_command == RelayCommand.DATA:
            return response.data

        if response.relay_command == RelayCommand.END:
            return None

        # Unexpected command
        return None

    def __enter__(self) -> "Circuit":
        """Context manager entry."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Context manager exit - destroy circuit."""
        self.destroy()
