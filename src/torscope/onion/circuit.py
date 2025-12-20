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
    LinkSpecifier,
    RelayCell,
    RelayCommand,
    RelayCrypto,
    RelayEndReason,
    ResolvedAnswer,
    create_begin_payload,
    create_end_payload,
    create_extend2_payload,
    create_resolve_payload,
    parse_extended2_payload,
    parse_resolved_payload,
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

    Supports multi-hop circuits with layered encryption.
    """

    connection: RelayConnection
    circ_id: int = 0
    state: CircuitState = CircuitState.NEW
    hops: list[CircuitHop] = field(default_factory=list)
    _crypto_layers: list[RelayCrypto] = field(default_factory=list, repr=False)
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
        ip: str | None = None,
        port: int | None = None,
    ) -> bool:
        """
        Extend circuit to a relay (create first hop or extend through existing hops).

        For the first hop, uses CREATE2 cell directly.
        For subsequent hops, uses RELAY_EXTEND2 through the existing circuit.

        Args:
            fingerprint: Relay's fingerprint (40 hex chars)
            ntor_onion_key: Relay's ntor-onion-key (32 bytes, base64 decoded)
            ip: Relay's IP address (required for extending, optional for first hop)
            port: Relay's OR port (required for extending, optional for first hop)

        Returns:
            True if handshake succeeded, False otherwise
        """
        if self.state == CircuitState.CLOSED:
            raise RuntimeError("Circuit is closed")

        # Get node ID from fingerprint
        node_id = node_id_from_fingerprint(fingerprint)

        # Create ntor handshake state
        ntor_state = NtorClientState.create(node_id, ntor_onion_key)

        # Create onion skin (client's handshake data)
        onion_skin = ntor_state.create_onion_skin()

        if len(self.hops) == 0:
            # First hop - use CREATE2
            return self._create_first_hop(fingerprint, ntor_onion_key, ntor_state, onion_skin)

        # Extending - use RELAY_EXTEND2
        if ip is None or port is None:
            raise ValueError("ip and port required for extending circuit")

        return self._extend_circuit(fingerprint, ntor_onion_key, ntor_state, onion_skin, ip, port)

    def _create_first_hop(
        self,
        fingerprint: str,
        ntor_onion_key: bytes,
        ntor_state: NtorClientState,
        onion_skin: bytes,
    ) -> bool:
        """Create the first hop using CREATE2 cell."""
        self.state = CircuitState.BUILDING

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

            # Add crypto layer
            self._crypto_layers.append(
                RelayCrypto.create(
                    key_forward=keys.key_forward,
                    key_backward=keys.key_backward,
                    digest_forward=keys.digest_forward,
                    digest_backward=keys.digest_backward,
                )
            )

            self.state = CircuitState.OPEN
            return True

        if response.command == CellCommand.DESTROY:
            self.state = CircuitState.FAILED
            return False

        self.state = CircuitState.FAILED
        return False

    def _extend_circuit(
        self,
        fingerprint: str,
        ntor_onion_key: bytes,
        ntor_state: NtorClientState,
        onion_skin: bytes,
        ip: str,
        port: int,
    ) -> bool:
        """Extend circuit using RELAY_EXTEND2."""
        # Build link specifiers
        link_specs = [
            LinkSpecifier.from_ipv4(ip, port),
            LinkSpecifier.from_legacy_id(fingerprint),
        ]

        # Create EXTEND2 payload
        extend2_data = create_extend2_payload(
            link_specifiers=link_specs,
            htype=HTYPE_NTOR,
            hdata=onion_skin,
        )

        # Send RELAY_EXTEND2 (stream_id must be 0 for control messages)
        # Must use RELAY_EARLY cell for EXTEND2 per tor-spec
        extend2_cell = RelayCell(
            relay_command=RelayCommand.EXTEND2,
            stream_id=0,
            data=extend2_data,
        )
        self.send_relay(extend2_cell, early=True)

        # Wait for RELAY_EXTENDED2
        response = self.recv_relay()
        if response is None:
            self.state = CircuitState.FAILED
            return False

        if response.relay_command == RelayCommand.EXTENDED2:
            # Parse EXTENDED2 payload (same as CREATED2: HLEN + HDATA)
            hdata = parse_extended2_payload(response.data)

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

            # Add crypto layer for new hop
            self._crypto_layers.append(
                RelayCrypto.create(
                    key_forward=keys.key_forward,
                    key_backward=keys.key_backward,
                    digest_forward=keys.digest_forward,
                    digest_backward=keys.digest_backward,
                )
            )

            return True

        # Extension failed (could be TRUNCATED or other error)
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

    def send_relay(self, relay_cell: RelayCell, early: bool = False) -> None:
        """
        Send an encrypted relay cell on this circuit.

        For multi-hop circuits, encrypts with each hop's key in reverse order
        (last hop first, then middle, then first).

        Args:
            relay_cell: RelayCell to send
            early: If True, send as RELAY_EARLY (required for EXTEND2)
        """
        if not self.is_open:
            raise RuntimeError("Circuit is not open")
        if not self._crypto_layers:
            raise RuntimeError("Circuit crypto not initialized")

        # Encrypt with the last hop's key first (the exit node),
        # then each preceding hop. The first hop decrypts first,
        # passing to middle, which decrypts and passes to exit.
        #
        # For the last crypto layer, we use encrypt_forward which
        # sets the digest. For earlier layers, we just encrypt.
        last_layer = self._crypto_layers[-1]
        encrypted_payload = last_layer.encrypt_forward(relay_cell)

        # Encrypt with remaining layers in reverse order
        for layer in reversed(self._crypto_layers[:-1]):
            encrypted_payload = layer.encrypt_raw(encrypted_payload)

        # Wrap in a RELAY or RELAY_EARLY cell
        command = CellCommand.RELAY_EARLY if early else CellCommand.RELAY
        cell = Cell(
            circ_id=self.circ_id,
            command=command,
            payload=encrypted_payload,
        )
        self.connection.send_cell(cell)

    def recv_relay(self, debug: bool = False) -> RelayCell | None:
        """
        Receive and decrypt a relay cell from this circuit.

        For multi-hop circuits, decrypts with each hop's key in order
        (first hop first, then middle, then last).

        Args:
            debug: If True, print debug info

        Returns:
            Decrypted RelayCell, or None if decryption failed
        """
        if not self.is_open:
            raise RuntimeError("Circuit is not open")
        if not self._crypto_layers:
            raise RuntimeError("Circuit crypto not initialized")

        # Receive cell
        cell = self.connection.recv_cell()

        if debug:
            print(f"    [debug] Received cell: cmd={cell.command.name}")

        if cell.command == CellCommand.DESTROY:
            reason = cell.payload[0] if cell.payload else 0
            reason_names = {
                0: "NONE",
                1: "PROTOCOL",
                2: "INTERNAL",
                3: "REQUESTED",
                4: "HIBERNATING",
                5: "RESOURCELIMIT",
                6: "CONNECTFAILED",
                7: "OR_IDENTITY",
                8: "CHANNEL_CLOSED",
                9: "FINISHED",
                10: "TIMEOUT",
                11: "DESTROYED",
                12: "NOSUCHSERVICE",
            }
            if debug:
                print(
                    f"    [debug] DESTROY reason: {reason} ({reason_names.get(reason, 'UNKNOWN')})"
                )
            self.state = CircuitState.CLOSED
            return None

        if cell.command not in (CellCommand.RELAY, CellCommand.RELAY_EARLY):
            # Unexpected cell type
            if debug:
                print(f"    [debug] Unexpected cell type: {cell.command.name}")
            return None

        # Decrypt through each layer in order (first hop first)
        # Each relay on the return path encrypted with its key,
        # so we decrypt in the same order they encrypted.
        payload = cell.payload[:RELAY_BODY_LEN]

        for i, layer in enumerate(self._crypto_layers):
            # For all but the last layer, just decrypt raw
            if i < len(self._crypto_layers) - 1:
                payload = layer.decrypt_raw(payload)
            else:
                # Last layer - check digest and parse
                result = layer.decrypt_backward(payload)
                if debug and result is None:
                    print("    [debug] decrypt_backward failed (bad recognized or digest)")
                return result

        return None

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

    def begin_dir(self) -> int | None:
        """
        Open a directory stream to the exit relay.

        This uses RELAY_BEGIN_DIR to connect to the relay's built-in
        directory server. The relay must have the V2Dir flag.

        Returns:
            Stream ID if successful, None if failed
        """
        stream_id = self._allocate_stream_id()

        # Send RELAY_BEGIN_DIR (no payload needed)
        begin_dir_cell = RelayCell(
            relay_command=RelayCommand.BEGIN_DIR,
            stream_id=stream_id,
            data=b"",
        )
        self.send_relay(begin_dir_cell)

        # Wait for RELAY_CONNECTED or RELAY_END
        response = self.recv_relay()
        if response is None:
            return None

        if response.relay_command == RelayCommand.CONNECTED:
            return stream_id

        if response.relay_command == RelayCommand.END:
            # Directory stream was rejected (relay may not support V2Dir)
            return None

        # Unexpected response
        return None

    def resolve(self, hostname: str) -> list[ResolvedAnswer]:
        """
        Resolve a hostname via the exit relay (RELAY_RESOLVE).

        This sends a DNS resolution request through the circuit to the
        exit relay. The relay performs the DNS lookup and returns results.
        No actual stream is created - only the resolution is performed.

        For reverse DNS lookups, pass an in-addr.arpa address.

        Args:
            hostname: Hostname to resolve (e.g., "example.com")

        Returns:
            List of ResolvedAnswer objects containing resolved addresses.
            Empty list if resolution failed.
        """
        # RESOLVE uses a stream ID that must match the RESOLVED response
        # but no actual stream is created
        stream_id = self._allocate_stream_id()

        # Send RELAY_RESOLVE
        resolve_cell = RelayCell(
            relay_command=RelayCommand.RESOLVE,
            stream_id=stream_id,
            data=create_resolve_payload(hostname),
        )
        self.send_relay(resolve_cell)

        # Wait for RELAY_RESOLVED
        response = self.recv_relay()
        if response is None:
            return []

        if response.relay_command == RelayCommand.RESOLVED:
            if response.stream_id != stream_id:
                # Mismatched stream ID
                return []
            return parse_resolved_payload(response.data)

        if response.relay_command == RelayCommand.END:
            # Resolution failed
            return []

        # Unexpected response
        return []

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

    def send_data(self, stream_id: int, data: bytes, debug: bool = False) -> None:
        """
        Send data on a stream.

        Args:
            stream_id: Stream ID
            data: Data to send (will be chunked if necessary)
            debug: If True, print debug info
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
            if debug:
                print(f"    [debug] Sending DATA: stream={stream_id} len={len(chunk)}")
            self.send_relay(data_cell)
            offset += RELAY_DATA_LEN

    def recv_data(self, stream_id: int, debug: bool = False) -> bytes | None:
        """
        Receive data from a stream.

        Args:
            stream_id: Stream ID
            debug: If True, print debug info

        Returns:
            Data bytes, or None if stream ended or error
        """
        response = self.recv_relay(debug=debug)
        if response is None:
            if debug:
                print("    [debug] recv_relay returned None")
            return None

        if debug:
            print(
                f"    [debug] Got relay cmd={response.relay_command.name} "
                f"stream={response.stream_id} len={len(response.data)}"
            )

        if response.stream_id != stream_id:
            # Data for different stream (shouldn't happen in single-stream use)
            if debug:
                print(f"    [debug] Wrong stream_id: got {response.stream_id}, want {stream_id}")
            return None

        if response.relay_command == RelayCommand.DATA:
            return response.data

        if response.relay_command == RelayCommand.END:
            if debug:
                print("    [debug] Stream ended (RELAY_END)")
            return None

        # Unexpected command - could be SENDME, etc.
        if debug:
            print(f"    [debug] Unexpected relay command: {response.relay_command.name}")
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
