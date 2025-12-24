"""
Tor circuit implementation.

A circuit is a path through the Tor network, consisting of multiple
hops (relays). Each hop is established using the ntor handshake.
"""

import secrets
import struct
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from types import TracebackType

from torscope import output
from torscope.onion.cell import (
    HTYPE_NTOR,
    Cell,
    CellCommand,
    Create2Cell,
    CreatedFastCell,
    CreateFastCell,
    DestroyCell,
    FastCircuitKeys,
)
from torscope.onion.connection import RelayConnection
from torscope.onion.ntor import CircuitKeys, NtorClientState, node_id_from_fingerprint
from torscope.onion.relay import (
    CIRCUIT_SENDME_THRESHOLD,
    CIRCUIT_WINDOW_INCREMENT,
    CIRCUIT_WINDOW_INITIAL,
    RELAY_BODY_LEN,
    RELAY_DATA_LEN,
    SENDME_VERSION_1,
    STREAM_SENDME_THRESHOLD,
    STREAM_WINDOW_INCREMENT,
    STREAM_WINDOW_INITIAL,
    CircpadCommand,
    CircpadMachineType,
    LinkSpecifier,
    PaddingNegotiated,
    RelayCell,
    RelayCommand,
    RelayCrypto,
    RelayEndReason,
    ResolvedAnswer,
    create_begin_payload,
    create_end_payload,
    create_extend2_payload,
    create_padding_negotiate_payload,
    create_resolve_payload,
    create_sendme_payload,
    parse_extended2_payload,
    parse_padding_negotiated_payload,
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
class StreamState:
    """Flow control state for a stream."""

    stream_id: int
    deliver_window: int = STREAM_WINDOW_INITIAL  # Decrements on DATA received


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

    # Flow control state (for receiving)
    # See: https://spec.torproject.org/tor-spec/flow-control.html
    _circuit_deliver_window: int = field(default=CIRCUIT_WINDOW_INITIAL, repr=False)
    _streams: dict[int, StreamState] = field(default_factory=dict, repr=False)

    # For authenticated SENDME v1: track the digest of the cell that will trigger SENDME
    # This is captured when the window crosses the threshold boundary
    _sendme_digest: bytes = field(default=b"", repr=False)

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
        output.debug(f"Allocated circuit ID: {circ_id:#010x}")

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

    def create_fast(self, fingerprint: str) -> bool:
        """
        Create a one-hop circuit using CREATE_FAST handshake.

        CREATE_FAST uses a simpler key exchange that doesn't require the relay's
        ntor-onion-key. It relies on TLS for identity verification and uses SHA1-based
        key derivation. Only suitable for one-hop circuits.

        Args:
            fingerprint: Relay's fingerprint (40 hex chars)

        Returns:
            True if handshake succeeded, False otherwise

        See: https://spec.torproject.org/tor-spec/create-created-cells.html
        """
        if self.state == CircuitState.CLOSED:
            raise RuntimeError("Circuit is closed")
        if len(self.hops) > 0:
            raise RuntimeError("CREATE_FAST can only be used for the first hop")

        self.state = CircuitState.BUILDING
        output.verbose("CREATE_FAST → (simple handshake)")

        # Generate 20 random bytes (X)
        x = secrets.token_bytes(20)
        output.debug(f"Generated X: {x.hex()[:20]}...")

        # Send CREATE_FAST cell
        create_fast = CreateFastCell(circ_id=self.circ_id, x=x)
        self.connection.send_cell(create_fast)

        # Receive response
        response = self.connection.recv_cell()
        output.verbose(f"{response.command.name} ←")

        if response.command == CellCommand.CREATED_FAST:
            # Parse CREATED_FAST response
            try:
                created_fast = CreatedFastCell.unpack(
                    response.pack(self.connection.link_protocol),
                    self.connection.link_protocol,
                )
            except ValueError as e:
                output.debug(f"Failed to parse CREATED_FAST: {e}")
                self.state = CircuitState.FAILED
                return False

            output.debug(f"Received Y: {created_fast.y.hex()[:20]}...")
            output.debug(f"Received KH: {created_fast.kh.hex()}")

            # Derive keys using KDF-TOR
            keys = FastCircuitKeys.from_key_material(x, created_fast.y)
            output.debug(f"Derived KH: {keys.kh.hex()}")

            # Verify derivative key hash
            if not keys.verify(created_fast.kh):
                output.debug("KH verification failed!")
                self.state = CircuitState.FAILED
                return False

            output.debug("KH verified successfully")
            output.debug(f"Derived circuit keys: Kf={keys.key_forward.hex()}")

            # Store hop (without ntor_onion_key since we didn't use it)
            hop = CircuitHop(
                fingerprint=fingerprint,
                ntor_onion_key=b"",  # Not used for CREATE_FAST
                keys=None,  # FastCircuitKeys is different from CircuitKeys
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
            output.verbose(f"One-hop circuit established via CREATE_FAST ({fingerprint[:16]}...)")
            return True

        if response.command == CellCommand.DESTROY:
            reason = response.payload[0] if response.payload else 0
            output.debug(f"Received DESTROY: reason={reason}")
            self.state = CircuitState.FAILED
            return False

        output.debug(f"Unexpected response: {response.command.name}")
        self.state = CircuitState.FAILED
        return False

    def _create_first_hop(
        self,
        fingerprint: str,
        ntor_onion_key: bytes,
        ntor_state: NtorClientState,
        onion_skin: bytes,
    ) -> bool:
        """Create the first hop using CREATE2 cell."""
        self.state = CircuitState.BUILDING
        output.debug(f"Creating first hop to {fingerprint[:16]}...")

        # Send CREATE2 cell
        output.verbose(f"CREATE2 → (ntor handshake, {len(onion_skin)} bytes)")
        create2 = Create2Cell(
            circ_id=self.circ_id,
            htype=HTYPE_NTOR,
            hdata=onion_skin,
        )
        self.connection.send_cell(create2)

        # Receive response
        response = self.connection.recv_cell()
        output.verbose(f"{response.command.name} ←")

        if response.command == CellCommand.CREATED2:
            # Extract HDATA from CREATED2 payload
            payload = response.payload
            if len(payload) < 2:
                output.debug(f"CREATED2 payload too short: {len(payload)}")
                self.state = CircuitState.FAILED
                return False

            hlen = struct.unpack(">H", payload[0:2])[0]
            if len(payload) < 2 + hlen:
                output.debug(f"CREATED2 hdata truncated: need {2 + hlen}, have {len(payload)}")
                self.state = CircuitState.FAILED
                return False

            hdata = payload[2 : 2 + hlen]
            output.debug(f"CREATED2 hdata: {hlen} bytes")

            # Complete handshake and derive keys
            output.debug("Completing ntor handshake and deriving keys")
            key_material = ntor_state.complete_handshake(hdata)

            if key_material is None:
                output.debug("ntor handshake failed")
                self.state = CircuitState.FAILED
                return False

            # Store hop with keys
            keys = CircuitKeys.from_key_material(key_material)
            output.debug(f"Derived circuit keys: Kf={keys.key_forward.hex()[:16]}...")
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
            output.verbose(f"First hop established ({fingerprint[:16]}...)")
            return True

        if response.command == CellCommand.DESTROY:
            output.debug(f"Received DESTROY: {response.payload[0] if response.payload else 0}")
            self.state = CircuitState.FAILED
            return False

        output.debug(f"Unexpected response: {response.command.name}")
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
        output.debug(f"Extending circuit to {fingerprint[:16]}... ({ip}:{port})")

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
        output.verbose(f"RELAY_EXTEND2 → {ip}:{port}")
        extend2_cell = RelayCell(
            relay_command=RelayCommand.EXTEND2,
            stream_id=0,
            data=extend2_data,
        )
        self.send_relay(extend2_cell, early=True)

        # Wait for RELAY_EXTENDED2
        response = self.recv_relay()
        if response is None:
            output.debug("No response to EXTEND2")
            self.state = CircuitState.FAILED
            return False

        output.verbose(f"{response.relay_command.name} ←")

        if response.relay_command == RelayCommand.EXTENDED2:
            # Parse EXTENDED2 payload (same as CREATED2: HLEN + HDATA)
            hdata = parse_extended2_payload(response.data)
            output.debug(f"EXTENDED2 hdata: {len(hdata)} bytes")

            # Complete handshake and derive keys
            output.debug("Completing ntor handshake and deriving keys")
            key_material = ntor_state.complete_handshake(hdata)

            if key_material is None:
                output.debug("ntor handshake failed")
                self.state = CircuitState.FAILED
                return False

            # Store hop with keys
            keys = CircuitKeys.from_key_material(key_material)
            output.debug(f"Derived circuit keys: Kf={keys.key_forward.hex()[:16]}...")
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

            output.verbose(f"Hop {len(self.hops)} established ({fingerprint[:16]}...)")
            return True

        # Extension failed (could be TRUNCATED or other error)
        output.debug(f"Extension failed: {response.relay_command.name}")
        return False

    def destroy(self) -> None:
        """Tear down the circuit."""
        if self.state in (CircuitState.CLOSED, CircuitState.NEW):
            return

        output.verbose(f"DESTROY → (circuit {self.circ_id:#010x})")
        try:
            destroy = DestroyCell(
                circ_id=self.circ_id,
                reason=DestroyCell.REASON_FINISHED,
            )
            self.connection.send_cell(destroy)
        except Exception:  # pylint: disable=broad-exception-caught
            pass

        self.state = CircuitState.CLOSED
        output.debug("Circuit destroyed")

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

        DROP cells (long-range dummy traffic) are logged and skipped.

        Args:
            debug: If True, print debug info

        Returns:
            Decrypted RelayCell, or None if decryption failed
        """
        if not self.is_open:
            raise RuntimeError("Circuit is not open")
        if not self._crypto_layers:
            raise RuntimeError("Circuit crypto not initialized")

        # Receive cell (skip PADDING and DROP cells, with timeout)
        start_time = time.time()
        timeout = self.connection.timeout

        while True:
            # Check if we've exceeded the connection timeout
            if time.time() - start_time > timeout:
                raise TimeoutError("Timeout while waiting for relay cell")

            cell = self.connection.recv_cell()

            # PADDING cells (link-level) should be silently ignored
            if cell.command == CellCommand.PADDING:
                output.debug("Received PADDING cell, skipping")
                continue

            # VPADDING cells (variable-length link padding) should be logged and skipped
            if cell.command == CellCommand.VPADDING:
                output.debug(f"Received VPADDING cell ({len(cell.payload)} bytes), skipping")
                continue

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
                        f"    [debug] DESTROY reason: {reason} "
                        f"({reason_names.get(reason, 'UNKNOWN')})"
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

            if debug:
                print(f"    [debug] Decrypting through {len(self._crypto_layers)} layers")

            result = None
            for i, layer in enumerate(self._crypto_layers):
                # For all but the last layer, just decrypt raw
                if i < len(self._crypto_layers) - 1:
                    payload = layer.decrypt_raw(payload)
                    if debug:
                        recognized = (payload[1] << 8) | payload[2]
                        print(f"    [debug] After layer {i}: recognized={recognized}")
                else:
                    # Last layer - check digest and parse
                    result = layer.decrypt_backward(payload)
                    if debug:
                        if result is None:
                            recognized = (payload[1] << 8) | payload[2]
                            print(f"    [debug] Layer {i} failed (recognized={recognized})")
                        else:
                            cmd = result.relay_command.name
                            print(f"    [debug] Layer {i} decrypt_backward OK: {cmd}")

            # Handle decrypted relay cell
            if result is None:
                return None

            # DROP cells (long-range dummy traffic) should be logged and skipped
            if result.relay_command == RelayCommand.DROP:
                output.debug("Received DROP cell (long-range dummy traffic), discarding")
                continue

            # Flow control: track windows and send SENDMEs for DATA cells
            if result.relay_command == RelayCommand.DATA:
                # Use last layer (the one that successfully decrypted the cell)
                self._handle_data_flow_control(result, self._crypto_layers[-1], debug)

            return result

    def _handle_data_flow_control(
        self, data_cell: RelayCell, crypto_layer: RelayCrypto, debug: bool = False
    ) -> None:
        """Handle flow control when a DATA cell is received.

        Decrements circuit and stream windows, captures digest for authenticated
        SENDME, and sends SENDME cells when thresholds are reached.

        Args:
            data_cell: The received DATA relay cell
            crypto_layer: The crypto layer (for digest capture)
            debug: If True, print debug info
        """
        # Decrement circuit deliver window
        self._circuit_deliver_window -= 1

        if debug:
            print(
                f"    [debug] Circuit window: {self._circuit_deliver_window + 1} → "
                f"{self._circuit_deliver_window}"
            )

        # Check if we need to capture digest for authenticated SENDME
        # Capture when we cross from above threshold to at/below threshold
        if self._circuit_deliver_window == CIRCUIT_SENDME_THRESHOLD:
            # This cell triggered the SENDME - capture its digest
            self._sendme_digest = crypto_layer.get_backward_digest()
            if debug:
                print(f"    [debug] Captured SENDME digest: {self._sendme_digest[:8].hex()}...")

        # Check if we need to send circuit-level SENDME
        if self._circuit_deliver_window <= CIRCUIT_SENDME_THRESHOLD:
            self._send_circuit_sendme()
            self._circuit_deliver_window += CIRCUIT_WINDOW_INCREMENT

        # Handle stream-level flow control
        stream_id = data_cell.stream_id
        if stream_id > 0 and stream_id in self._streams:
            stream = self._streams[stream_id]
            stream.deliver_window -= 1

            if debug:
                print(
                    f"    [debug] Stream {stream_id} window: {stream.deliver_window + 1} → "
                    f"{stream.deliver_window}"
                )

            # Check if we need to send stream-level SENDME
            if stream.deliver_window <= STREAM_SENDME_THRESHOLD:
                self._send_stream_sendme(stream_id)
                stream.deliver_window += STREAM_WINDOW_INCREMENT

    def _send_circuit_sendme(self) -> None:
        """Send circuit-level SENDME cell (stream_id=0).

        Uses authenticated SENDME v1 with the digest captured when
        the window crossed the threshold.
        """
        sendme_data = create_sendme_payload(
            version=SENDME_VERSION_1,
            digest=self._sendme_digest,
        )
        sendme = RelayCell(
            relay_command=RelayCommand.SENDME,
            stream_id=0,  # Circuit-level
            data=sendme_data,
        )
        self.send_relay(sendme)
        output.debug(
            f"Sent circuit SENDME (window: {self._circuit_deliver_window} → "
            f"{self._circuit_deliver_window + CIRCUIT_WINDOW_INCREMENT})"
        )

    def _send_stream_sendme(self, stream_id: int) -> None:
        """Send stream-level SENDME cell.

        Stream-level SENDMEs use v0 (no authentication required).
        """
        sendme_data = create_sendme_payload(version=0)  # Stream SENDMEs are v0
        sendme = RelayCell(
            relay_command=RelayCommand.SENDME,
            stream_id=stream_id,
            data=sendme_data,
        )
        self.send_relay(sendme)
        stream = self._streams.get(stream_id)
        if stream:
            output.debug(
                f"Sent stream SENDME for stream {stream_id} (window: {stream.deliver_window} → "
                f"{stream.deliver_window + STREAM_WINDOW_INCREMENT})"
            )

    def begin_stream(self, address: str, port: int, flags: int = 0) -> int | None:
        """
        Open a stream to a remote address.

        Args:
            address: Hostname or IP address
            port: Port number
            flags: Optional BEGIN flags (see BEGIN_FLAG_* constants)
                   - BEGIN_FLAG_IPV6_OK (0x01): We support IPv6 addresses
                   - BEGIN_FLAG_IPV4_NOT_OK (0x02): We don't want IPv4 addresses
                   - BEGIN_FLAG_IPV6_PREFERRED (0x04): Prefer IPv6 over IPv4

        Returns:
            Stream ID if successful, None if failed
        """
        stream_id = self._allocate_stream_id()
        output.debug(f"Allocated stream ID: {stream_id}")

        # Send RELAY_BEGIN
        flags_str = f" flags=0x{flags:02x}" if flags else ""
        output.verbose(f"RELAY_BEGIN → {address}:{port} (stream {stream_id}){flags_str}")
        output.debug(f"Sending through {len(self._crypto_layers)} crypto layers")
        begin_cell = RelayCell(
            relay_command=RelayCommand.BEGIN,
            stream_id=stream_id,
            data=create_begin_payload(address, port, flags),
        )
        # Debug: show the plaintext before encryption
        packed = begin_cell.pack_payload()
        output.debug(f"BEGIN plaintext (first 20 bytes): {packed[:20].hex()}")
        self.send_relay(begin_cell)

        # Wait for RELAY_CONNECTED or RELAY_END
        response = self.recv_relay(debug=output.is_debug())
        if response is None:
            output.debug("No response to BEGIN")
            return None

        output.verbose(f"{response.relay_command.name} ← (stream {response.stream_id})")

        if response.relay_command == RelayCommand.CONNECTED:
            output.debug(f"Stream {stream_id} connected")
            # Initialize stream flow control state
            self._streams[stream_id] = StreamState(stream_id=stream_id)
            return stream_id

        if response.relay_command == RelayCommand.END:
            # Stream was rejected
            output.debug("Stream rejected: END received")
            return None

        # Unexpected response
        output.debug(f"Unexpected response: {response.relay_command.name}")
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
        output.debug(f"Allocated stream ID: {stream_id}")

        # Send RELAY_BEGIN_DIR (no payload needed)
        output.verbose(f"RELAY_BEGIN_DIR → (stream {stream_id})")
        begin_dir_cell = RelayCell(
            relay_command=RelayCommand.BEGIN_DIR,
            stream_id=stream_id,
            data=b"",
        )
        self.send_relay(begin_dir_cell)

        # Wait for RELAY_CONNECTED or RELAY_END
        response = self.recv_relay()
        if response is None:
            output.debug("No response to BEGIN_DIR")
            return None

        output.verbose(f"{response.relay_command.name} ← (stream {response.stream_id})")

        if response.relay_command == RelayCommand.CONNECTED:
            output.debug(f"Directory stream {stream_id} connected")
            # Initialize stream flow control state
            self._streams[stream_id] = StreamState(stream_id=stream_id)
            return stream_id

        if response.relay_command == RelayCommand.END:
            # Directory stream was rejected (relay may not support V2Dir)
            output.debug("Directory stream rejected (no V2Dir support?)")
            return None

        # Unexpected response
        output.debug(f"Unexpected response: {response.relay_command.name}")
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
        output.verbose(f"RELAY_RESOLVE → {hostname} (stream {stream_id})")
        resolve_cell = RelayCell(
            relay_command=RelayCommand.RESOLVE,
            stream_id=stream_id,
            data=create_resolve_payload(hostname),
        )
        self.send_relay(resolve_cell)

        # Wait for RELAY_RESOLVED
        response = self.recv_relay()
        if response is None:
            output.debug("No response to RESOLVE")
            return []

        output.verbose(f"{response.relay_command.name} ← (stream {response.stream_id})")

        if response.relay_command == RelayCommand.RESOLVED:
            if response.stream_id != stream_id:
                # Mismatched stream ID
                output.debug(f"Stream ID mismatch: got {response.stream_id}, want {stream_id}")
                return []
            answers = parse_resolved_payload(response.data)
            output.debug(f"Resolved to {len(answers)} answer(s)")
            return answers

        if response.relay_command == RelayCommand.END:
            # Resolution failed
            output.debug("Resolution failed (END received)")
            return []

        # Unexpected response
        output.debug(f"Unexpected response: {response.relay_command.name}")
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
        # Clean up stream flow control state
        self._streams.pop(stream_id, None)

    def negotiate_padding(
        self,
        command: CircpadCommand = CircpadCommand.START,
        machine_type: CircpadMachineType = CircpadMachineType.CIRC_SETUP,
    ) -> PaddingNegotiated | None:
        """
        Negotiate circuit padding with the relay.

        Sends a PADDING_NEGOTIATE cell to request circuit padding and waits
        for a PADDING_NEGOTIATED response.

        See: https://spec.torproject.org/padding-spec/circuit-level-padding.html

        Args:
            command: START to enable padding, STOP to disable
            machine_type: Type of padding machine (default: CIRC_SETUP)

        Returns:
            PaddingNegotiated response if successful, None if failed
        """
        if not self.is_open:
            raise RuntimeError("Circuit is not open")

        # Create PADDING_NEGOTIATE payload
        negotiate_data = create_padding_negotiate_payload(
            command=command,
            machine_type=machine_type,
        )

        # Send RELAY_PADDING_NEGOTIATE (stream_id must be 0 for control messages)
        cmd_name = "START" if command == CircpadCommand.START else "STOP"
        output.verbose(f"RELAY_PADDING_NEGOTIATE → {cmd_name}")
        negotiate_cell = RelayCell(
            relay_command=RelayCommand.PADDING_NEGOTIATE,
            stream_id=0,
            data=negotiate_data,
        )
        self.send_relay(negotiate_cell)

        # Wait for RELAY_PADDING_NEGOTIATED
        response = self.recv_relay()
        if response is None:
            output.debug("No response to PADDING_NEGOTIATE")
            return None

        output.verbose(f"{response.relay_command.name} ←")

        if response.relay_command == RelayCommand.PADDING_NEGOTIATED:
            try:
                negotiated = parse_padding_negotiated_payload(response.data)
                if negotiated.is_ok:
                    output.debug("Padding negotiation successful")
                else:
                    output.debug("Padding negotiation failed (relay returned ERR)")
                return negotiated
            except ValueError as e:
                output.debug(f"Failed to parse PADDING_NEGOTIATED: {e}")
                return None

        # Unexpected response
        output.debug(f"Unexpected response: {response.relay_command.name}")
        return None

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

    def send_drop(self, padding_data: bytes | None = None) -> None:
        """
        Send a DROP cell (long-range dummy traffic).

        DROP cells are RELAY cells that travel through the circuit like normal
        relay cells but are discarded by the exit relay. They are used for
        traffic padding to defeat traffic analysis.

        Args:
            padding_data: Optional padding data. If None, random data is used.

        See: https://spec.torproject.org/tor-spec/relay-cells.html
        """
        if not self.is_open:
            raise RuntimeError("Circuit is not open")

        # Generate random padding if not provided
        if padding_data is None:
            padding_data = secrets.token_bytes(RELAY_DATA_LEN)
        else:
            # Truncate or pad to RELAY_DATA_LEN
            padding_data = padding_data[:RELAY_DATA_LEN]

        drop_cell = RelayCell(
            relay_command=RelayCommand.DROP,
            stream_id=0,  # DROP cells use stream_id=0 (no stream association)
            data=padding_data,
        )
        self.send_relay(drop_cell)
        output.debug("Sent DROP cell (long-range dummy traffic)")

    def recv_data(self, stream_id: int, debug: bool = False) -> bytes | None:
        """
        Receive data from a stream.

        Args:
            stream_id: Stream ID
            debug: If True, print debug info

        Returns:
            Data bytes, or None if stream ended or error
        """
        while True:
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

            # Handle incoming SENDME cells (from sender acknowledging our SENDMEs)
            # These are flow control signals that don't carry data - skip them
            if response.relay_command == RelayCommand.SENDME:
                if debug:
                    target = (
                        "circuit" if response.stream_id == 0 else f"stream {response.stream_id}"
                    )
                    print(f"    [debug] Received SENDME for {target}")
                # Continue to get the next cell
                continue

            if response.stream_id != stream_id:
                # Data for different stream (shouldn't happen in single-stream use)
                if debug:
                    print(
                        f"    [debug] Wrong stream_id: got {response.stream_id}, want {stream_id}"
                    )
                return None

            if response.relay_command == RelayCommand.DATA:
                return response.data

            if response.relay_command == RelayCommand.END:
                if debug:
                    print("    [debug] Stream ended (RELAY_END)")
                # Clean up stream state
                self._streams.pop(stream_id, None)
                return None

            # Unexpected command
            if debug:
                print(f"    [debug] Unexpected relay command: {response.relay_command.name}")
            return None

    def fetch_directory(self, path: str, timeout: float = 30.0) -> bytes | None:
        """
        Fetch a directory document through a BEGIN_DIR stream.

        Opens a directory stream to the relay, sends an HTTP GET request,
        and returns the response body. Used for fetching descriptors,
        consensus, etc. through bridges.

        Args:
            path: HTTP path to fetch (e.g., "/tor/server/fp/FINGERPRINT")
            timeout: Timeout in seconds for the entire operation

        Returns:
            Response body as bytes, or None if failed
        """
        # Open directory stream
        stream_id = self.begin_dir()
        if stream_id is None:
            output.debug("Failed to open directory stream")
            return None

        try:
            # Send HTTP GET request
            request = (
                f"GET {path} HTTP/1.0\r\n"
                f"Host: 127.0.0.1\r\n"
                f"Accept-Encoding: identity\r\n"
                f"\r\n"
            ).encode("ascii")

            output.debug(f"Sending HTTP request: GET {path}")
            self.send_data(stream_id, request)

            # Receive response
            response_data = b""
            start_time = time.time()

            while True:
                if time.time() - start_time > timeout:
                    output.debug("Directory fetch timeout")
                    break

                chunk = self.recv_data(stream_id)
                if chunk is None:
                    # Stream ended or error
                    break
                response_data += chunk

            if not response_data:
                output.debug("No response data received")
                return None

            # Parse HTTP response
            try:
                header_end = response_data.find(b"\r\n\r\n")
                if header_end == -1:
                    output.debug("Invalid HTTP response (no header terminator)")
                    return None

                headers = response_data[:header_end].decode("ascii", errors="replace")
                body = response_data[header_end + 4 :]

                # Check status code
                first_line = headers.split("\r\n")[0]
                if " 200 " not in first_line:
                    output.debug(f"HTTP error: {first_line}")
                    return None

                output.debug(f"Received {len(body)} bytes of directory data")
                return body

            except Exception as e:  # pylint: disable=broad-exception-caught
                output.debug(f"Failed to parse HTTP response: {e}")
                return None

        finally:
            # Close stream
            try:
                self.end_stream(stream_id)
            except Exception:  # pylint: disable=broad-exception-caught
                pass

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
