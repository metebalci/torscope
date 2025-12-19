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
    CellCommand,
    Create2Cell,
    DestroyCell,
)
from torscope.onion.connection import RelayConnection
from torscope.onion.ntor import CircuitKeys, NtorClientState, node_id_from_fingerprint


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
            hop = CircuitHop(
                fingerprint=fingerprint,
                ntor_onion_key=ntor_onion_key,
                keys=CircuitKeys.from_key_material(key_material),
            )
            self.hops.append(hop)
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
