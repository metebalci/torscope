"""
Onion Router (OR) protocol implementation.

This module implements the Tor OR protocol for building circuits
and communicating with relays.
"""

from torscope.onion.cell import (
    HTYPE_NTOR,
    AuthChallengeCell,
    Cell,
    CellCommand,
    CertsCell,
    Create2Cell,
    Created2Cell,
    DestroyCell,
    NetInfoCell,
    VersionsCell,
)
from torscope.onion.circuit import Circuit, CircuitHop, CircuitState
from torscope.onion.connection import RelayConnection
from torscope.onion.ntor import CircuitKeys, NtorClientState, node_id_from_fingerprint
from torscope.onion.relay import (
    RelayCell,
    RelayCommand,
    RelayCrypto,
    RelayEndReason,
    create_begin_payload,
    create_end_payload,
    parse_connected_payload,
)

__all__ = [
    # Cells
    "Cell",
    "CellCommand",
    "VersionsCell",
    "NetInfoCell",
    "CertsCell",
    "AuthChallengeCell",
    "Create2Cell",
    "Created2Cell",
    "DestroyCell",
    "HTYPE_NTOR",
    # Connection
    "RelayConnection",
    # Circuit
    "Circuit",
    "CircuitHop",
    "CircuitKeys",
    "CircuitState",
    # ntor
    "NtorClientState",
    "node_id_from_fingerprint",
    # Relay
    "RelayCell",
    "RelayCommand",
    "RelayCrypto",
    "RelayEndReason",
    "create_begin_payload",
    "create_end_payload",
    "parse_connected_payload",
]
