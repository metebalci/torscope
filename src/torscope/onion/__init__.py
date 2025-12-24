"""
Onion Router (OR) protocol implementation.

This module implements the Tor OR protocol for building circuits
and communicating with relays.
"""

from torscope.onion.address import OnionAddress, get_current_time_period, get_time_period_info
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
    BEGIN_FLAG_IPV4_NOT_OK,
    BEGIN_FLAG_IPV6_OK,
    BEGIN_FLAG_IPV6_PREFERRED,
    LinkSpecifier,
    LinkSpecifierType,
    RelayCell,
    RelayCommand,
    RelayCrypto,
    RelayEndReason,
    ResolvedAnswer,
    ResolvedType,
    create_begin_payload,
    create_end_payload,
    create_extend2_payload,
    create_resolve_payload,
    parse_connected_payload,
    parse_extended2_payload,
    parse_resolved_payload,
)
from torscope.onion.transport import TransportError, WebTunnelTransport

__all__ = [
    # Address
    "OnionAddress",
    "get_current_time_period",
    "get_time_period_info",
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
    "LinkSpecifier",
    "LinkSpecifierType",
    "ResolvedAnswer",
    "ResolvedType",
    "BEGIN_FLAG_IPV6_OK",
    "BEGIN_FLAG_IPV4_NOT_OK",
    "BEGIN_FLAG_IPV6_PREFERRED",
    "create_begin_payload",
    "create_end_payload",
    "create_extend2_payload",
    "create_resolve_payload",
    "parse_connected_payload",
    "parse_extended2_payload",
    "parse_resolved_payload",
    # Transport
    "TransportError",
    "WebTunnelTransport",
]
