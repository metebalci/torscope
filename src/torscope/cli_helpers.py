"""
CLI helper functions for torscope.

These functions extract common patterns from the CLI to reduce code duplication
and improve maintainability.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from torscope.directory.models import ConsensusDocument, RouterStatusEntry


def find_router(consensus: ConsensusDocument, query: str) -> RouterStatusEntry | None:
    """
    Find router by fingerprint or nickname.

    Args:
        consensus: Network consensus document
        query: Fingerprint prefix or nickname (case-insensitive)

    Returns:
        Router entry if found, None otherwise
    """
    query_upper = query.strip().upper()
    for r in consensus.routers:
        if r.fingerprint.startswith(query_upper):
            return r
        if r.nickname.upper() == query_upper:
            return r
    return None


def resolve_router_or_fail(
    consensus: ConsensusDocument,
    query: str,
    role: str = "Router",
) -> RouterStatusEntry | None:
    """
    Find router by query, printing error message if not found.

    Args:
        consensus: Network consensus document
        query: Fingerprint prefix or nickname
        role: Role name for error message (e.g., "Guard", "Exit")

    Returns:
        Router entry if found, None otherwise (with error printed to stderr)
    """
    router = find_router(consensus, query)
    if router is None:
        print(f"{role} router not found: {query}", file=sys.stderr)
    return router


def parse_address_port(addr_port: str) -> tuple[str, int]:
    """
    Parse address:port string, handling IPv6 bracket notation.

    Examples:
        example.com:80 -> ("example.com", 80)
        [::1]:8080 -> ("::1", 8080)
        192.168.1.1:443 -> ("192.168.1.1", 443)

    Args:
        addr_port: Address and port in format "host:port" or "[ipv6]:port"

    Returns:
        Tuple of (address, port)

    Raises:
        ValueError: If the format is invalid or port is out of range
    """
    # Handle IPv6 bracket notation
    if addr_port.startswith("["):
        # IPv6 format: [address]:port
        bracket_end = addr_port.find("]")
        if bracket_end == -1:
            raise ValueError(f"Invalid IPv6 address format (missing ]): {addr_port}")
        if bracket_end + 1 >= len(addr_port) or addr_port[bracket_end + 1] != ":":
            raise ValueError(f"Invalid format (expected ]:port): {addr_port}")
        address = addr_port[1:bracket_end]
        port_str = addr_port[bracket_end + 2 :]
    else:
        # Regular format: address:port
        parts = addr_port.rsplit(":", 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid address:port format: {addr_port}")
        address, port_str = parts

    # Parse and validate port
    try:
        port = int(port_str)
    except ValueError as e:
        raise ValueError(f"Invalid port number: {port_str}") from e

    if port < 1 or port > 65535:
        raise ValueError(f"Port out of range (1-65535): {port}")

    return address, port
