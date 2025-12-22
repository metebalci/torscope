"""
Bridge relay support.

Bridge relays are unlisted Tor entry points used for censorship circumvention.
They are not listed in the public consensus and must be obtained through
alternative channels (BridgeDB, manual distribution, etc.).
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from torscope.directory.models import ServerDescriptor
    from torscope.onion.circuit import Circuit
    from torscope.onion.transport import Transport


class BridgeParseError(Exception):
    """Error parsing bridge line."""


@dataclass
class BridgeRelay:
    """Represents a bridge relay.

    Bridges can be connected directly (no transport) or through a pluggable
    transport (obfs4, meek, snowflake, etc.) for traffic obfuscation.

    Attributes:
        ip: Bridge IP address
        port: Bridge OR port
        fingerprint: 40-character hex fingerprint
        transport: Pluggable transport name (None for direct connection)
        transport_params: Transport-specific parameters (e.g., cert, iat-mode)
    """

    ip: str
    port: int
    fingerprint: str  # 40 hex chars, uppercase
    transport: str | None = None  # None = direct, "obfs4", "meek", etc.
    transport_params: dict[str, str] = field(default_factory=dict)

    @property
    def address(self) -> str:
        """Get formatted address string (IP:port)."""
        return f"{self.ip}:{self.port}"

    @property
    def is_direct(self) -> bool:
        """Check if this is a direct (non-PT) bridge."""
        return self.transport is None

    @property
    def short_fingerprint(self) -> str:
        """Get shortened fingerprint (first 8 hex chars)."""
        return self.fingerprint[:8] if len(self.fingerprint) >= 8 else self.fingerprint

    def __str__(self) -> str:
        """Return bridge line representation."""
        if self.transport:
            params = " ".join(f"{k}={v}" for k, v in self.transport_params.items())
            if params:
                return f"{self.transport} {self.address} {self.fingerprint} {params}"
            return f"{self.transport} {self.address} {self.fingerprint}"
        return f"{self.address} {self.fingerprint}"


# Regex patterns for parsing
_IP_PORT_PATTERN = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})$")
_FINGERPRINT_PATTERN = re.compile(r"^[A-Fa-f0-9]{40}$")
_TRANSPORT_NAMES = frozenset(
    [
        "obfs4",
        "obfs3",
        "obfs2",  # Obfuscation
        "meek",
        "meek_lite",  # Domain fronting
        "snowflake",  # WebRTC peer-to-peer
        "webtunnel",  # WebSocket tunneling
        "scramblesuit",  # Legacy
    ]
)


def parse_bridge_line(line: str) -> BridgeRelay:
    """Parse a bridge line into a BridgeRelay object.

    Supports two formats:

    1. Direct (no pluggable transport):
       IP:PORT FINGERPRINT

    2. With pluggable transport:
       TRANSPORT IP:PORT FINGERPRINT [key=value ...]

    Examples:
        >>> parse_bridge_line("192.0.2.1:443 4352E58420E68F5E40BF7C74FADDCCD9D1349413")
        BridgeRelay(ip='192.0.2.1', port=443, fingerprint='4352E5842...')

        >>> parse_bridge_line("obfs4 192.0.2.1:443 FINGERPRINT cert=ABC iat-mode=0")
        BridgeRelay(ip='192.0.2.1', port=443, ..., transport='obfs4', ...)

    Args:
        line: Bridge line to parse

    Returns:
        Parsed BridgeRelay object

    Raises:
        BridgeParseError: If the bridge line is invalid
    """
    line = line.strip()

    # Remove "Bridge" prefix if present (from torrc format)
    if line.lower().startswith("bridge "):
        line = line[7:].strip()

    parts = line.split()
    if len(parts) < 2:
        raise BridgeParseError(f"Invalid bridge line: too few parts: {line}")

    # Determine if first part is a transport name or IP:port
    transport: str | None = None
    transport_params: dict[str, str] = {}

    first = parts[0].lower()
    if first in _TRANSPORT_NAMES:
        # Format: TRANSPORT IP:PORT FINGERPRINT [params...]
        transport = first
        parts = parts[1:]  # Remove transport from parts

    if len(parts) < 2:
        raise BridgeParseError(f"Invalid bridge line: missing address or fingerprint: {line}")

    # Parse IP:PORT
    addr_match = _IP_PORT_PATTERN.match(parts[0])
    if not addr_match:
        raise BridgeParseError(f"Invalid address format: {parts[0]}")

    ip = addr_match.group(1)
    port = int(addr_match.group(2))

    if port < 1 or port > 65535:
        raise BridgeParseError(f"Invalid port number: {port}")

    # Parse fingerprint
    fingerprint = parts[1].upper()
    if not _FINGERPRINT_PATTERN.match(fingerprint):
        raise BridgeParseError(f"Invalid fingerprint format: {parts[1]}")

    # Parse optional key=value parameters (for pluggable transports)
    for param in parts[2:]:
        if "=" in param:
            key, value = param.split("=", 1)
            transport_params[key] = value
        # Skip non key=value parts (could be extra fingerprint formats)

    return BridgeRelay(
        ip=ip,
        port=port,
        fingerprint=fingerprint,
        transport=transport,
        transport_params=transport_params,
    )


def validate_bridge(bridge: BridgeRelay) -> None:
    """Validate a BridgeRelay object.

    Args:
        bridge: Bridge to validate

    Raises:
        BridgeParseError: If the bridge is invalid
    """
    # Validate IP format
    ip_parts = bridge.ip.split(".")
    if len(ip_parts) != 4:
        raise BridgeParseError(f"Invalid IP address: {bridge.ip}")
    for part in ip_parts:
        val = int(part)
        if val < 0 or val > 255:
            raise BridgeParseError(f"Invalid IP address: {bridge.ip}")

    # Validate port
    if bridge.port < 1 or bridge.port > 65535:
        raise BridgeParseError(f"Invalid port: {bridge.port}")

    # Validate fingerprint
    if not _FINGERPRINT_PATTERN.match(bridge.fingerprint):
        raise BridgeParseError(f"Invalid fingerprint: {bridge.fingerprint}")

    # Validate transport if specified
    if bridge.transport and bridge.transport.lower() not in _TRANSPORT_NAMES:
        raise BridgeParseError(f"Unknown transport: {bridge.transport}")


def create_transport(bridge: BridgeRelay, timeout: float = 30.0) -> Transport | None:
    """
    Create appropriate transport for a bridge.

    Args:
        bridge: BridgeRelay with transport configuration
        timeout: Connection timeout in seconds

    Returns:
        Transport instance, or None for direct (non-PT) bridges

    Raises:
        BridgeParseError: If transport is unsupported or misconfigured
    """
    if bridge.transport is None:
        return None  # Direct connection, no transport needed

    transport_name = bridge.transport.lower()

    if transport_name == "webtunnel":
        # Import here to avoid circular imports
        # pylint: disable=import-outside-toplevel
        from torscope.onion.transport import WebTunnelTransport

        url = bridge.transport_params.get("url")
        if not url:
            raise BridgeParseError("WebTunnel bridge requires 'url' parameter")
        return WebTunnelTransport(
            host=bridge.ip,
            port=bridge.port,
            url=url,
            timeout=timeout,
        )

    if transport_name == "obfs4":
        # Import here to avoid circular imports
        # pylint: disable=import-outside-toplevel
        from torscope.onion.obfs4 import Obfs4Transport

        cert = bridge.transport_params.get("cert")
        if not cert:
            raise BridgeParseError("obfs4 bridge requires 'cert' parameter")

        iat_mode_str = bridge.transport_params.get("iat-mode", "0")
        try:
            iat_mode = int(iat_mode_str)
        except ValueError:
            iat_mode = 0

        return Obfs4Transport(
            host=bridge.ip,
            port=bridge.port,
            cert=cert,
            iat_mode=iat_mode,
            timeout=timeout,
        )

    # Other transports not yet implemented
    raise BridgeParseError(
        f"Pluggable transport '{bridge.transport}' not yet supported. "
        "Supported transports: webtunnel, obfs4"
    )


def fetch_bridge_descriptor(circuit: Circuit, fingerprint: str) -> ServerDescriptor | None:
    """
    Fetch a bridge's server descriptor via BEGIN_DIR.

    This is used to get the bridge's ntor-onion-key for extending the circuit.
    Must be called after establishing a circuit to the bridge (via CREATE_FAST).

    Args:
        circuit: An open circuit to the bridge
        fingerprint: Bridge's fingerprint (40 hex chars)

    Returns:
        ServerDescriptor if found, None otherwise
    """
    # Import here to avoid circular imports
    # pylint: disable=import-outside-toplevel
    from torscope.directory.descriptor import ServerDescriptorParser

    # Fetch bridge's own descriptor
    path = f"/tor/server/fp/{fingerprint}"
    response = circuit.fetch_directory(path)
    if response is None:
        return None

    descriptors = ServerDescriptorParser.parse(response)
    if not descriptors:
        return None

    return descriptors[0]


def get_bridge_ntor_key(circuit: Circuit, fingerprint: str) -> bytes | None:
    """
    Get the ntor-onion-key for a bridge via BEGIN_DIR.

    Args:
        circuit: An open circuit to the bridge
        fingerprint: Bridge's fingerprint (40 hex chars)

    Returns:
        32-byte ntor-onion-key, or None if not available
    """
    descriptor = fetch_bridge_descriptor(circuit, fingerprint)
    if descriptor is None or descriptor.ntor_onion_key is None:
        return None

    # Decode base64 ntor key
    key_b64 = descriptor.ntor_onion_key
    # Add padding if needed
    padding = 4 - len(key_b64) % 4
    if padding != 4:
        key_b64 += "=" * padding

    try:
        return base64.b64decode(key_b64)
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def connect_to_bridge(
    bridge: BridgeRelay,
    timeout: float = 30.0,
) -> tuple[Circuit, bytes | None]:
    """
    Connect to a bridge and establish a one-hop circuit.

    Uses CREATE_FAST for the initial connection (doesn't require ntor key).
    Then fetches the bridge's descriptor to get the ntor key for extending.

    Supports both direct bridges and pluggable transports (WebTunnel).

    Args:
        bridge: BridgeRelay to connect to
        timeout: Connection timeout in seconds

    Returns:
        Tuple of (Circuit, ntor_key) where ntor_key may be None if not retrieved

    Raises:
        BridgeParseError: If bridge transport is unsupported
        ConnectionError: If connection fails
        RuntimeError: If circuit creation fails
    """
    # pylint: disable=import-outside-toplevel
    from torscope.onion.circuit import Circuit
    from torscope.onion.connection import RelayConnection

    # Create transport if needed (None for direct connections)
    transport = create_transport(bridge, timeout=timeout)

    # Connect to bridge (using transport if available)
    conn = RelayConnection(
        host=bridge.ip,
        port=bridge.port,
        transport=transport,
        timeout=timeout,
    )
    conn.connect()

    if not conn.handshake():
        conn.close()
        raise ConnectionError("Link handshake with bridge failed")

    # Create circuit using CREATE_FAST (doesn't require ntor key)
    circuit = Circuit.create(conn)

    if not circuit.create_fast(bridge.fingerprint):
        conn.close()
        raise RuntimeError("CREATE_FAST to bridge failed")

    # Try to fetch bridge's ntor key for extending to other relays
    ntor_key = get_bridge_ntor_key(circuit, bridge.fingerprint)

    return circuit, ntor_key
