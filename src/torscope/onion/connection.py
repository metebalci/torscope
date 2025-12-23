"""
TLS connection to Tor relays.

This module implements the link-level connection to Tor relays,
including TLS setup and the link handshake protocol.
"""

from __future__ import annotations

import secrets
import socket
import ssl
import struct
from dataclasses import dataclass, field
from types import TracebackType
from typing import TYPE_CHECKING, Any

from torscope import output
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

if TYPE_CHECKING:
    from torscope.onion.transport import Transport


@dataclass
class RelayConnection:
    """
    Connection to a Tor relay over TLS.

    Handles the link protocol handshake and cell I/O.
    """

    host: str
    port: int
    transport: Transport | None = None  # None = direct TLS connection
    _socket: socket.socket | None = field(default=None, repr=False)
    _tls_socket: ssl.SSLSocket | None = field(default=None, repr=False)
    link_protocol: int = 0  # Negotiated link protocol version
    their_versions: list[int] = field(default_factory=list)
    certs: CertsCell | None = None
    auth_challenge: AuthChallengeCell | None = None
    timeout: float = 30.0

    # Supported link protocol versions
    SUPPORTED_VERSIONS = [4, 5]

    def connect(self) -> None:
        """
        Establish TLS connection to relay.

        Creates a TLS connection without validating the relay's certificate
        (Tor has its own certificate validation via CERTS cell).

        If a transport is configured, uses the transport to establish the
        connection instead of direct TLS.
        """
        if self.transport is not None:
            # Use pluggable transport
            output.debug(f"Using transport to connect to {self.host}:{self.port}")
            self._tls_socket = self.transport.connect()
            output.debug("Transport connection established")
            return

        # Direct TLS connection
        output.debug(f"Creating TCP socket to {self.host}:{self.port}")

        # Create TCP socket
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.settimeout(self.timeout)
        self._socket.connect((self.host, self.port))
        output.debug("TCP connection established")

        # Wrap with TLS (no certificate verification - Tor handles this differently)
        output.debug("Initiating TLS handshake")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        # Set minimum TLS version for security
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        self._tls_socket = context.wrap_socket(self._socket, server_hostname=self.host)
        output.debug(f"TLS version: {self._tls_socket.version()}")

    def close(self) -> None:
        """Close the connection."""
        if self.transport is not None:
            # Let transport handle cleanup
            self.transport.close()
            self._tls_socket = None
            return

        if self._tls_socket:
            try:
                self._tls_socket.close()
            except Exception:  # pylint: disable=broad-exception-caught
                pass
            self._tls_socket = None
        if self._socket:
            try:
                self._socket.close()
            except Exception:  # pylint: disable=broad-exception-caught
                pass
            self._socket = None

    def handshake(self) -> bool:
        """
        Perform link protocol handshake.

        1. Send VERSIONS cell
        2. Receive VERSIONS cell
        3. Negotiate highest common version
        4. Receive CERTS cell
        5. Receive AUTH_CHALLENGE cell
        6. Receive NETINFO cell
        7. Send NETINFO cell

        Returns:
            True if handshake successful, False otherwise
        """
        if not self._tls_socket:
            raise ConnectionError("Not connected")

        # Send our VERSIONS cell
        output.verbose(f"VERSIONS → (supported: {self.SUPPORTED_VERSIONS})")
        versions_cell = VersionsCell(versions=self.SUPPORTED_VERSIONS)
        self._send_raw(versions_cell.pack())

        # Receive their VERSIONS cell (always uses 2-byte CircID)
        their_versions_data = self._recv_variable_cell_v3()
        their_versions = VersionsCell.unpack(their_versions_data)
        self.their_versions = their_versions.versions
        output.verbose(f"VERSIONS ← (their versions: {self.their_versions})")

        # Negotiate highest common version
        common = set(self.SUPPORTED_VERSIONS) & set(self.their_versions)
        if not common:
            output.debug("No common link protocol version")
            return False
        self.link_protocol = max(common)
        output.verbose(f"Negotiated link protocol v{self.link_protocol}")

        # Now receive CERTS, AUTH_CHALLENGE, NETINFO from responder
        # These use the negotiated link protocol's CircID size

        # Receive CERTS cell
        certs_data = self._recv_variable_cell()
        self.certs = CertsCell.unpack(certs_data, self.link_protocol)
        output.verbose(f"CERTS ← ({len(self.certs.certificates)} certificates)")
        output.debug(f"Certificate types: {[c[0] for c in self.certs.certificates]}")

        # Receive AUTH_CHALLENGE cell
        auth_data = self._recv_variable_cell()
        self.auth_challenge = AuthChallengeCell.unpack(auth_data, self.link_protocol)
        output.verbose(f"AUTH_CHALLENGE ← ({len(self.auth_challenge.challenge)} bytes)")

        # Receive NETINFO cell (fixed-length)
        netinfo_data = self._recv_fixed_cell()
        their_netinfo = NetInfoCell.unpack(netinfo_data, self.link_protocol)
        output.verbose(f"NETINFO ← (their addresses: {len(their_netinfo.my_addresses)})")

        # Send our NETINFO cell
        # We use their address as the "other address"
        if their_netinfo.my_addresses:
            other_addr = their_netinfo.my_addresses[0]
        else:
            other_addr = (4, b"\x00\x00\x00\x00")
        my_netinfo = NetInfoCell(
            other_address=other_addr,
            my_addresses=[],  # We don't need to advertise our addresses
        )
        self._send_raw(my_netinfo.pack(self.link_protocol))
        output.verbose("NETINFO →")

        output.debug("Link handshake complete")
        return True

    def _send_raw(self, data: bytes) -> None:
        """Send raw bytes over TLS connection."""
        if not self._tls_socket:
            raise ConnectionError("Not connected")
        self._tls_socket.sendall(data)

    def _recv_exact(self, length: int) -> bytes:
        """Receive exactly `length` bytes."""
        if not self._tls_socket:
            raise ConnectionError("Not connected")

        data = b""
        while len(data) < length:
            chunk = self._tls_socket.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
        return data

    def _recv_fixed_cell(self) -> bytes:
        """Receive a fixed-length cell."""
        if self.link_protocol >= 4:
            cell_len = CELL_LEN_V4
        else:
            cell_len = CELL_LEN_V3
        return self._recv_exact(cell_len)

    def _recv_variable_cell(self) -> bytes:
        """Receive a variable-length cell using negotiated protocol."""
        if self.link_protocol >= 4:
            # CircID (4 bytes) + Command (1 byte)
            header = self._recv_exact(5)
            # Length (2 bytes)
            length_bytes = self._recv_exact(2)
            length = struct.unpack(">H", length_bytes)[0]
            # Payload
            payload = self._recv_exact(length)
            return header + length_bytes + payload

        return self._recv_variable_cell_v3()

    def _recv_variable_cell_v3(self) -> bytes:
        """Receive a variable-length cell with 2-byte CircID (for VERSIONS)."""
        # CircID (2 bytes) + Command (1 byte)
        header = self._recv_exact(3)
        # Length (2 bytes)
        length_bytes = self._recv_exact(2)
        length = struct.unpack(">H", length_bytes)[0]
        # Payload
        payload = self._recv_exact(length)
        return header + length_bytes + payload

    def send_cell(self, cell: Any) -> None:
        """Send a cell using the negotiated link protocol."""
        # Works with any cell type that has a pack() method
        self._send_raw(cell.pack(self.link_protocol))

    def send_vpadding(self, length: int = 0) -> None:
        """
        Send a VPADDING cell (variable-length link padding).

        VPADDING cells are used for link-level padding. They are processed
        at the link layer and do not travel through circuits. Unlike fixed
        PADDING cells (512/514 bytes), VPADDING can be any length.

        Args:
            length: Length of random padding (1-65535). If 0, generates
                    random length between 1 and 509 bytes.

        See: https://spec.torproject.org/tor-spec/link-protocol.html
        """
        if length == 0:
            # Random length between 1 and 509 (typical relay cell payload size)
            length = secrets.randbelow(509) + 1

        if length > 65535:
            raise ValueError("VPADDING length cannot exceed 65535")
        if length < 1:
            raise ValueError("VPADDING length must be at least 1")

        # Generate random padding
        padding = secrets.token_bytes(length)

        # Create VPADDING cell (variable-length, circ_id=0)
        vpadding_cell = Cell(circ_id=0, command=CellCommand.VPADDING, payload=padding)
        self._send_raw(vpadding_cell.pack(self.link_protocol))
        output.debug(f"Sent VPADDING cell ({length} bytes)")

    def recv_cell(self) -> Cell:
        """Receive a cell using the negotiated link protocol."""
        # Peek at command byte to determine if fixed or variable length
        if self.link_protocol >= 4:
            header = self._recv_exact(5)
            command = header[4]
        else:
            header = self._recv_exact(3)
            command = header[2]

        if CellCommand.is_variable_length(command):
            # Variable-length cell
            length_bytes = self._recv_exact(2)
            length = struct.unpack(">H", length_bytes)[0]
            payload = self._recv_exact(length)
            return Cell.unpack(header + length_bytes + payload, self.link_protocol)

        # Fixed-length cell
        if self.link_protocol >= 4:
            body_len = CELL_LEN_V4 - 5
        else:
            body_len = CELL_LEN_V3 - 3
        body = self._recv_exact(body_len)
        return Cell.unpack(header + body, self.link_protocol)

    def __enter__(self) -> RelayConnection:
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Context manager exit."""
        self.close()
