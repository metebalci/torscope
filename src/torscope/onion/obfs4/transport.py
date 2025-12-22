"""
obfs4 pluggable transport implementation.

This module provides the main Obfs4Transport class that implements
the Transport protocol for connecting to obfs4 bridges.

Usage:
    transport = Obfs4Transport(
        host="192.0.2.1",
        port=443,
        cert="AbCdEf...",  # Base64-encoded server cert
        iat_mode=0,
    )
    tls_socket = transport.connect()
    # Use tls_socket for Tor OR protocol
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field

from torscope import output
from torscope.onion.obfs4.framing import Obfs4Framing
from torscope.onion.obfs4.handshake import ClientHandshake, HandshakeError, Obfs4ServerCert
from torscope.onion.obfs4.socket_wrapper import Obfs4Socket
from torscope.onion.transport import TransportError

# Maximum handshake response size
MAX_HANDSHAKE_RESPONSE = 8192


@dataclass
class Obfs4Transport:
    """
    obfs4 pluggable transport.

    Establishes an obfs4-encrypted connection to a bridge relay,
    performs the handshake, and returns a TLS socket for the OR protocol.

    Attributes:
        host: Bridge IP address
        port: Bridge port
        cert: Base64-encoded server certificate
        iat_mode: Inter-arrival time mode (0=off, 1=enabled, 2=paranoid)
        timeout: Connection timeout in seconds
    """

    host: str
    port: int
    cert: str
    iat_mode: int = 0
    timeout: float = 30.0

    _socket: socket.socket | None = field(default=None, repr=False)
    _obfs4_socket: Obfs4Socket | None = field(default=None, repr=False)
    _tls_socket: ssl.SSLSocket | None = field(default=None, repr=False)

    def connect(self) -> ssl.SSLSocket:
        """
        Establish obfs4 connection and return TLS socket.

        Flow:
        1. Parse server certificate
        2. Create TCP connection
        3. Perform obfs4 handshake
        4. Create Obfs4Socket wrapper
        5. Perform TLS handshake inside obfs4 tunnel
        6. Return ssl.SSLSocket

        Returns:
            TLS socket ready for Tor OR protocol

        Raises:
            TransportError: If connection or handshake fails
        """
        output.debug(f"obfs4: connecting to {self.host}:{self.port}")

        # 1. Parse server certificate
        try:
            server_cert = Obfs4ServerCert.from_string(self.cert)
        except HandshakeError as e:
            raise TransportError(f"Invalid obfs4 cert: {e}") from e

        output.debug(f"obfs4: parsed cert, node_id={server_cert.node_id.hex()[:16]}...")

        # 2. Create TCP socket
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.settimeout(self.timeout)

        try:
            self._socket.connect((self.host, self.port))
        except OSError as e:
            self.close()
            raise TransportError(f"TCP connection failed: {e}") from e

        output.debug("obfs4: TCP connected")

        # 3. Perform obfs4 handshake
        try:
            key_material = self._perform_handshake(server_cert)
        except HandshakeError as e:
            self.close()
            raise TransportError(f"obfs4 handshake failed: {e}") from e

        output.debug("obfs4: handshake complete")

        # 4. Create framing and socket wrapper
        framing = Obfs4Framing.from_key_material(key_material, is_client=True)
        self._obfs4_socket = Obfs4Socket(self._socket, framing)

        # 5. Perform TLS handshake inside obfs4 tunnel
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        try:
            self._tls_socket = context.wrap_socket(
                self._obfs4_socket,  # type: ignore[arg-type]
                server_hostname=self.host,
            )
        except ssl.SSLError as e:
            self.close()
            raise TransportError(f"TLS handshake failed: {e}") from e

        output.debug("obfs4: TLS established inside tunnel")

        return self._tls_socket

    def _perform_handshake(self, server_cert: Obfs4ServerCert) -> bytes:
        """
        Perform the obfs4 handshake.

        Args:
            server_cert: Parsed server certificate

        Returns:
            144 bytes of key material

        Raises:
            HandshakeError: If handshake fails
        """
        if self._socket is None:
            raise HandshakeError("Socket not connected")

        # Create client handshake state
        handshake = ClientHandshake(server_cert=server_cert, iat_mode=self.iat_mode)

        # Generate and send client request
        request = handshake.generate_request()
        output.debug(f"obfs4: sending handshake request ({len(request)} bytes)")

        try:
            self._socket.sendall(request)
        except OSError as e:
            raise HandshakeError(f"Failed to send request: {e}") from e

        # Receive server response
        response = self._receive_handshake_response()
        output.debug(f"obfs4: received response ({len(response)} bytes)")

        # Process response and derive keys
        return handshake.process_response(response)

    def _receive_handshake_response(self) -> bytes:
        """
        Receive the server's handshake response.

        The response length is variable due to padding.
        We read until we have enough to find the MAC.
        """
        if self._socket is None:
            raise HandshakeError("Socket not connected")

        response = b""
        min_response = 32 + 32 + 16 + 16  # Y' + auth + mark + MAC

        while len(response) < MAX_HANDSHAKE_RESPONSE:
            try:
                chunk = self._socket.recv(1024)
            except TimeoutError:
                if len(response) >= min_response:
                    break
                raise HandshakeError("Timeout waiting for handshake response") from None
            except OSError as e:
                raise HandshakeError(f"Failed to receive response: {e}") from e

            if not chunk:
                if len(response) >= min_response:
                    break
                raise HandshakeError("Connection closed during handshake")

            response += chunk

            # Check if we have enough for a complete response
            # The minimum is Y' (32) + auth (32) + mark (16) + MAC (16) = 96 bytes
            if len(response) >= min_response:
                # Try to parse - if successful, we're done
                # If not, keep reading for more padding
                # For now, just return what we have and let process_response handle it
                break

        return response

    def close(self) -> None:
        """Close the transport connection."""
        if self._tls_socket:
            try:
                self._tls_socket.close()
            except OSError:
                pass
            self._tls_socket = None

        if self._obfs4_socket:
            try:
                self._obfs4_socket.close()
            except OSError:
                pass
            self._obfs4_socket = None

        if self._socket:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None
