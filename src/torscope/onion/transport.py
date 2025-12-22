"""
Pluggable transport implementations.

Transports provide alternative connection methods for Tor circuits,
enabling traffic obfuscation to bypass censorship.
"""

from __future__ import annotations

import base64
import hashlib
import os
import socket
import ssl
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlparse

from torscope import output


class TransportError(Exception):
    """Error during transport connection."""


class Transport(Protocol):
    """Abstract transport layer for relay connections."""

    def connect(self) -> ssl.SSLSocket:
        """Establish connection and return socket for OR protocol."""

    def close(self) -> None:
        """Close the transport."""


# WebSocket magic GUID from RFC 6455
WEBSOCKET_MAGIC = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _compute_websocket_accept(key: str) -> str:
    """Compute Sec-WebSocket-Accept value per RFC 6455."""
    combined = key.encode() + WEBSOCKET_MAGIC
    return base64.b64encode(hashlib.sha1(combined).digest()).decode()  # noqa: S324


def _generate_websocket_key() -> str:
    """Generate random Sec-WebSocket-Key (16 bytes, base64 encoded)."""
    return base64.b64encode(os.urandom(16)).decode()


@dataclass
class WebTunnelTransport:
    """
    WebTunnel pluggable transport.

    WebTunnel tunnels Tor traffic through a WebSocket-like HTTPS connection.
    The client connects via TLS, sends an HTTP upgrade request to a secret path,
    and upon receiving 101 Switching Protocols, the connection becomes a raw
    bidirectional tunnel for Tor OR protocol cells.

    Attributes:
        host: Bridge IP address (for TCP connection)
        port: Bridge port (for TCP connection)
        url: Full URL with secret path (https://hostname/secret-path)
        timeout: Connection timeout in seconds
    """

    host: str
    port: int
    url: str
    timeout: float = 30.0

    _socket: socket.socket | None = None
    _tls_socket: ssl.SSLSocket | None = None

    def connect(self) -> ssl.SSLSocket:
        """
        Establish WebTunnel connection.

        1. Parse URL to get SNI hostname and secret path
        2. Create TLS connection to bridge IP:port with SNI hostname
        3. Send HTTP upgrade request with WebSocket headers
        4. Validate 101 Switching Protocols response
        5. Return socket for OR protocol

        Returns:
            TLS socket ready for OR protocol

        Raises:
            TransportError: If connection or upgrade fails
        """
        # Parse URL to get hostname (for SNI) and path (for upgrade request)
        parsed = urlparse(self.url)
        if parsed.scheme != "https":
            raise TransportError(f"WebTunnel requires HTTPS URL, got: {parsed.scheme}")

        sni_hostname = parsed.hostname
        if not sni_hostname:
            raise TransportError(f"Invalid URL, no hostname: {self.url}")

        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        output.debug(f"WebTunnel: connecting to {self.host}:{self.port}, SNI={sni_hostname}")

        # Create TCP socket
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.settimeout(self.timeout)

        try:
            self._socket.connect((self.host, self.port))
        except OSError as e:
            self.close()
            raise TransportError(f"TCP connection failed: {e}") from e

        # Wrap with TLS using SNI hostname (not bridge IP)
        context = ssl.create_default_context()
        try:
            self._tls_socket = context.wrap_socket(self._socket, server_hostname=sni_hostname)
        except ssl.SSLError as e:
            self.close()
            raise TransportError(f"TLS handshake failed: {e}") from e

        output.debug("WebTunnel: TLS established, sending upgrade request")

        # Send HTTP upgrade request
        websocket_key = _generate_websocket_key()
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {sni_hostname}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {websocket_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        )

        try:
            self._tls_socket.sendall(request.encode())
        except OSError as e:
            self.close()
            raise TransportError(f"Failed to send upgrade request: {e}") from e

        # Read response (up to 4KB should be enough for headers)
        try:
            response = self._read_http_response()
        except OSError as e:
            self.close()
            raise TransportError(f"Failed to read upgrade response: {e}") from e

        # Parse and validate response
        self._validate_upgrade_response(response, websocket_key)

        output.debug("WebTunnel: upgrade successful, tunnel established")
        return self._tls_socket

    def _read_http_response(self) -> str:
        """Read HTTP response until end of headers."""
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self._tls_socket.recv(1024)  # type: ignore[union-attr]
            if not chunk:
                raise TransportError("Connection closed while reading response")
            data += chunk
            if len(data) > 8192:
                raise TransportError("Response too large")
        return data.decode("utf-8", errors="replace")

    def _validate_upgrade_response(self, response: str, websocket_key: str) -> None:
        """Validate HTTP 101 Switching Protocols response."""
        lines = response.split("\r\n")
        if not lines:
            raise TransportError("Empty response")

        # Parse status line
        status_line = lines[0]
        parts = status_line.split(" ", 2)
        if len(parts) < 2:
            raise TransportError(f"Invalid status line: {status_line}")

        try:
            status_code = int(parts[1])
        except ValueError:
            raise TransportError(f"Invalid status code: {parts[1]}") from None

        if status_code != 101:
            reason = parts[2] if len(parts) > 2 else ""
            raise TransportError(f"Upgrade failed: HTTP {status_code} {reason}")

        # Parse headers
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                break
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.lower().strip()] = value.strip()

        # Validate required headers
        if headers.get("upgrade", "").lower() != "websocket":
            raise TransportError("Missing or invalid Upgrade header")

        if "upgrade" not in headers.get("connection", "").lower():
            raise TransportError("Missing or invalid Connection header")

        # Validate Sec-WebSocket-Accept
        expected_accept = _compute_websocket_accept(websocket_key)
        actual_accept = headers.get("sec-websocket-accept", "")
        if actual_accept != expected_accept:
            raise TransportError(
                f"Invalid Sec-WebSocket-Accept: expected {expected_accept}, got {actual_accept}"
            )

    def close(self) -> None:
        """Close the transport connection."""
        if self._tls_socket:
            try:
                self._tls_socket.close()
            except OSError:
                pass
            self._tls_socket = None

        if self._socket:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None
