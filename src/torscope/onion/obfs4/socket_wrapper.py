"""
Socket wrapper for obfs4 encrypted streams.

This module provides a socket-like wrapper that handles obfs4 framing
transparently, allowing higher-level protocols (like TLS) to operate
over the encrypted tunnel.

The wrapper implements the socket interface required by ssl.wrap_socket().
"""

from __future__ import annotations

import socket
from typing import TYPE_CHECKING

from torscope.onion.obfs4.framing import (
    MAX_FRAME_PAYLOAD_LENGTH,
    TYPE_PAYLOAD,
    FrameReader,
    Obfs4Framing,
)

if TYPE_CHECKING:
    pass


class Obfs4Socket:
    """
    Socket-like wrapper for obfs4 encrypted stream.

    This class wraps a raw TCP socket and handles obfs4 framing
    transparently. It implements the socket interface required
    by ssl.SSLContext.wrap_socket().

    The wrapper:
    - Encrypts outgoing data into obfs4 frames
    - Decrypts incoming frames to recover original data
    - Buffers partial reads for the consumer
    """

    def __init__(
        self,
        sock: socket.socket,
        framing: Obfs4Framing,
    ):
        """
        Initialize the obfs4 socket wrapper.

        Args:
            sock: Raw TCP socket to the obfs4 server
            framing: Initialized Obfs4Framing instance
        """
        self._socket = sock
        self._framing = framing
        self._reader = FrameReader(framing)
        self._read_buffer = b""
        self._closed = False

    def send(self, data: bytes, _flags: int = 0) -> int:
        """
        Send data through the obfs4 tunnel.

        Data is fragmented into MAX_FRAME_PAYLOAD_LENGTH chunks,
        encrypted, and sent to the underlying socket.

        Args:
            data: Data to send
            _flags: Socket flags (ignored, kept for interface compatibility)

        Returns:
            Number of bytes sent (always len(data) on success)

        Raises:
            OSError: If the socket is closed or send fails
        """
        if self._closed:
            raise OSError("Socket is closed")

        if not data:
            return 0

        # Fragment into frames and send
        offset = 0
        while offset < len(data):
            chunk_size = min(MAX_FRAME_PAYLOAD_LENGTH, len(data) - offset)
            chunk = data[offset : offset + chunk_size]

            # Encrypt and send
            frame = self._framing.encrypt_frame(chunk, TYPE_PAYLOAD)
            self._socket.sendall(frame)

            offset += chunk_size

        return len(data)

    def sendall(self, data: bytes, flags: int = 0) -> None:
        """
        Send all data through the obfs4 tunnel.

        Args:
            data: Data to send
            flags: Socket flags (ignored)
        """
        self.send(data, flags)

    def recv(self, bufsize: int, _flags: int = 0) -> bytes:
        """
        Receive data from the obfs4 tunnel.

        Reads encrypted frames from the socket, decrypts them,
        and returns the payload data.

        Args:
            bufsize: Maximum bytes to return
            _flags: Socket flags (ignored, kept for interface compatibility)

        Returns:
            Decrypted data (may be less than bufsize)

        Raises:
            OSError: If the socket is closed or recv fails
        """
        if self._closed:
            raise OSError("Socket is closed")

        # Return buffered data if available
        if self._read_buffer:
            result = self._read_buffer[:bufsize]
            self._read_buffer = self._read_buffer[bufsize:]
            return result

        # Read more data from socket and decrypt
        while True:
            # Read from socket
            try:
                raw_data = self._socket.recv(4096)
            except TimeoutError:
                raise
            except OSError:
                if self._closed:
                    return b""
                raise

            if not raw_data:
                # Connection closed
                return b""

            # Feed to frame reader
            self._reader.feed(raw_data)

            # Try to extract frames
            frames = self._reader.read_all_frames()
            for frame_type, payload in frames:
                if frame_type == TYPE_PAYLOAD:
                    self._read_buffer += payload

            # Return what we have
            if self._read_buffer:
                result = self._read_buffer[:bufsize]
                self._read_buffer = self._read_buffer[bufsize:]
                return result

            # If no complete frames yet, continue reading

    def recv_into(self, buffer: bytearray, nbytes: int = 0, flags: int = 0) -> int:
        """
        Receive data into a buffer.

        Args:
            buffer: Buffer to receive into
            nbytes: Maximum bytes to receive (0 = buffer size)
            flags: Socket flags (ignored)

        Returns:
            Number of bytes received
        """
        if nbytes == 0:
            nbytes = len(buffer)

        data = self.recv(nbytes, flags)
        buffer[: len(data)] = data
        return len(data)

    def close(self) -> None:
        """Close the obfs4 connection."""
        self._closed = True
        try:
            self._socket.close()
        except OSError:
            pass

    def shutdown(self, how: int) -> None:
        """Shutdown the connection."""
        try:
            self._socket.shutdown(how)
        except OSError:
            pass

    # Methods required for ssl.wrap_socket()

    def fileno(self) -> int:
        """Return the socket's file descriptor."""
        return self._socket.fileno()

    def getpeername(self) -> tuple[str, int]:
        """Return the remote address."""
        result: tuple[str, int] = self._socket.getpeername()
        return result

    def getsockname(self) -> tuple[str, int]:
        """Return the local address."""
        result: tuple[str, int] = self._socket.getsockname()
        return result

    def settimeout(self, timeout: float | None) -> None:
        """Set the socket timeout."""
        self._socket.settimeout(timeout)

    def gettimeout(self) -> float | None:
        """Get the socket timeout."""
        return self._socket.gettimeout()

    def setblocking(self, flag: bool) -> None:
        """Set blocking mode."""
        self._socket.setblocking(flag)

    def getblocking(self) -> bool:
        """Get blocking mode."""
        return self._socket.getblocking()

    def setsockopt(self, level: int, optname: int, value: int | bytes) -> None:
        """Set socket option."""
        self._socket.setsockopt(level, optname, value)

    def getsockopt(self, level: int, optname: int, buflen: int = 0) -> int | bytes:
        """Get socket option."""
        if buflen:
            return self._socket.getsockopt(level, optname, buflen)
        return self._socket.getsockopt(level, optname)

    # Context manager support

    def __enter__(self) -> Obfs4Socket:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    # Make it look like a socket for type checking purposes

    @property
    def family(self) -> socket.AddressFamily:
        """Return socket family."""
        return self._socket.family

    @property
    def type(self) -> socket.SocketKind:
        """Return socket type."""
        return self._socket.type

    @property
    def proto(self) -> int:
        """Return socket protocol."""
        return self._socket.proto
