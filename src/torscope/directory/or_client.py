"""
Directory client using OR protocol (BEGIN_DIR).

This module provides functionality to fetch directory documents through
the Tor network using the OR protocol with BEGIN_DIR streams.

This is used for fetching from "mirrors" (relays with V2Dir flag) after
the initial bootstrap, which must use direct HTTP to authorities/fallbacks.
"""

import base64
import random

from torscope.directory.models import ConsensusDocument, RouterStatusEntry
from torscope.onion.circuit import Circuit
from torscope.onion.connection import RelayConnection


def fetch_ntor_key(fingerprint: str, timeout: int = 30) -> tuple[bytes, str] | None:
    """
    Fetch and decode ntor-onion-key for a relay via direct HTTP.

    Args:
        fingerprint: Relay fingerprint
        timeout: HTTP request timeout

    Returns:
        Tuple of (32-byte ntor-onion-key, authority_nickname), or None if not available
    """
    # Import here to avoid circular imports
    # pylint: disable=import-outside-toplevel
    from torscope.directory.client import DirectoryClient
    from torscope.directory.descriptor import ServerDescriptorParser

    # pylint: enable=import-outside-toplevel

    client = DirectoryClient(timeout=timeout)
    content, authority = client.fetch_server_descriptors([fingerprint])
    descriptors = ServerDescriptorParser.parse(content)
    if not descriptors or not descriptors[0].ntor_onion_key:
        return None

    key_b64 = descriptors[0].ntor_onion_key
    # Add padding if needed
    padding = 4 - len(key_b64) % 4
    if padding != 4:
        key_b64 += "=" * padding
    return base64.b64decode(key_b64), authority.nickname


class ORDirectoryClient:
    """Directory client that fetches documents via OR protocol (BEGIN_DIR)."""

    def __init__(self, consensus: ConsensusDocument, timeout: float = 30.0) -> None:
        """
        Initialize the OR directory client.

        Args:
            consensus: A valid consensus document (needed to find V2Dir relays)
            timeout: Connection timeout in seconds
        """
        self.consensus = consensus
        self.timeout = timeout

    def _select_v2dir_relay(self, exclude: list[str] | None = None) -> RouterStatusEntry | None:
        """Select a random relay with V2Dir flag."""
        exclude_set = set(exclude) if exclude else set()
        candidates = [
            r
            for r in self.consensus.routers
            if r.has_flag("V2Dir")
            and r.has_flag("Fast")
            and r.has_flag("Stable")
            and r.fingerprint not in exclude_set
        ]
        if not candidates:
            return None
        return random.choice(candidates)

    def _get_ntor_key(self, fingerprint: str) -> bytes | None:
        """Fetch and decode ntor-onion-key for a relay via direct HTTP."""
        result = fetch_ntor_key(fingerprint, int(self.timeout))
        if result is None:
            return None
        return result[0]  # Return just the key, not the authority

    def _fetch_via_begin_dir(
        self, relay: RouterStatusEntry, path: str
    ) -> tuple[bytes, RouterStatusEntry]:
        """
        Fetch a document via BEGIN_DIR to a specific relay.

        Args:
            relay: The relay to connect to (must have V2Dir flag)
            path: The HTTP path to request (e.g., /tor/status-vote/current/consensus)

        Returns:
            Tuple of (document_body, relay_used)

        Raises:
            ConnectionError: If connection or circuit creation fails
            RuntimeError: If BEGIN_DIR stream fails
        """
        # Get ntor key for the relay
        ntor_key = self._get_ntor_key(relay.fingerprint)
        if ntor_key is None:
            raise RuntimeError(f"No ntor-onion-key for {relay.nickname}")

        # Connect to relay
        conn = RelayConnection(host=relay.ip, port=relay.orport, timeout=self.timeout)

        try:
            conn.connect()

            if not conn.handshake():
                raise ConnectionError("Link handshake failed")

            # Create 1-hop circuit
            circuit = Circuit.create(conn)

            if not circuit.extend_to(relay.fingerprint, ntor_key):
                raise RuntimeError("CREATE2 failed")

            # Open directory stream
            stream_id = circuit.begin_dir()
            if stream_id is None:
                circuit.destroy()
                raise RuntimeError("BEGIN_DIR rejected by relay")

            # Send HTTP GET request
            http_request = f"GET {path} HTTP/1.0\r\nHost: {relay.ip}\r\n\r\n"
            circuit.send_data(stream_id, http_request.encode("ascii"))

            # Receive response (up to ~2.5MB)
            response_data = b""
            for _ in range(5000):  # 5000 * 498 bytes ≈ 2.5MB
                data = circuit.recv_data(stream_id)
                if data is None:
                    break
                response_data += data

            circuit.destroy()

            if not response_data:
                raise RuntimeError("No response received")

            # Parse HTTP response - extract body
            if b"\r\n\r\n" in response_data:
                header_end = response_data.index(b"\r\n\r\n")
                body = response_data[header_end + 4 :]
            else:
                body = response_data

            return body, relay

        finally:
            conn.close()

    def fetch_consensus(
        self,
        relay: RouterStatusEntry | None = None,
        consensus_type: str = "microdesc",
    ) -> tuple[bytes, RouterStatusEntry]:
        """
        Fetch consensus document via BEGIN_DIR.

        Args:
            relay: Specific relay to use (random V2Dir relay if None)
            consensus_type: Type of consensus ("microdesc" or "full")

        Returns:
            Tuple of (consensus_bytes, relay_used)

        Raises:
            RuntimeError: If no suitable relay found or fetch fails
        """
        if relay is None:
            relay = self._select_v2dir_relay()
            if relay is None:
                raise RuntimeError("No suitable V2Dir relay found")

        if consensus_type == "microdesc":
            path = "/tor/status-vote/current/consensus-microdesc"
        else:
            path = "/tor/status-vote/current/consensus"

        return self._fetch_via_begin_dir(relay, path)

    def fetch_server_descriptors(
        self,
        fingerprints: list[str],
        relay: RouterStatusEntry | None = None,
    ) -> tuple[bytes, RouterStatusEntry]:
        """
        Fetch server descriptors via BEGIN_DIR.

        Args:
            fingerprints: List of hex-encoded fingerprints
            relay: Specific relay to use (random V2Dir relay if None)

        Returns:
            Tuple of (descriptors_bytes, relay_used)

        Raises:
            RuntimeError: If no suitable relay found or fetch fails
        """
        if relay is None:
            relay = self._select_v2dir_relay()
            if relay is None:
                raise RuntimeError("No suitable V2Dir relay found")

        fp_string = "+".join(fingerprints)
        path = f"/tor/server/fp/{fp_string}"

        return self._fetch_via_begin_dir(relay, path)

    def fetch_extra_info(
        self,
        fingerprints: list[str],
        relay: RouterStatusEntry | None = None,
    ) -> tuple[bytes, RouterStatusEntry]:
        """
        Fetch extra-info descriptors via BEGIN_DIR.

        Args:
            fingerprints: List of hex-encoded fingerprints
            relay: Specific relay to use (random V2Dir relay if None)

        Returns:
            Tuple of (descriptors_bytes, relay_used)

        Raises:
            RuntimeError: If no suitable relay found or fetch fails
        """
        if relay is None:
            relay = self._select_v2dir_relay()
            if relay is None:
                raise RuntimeError("No suitable V2Dir relay found")

        fp_string = "+".join(fingerprints)
        path = f"/tor/extra/fp/{fp_string}"

        return self._fetch_via_begin_dir(relay, path)

    def fetch_microdescriptors(
        self,
        hashes: list[str],
        relay: RouterStatusEntry | None = None,
    ) -> tuple[bytes, RouterStatusEntry]:
        """
        Fetch microdescriptors via BEGIN_DIR.

        Args:
            hashes: List of base64-encoded SHA256 hashes
            relay: Specific relay to use (random V2Dir relay if None)

        Returns:
            Tuple of (descriptors_bytes, relay_used)

        Raises:
            RuntimeError: If no suitable relay found or fetch fails
        """
        if relay is None:
            relay = self._select_v2dir_relay()
            if relay is None:
                raise RuntimeError("No suitable V2Dir relay found")

        # Remove trailing '=' from base64 hashes and join with '-'
        hash_string = "-".join(h.rstrip("=") for h in hashes)
        path = f"/tor/micro/d/{hash_string}"

        return self._fetch_via_begin_dir(relay, path)
