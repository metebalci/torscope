"""Hidden Service (v3) descriptor fetching and parsing.

This module handles v3 hidden service descriptors as specified in rend-spec-v3.txt.

Descriptor structure (outer layer):
    hs-descriptor 3
    descriptor-lifetime <minutes>
    descriptor-signing-key-cert
    -----BEGIN ED25519 CERT-----
    ...
    -----END ED25519 CERT-----
    revision-counter <counter>
    superencrypted
    -----BEGIN MESSAGE-----
    <base64 encrypted blob>
    -----END MESSAGE-----
    signature <base64 signature>
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

from torscope.directory.models import ConsensusDocument, RouterStatusEntry
from torscope.onion.circuit import Circuit
from torscope.onion.connection import RelayConnection
from torscope.path import PathSelector


@dataclass
class HSDescriptorOuter:
    """Parsed outer layer of a v3 hidden service descriptor."""

    version: int  # Should be 3
    descriptor_lifetime: int  # Minutes
    signing_key_cert: bytes  # Ed25519 certificate
    revision_counter: int
    superencrypted_blob: bytes  # Encrypted inner descriptor
    signature: bytes  # Ed25519 signature

    # Raw data for verification
    raw_descriptor: str = ""

    @classmethod
    def parse(cls, content: str) -> HSDescriptorOuter:
        """Parse the outer layer of an HS descriptor.

        Args:
            content: Raw descriptor text

        Returns:
            Parsed HSDescriptorOuter

        Raises:
            ValueError: If parsing fails
        """
        lines = content.strip().split("\n")

        version: int | None = None
        descriptor_lifetime: int | None = None
        signing_key_cert: bytes | None = None
        revision_counter: int | None = None
        superencrypted_blob: bytes | None = None
        signature: bytes | None = None

        i = 0
        while i < len(lines):
            line = lines[i].strip()

            if line.startswith("hs-descriptor "):
                version = int(line.split()[1])

            elif line.startswith("descriptor-lifetime "):
                descriptor_lifetime = int(line.split()[1])

            elif line.startswith("descriptor-signing-key-cert"):
                # Read Ed25519 certificate (PEM block)
                cert_lines = []
                i += 1
                while i < len(lines) and not lines[i].startswith("-----END"):
                    if not lines[i].startswith("-----BEGIN"):
                        cert_lines.append(lines[i].strip())
                    i += 1
                signing_key_cert = base64.b64decode("".join(cert_lines))

            elif line.startswith("revision-counter "):
                revision_counter = int(line.split()[1])

            elif line.startswith("superencrypted"):
                # Read encrypted blob (MESSAGE block)
                blob_lines = []
                i += 1
                while i < len(lines) and not lines[i].startswith("-----END"):
                    if not lines[i].startswith("-----BEGIN"):
                        blob_lines.append(lines[i].strip())
                    i += 1
                superencrypted_blob = base64.b64decode("".join(blob_lines))

            elif line.startswith("signature "):
                sig_b64 = line.split()[1]
                # Handle base64 padding
                padding = 4 - len(sig_b64) % 4
                if padding != 4:
                    sig_b64 += "=" * padding
                signature = base64.b64decode(sig_b64)

            i += 1

        # Validate required fields
        if version is None:
            raise ValueError("Missing hs-descriptor version")
        if version != 3:
            raise ValueError(f"Unsupported descriptor version: {version}")
        if descriptor_lifetime is None:
            raise ValueError("Missing descriptor-lifetime")
        if signing_key_cert is None:
            raise ValueError("Missing descriptor-signing-key-cert")
        if revision_counter is None:
            raise ValueError("Missing revision-counter")
        if superencrypted_blob is None:
            raise ValueError("Missing superencrypted blob")
        if signature is None:
            raise ValueError("Missing signature")

        return cls(
            version=version,
            descriptor_lifetime=descriptor_lifetime,
            signing_key_cert=signing_key_cert,
            revision_counter=revision_counter,
            superencrypted_blob=superencrypted_blob,
            signature=signature,
            raw_descriptor=content,
        )


@dataclass
class IntroductionPoint:
    """A hidden service introduction point."""

    # Link specifiers (how to connect to the intro point)
    link_specifiers: list[tuple[int, bytes]] = field(default_factory=list)  # [(type, data), ...]

    # Keys
    onion_key_ntor: bytes | None = None  # Curve25519 key for ntor
    auth_key: bytes | None = None  # Ed25519 authentication key
    enc_key: bytes | None = None  # X25519 encryption key

    # Derived properties
    @property
    def ip_address(self) -> str | None:
        """Get IPv4 address from link specifiers."""
        for spec_type, data in self.link_specifiers:
            if spec_type == 0 and len(data) == 6:  # TLS_TCP_IPV4
                ip = ".".join(str(b) for b in data[:4])
                return ip
        return None

    @property
    def port(self) -> int | None:
        """Get port from link specifiers."""
        for spec_type, data in self.link_specifiers:
            if spec_type == 0 and len(data) == 6:  # TLS_TCP_IPV4
                return int.from_bytes(data[4:6], "big")
            if spec_type == 1 and len(data) == 18:  # TLS_TCP_IPV6
                return int.from_bytes(data[16:18], "big")
        return None

    @property
    def fingerprint(self) -> str | None:
        """Get legacy identity fingerprint from link specifiers."""
        for spec_type, data in self.link_specifiers:
            if spec_type == 2 and len(data) == 20:  # LEGACY_ID
                return data.hex().upper()
        return None


@dataclass
class HSDescriptor:
    """Complete parsed v3 hidden service descriptor."""

    outer: HSDescriptorOuter
    introduction_points: list[IntroductionPoint] = field(default_factory=list)

    # Decryption status
    decrypted: bool = False
    decryption_error: str | None = None


def fetch_hs_descriptor(
    consensus: ConsensusDocument,
    hsdir: RouterStatusEntry,
    blinded_key: bytes,
    timeout: float = 30.0,
    use_3hop_circuit: bool = True,
    verbose: bool = False,
) -> tuple[str, RouterStatusEntry] | None:
    """Fetch hidden service descriptor from an HSDir.

    Args:
        consensus: Network consensus
        hsdir: The HSDir to fetch from
        blinded_key: 32-byte blinded public key
        timeout: Connection timeout
        use_3hop_circuit: If True, build 3-hop circuit for anonymity
        verbose: If True, print debug information

    Returns:
        Tuple of (descriptor_text, hsdir_used) or None if fetch fails
    """
    # pylint: disable=import-outside-toplevel
    from torscope.cache import get_ntor_key_from_cache
    from torscope.directory.or_client import fetch_ntor_key

    # pylint: enable=import-outside-toplevel

    def _log(msg: str) -> None:
        if verbose:
            print(f"    [debug] {msg}")

    # Build the path (URL) for the descriptor
    # Format: /tor/hs/3/<blinded_key_base64>
    blinded_key_b64 = base64.b64encode(blinded_key).decode("ascii").rstrip("=")
    path = f"/tor/hs/3/{blinded_key_b64}"
    _log(f"Path: {path}")

    if use_3hop_circuit:
        # Build 3-hop circuit to HSDir for anonymity
        selector = PathSelector(consensus=consensus)
        try:
            # Select path with HSDir as the exit
            circuit_path = selector.select_path(num_hops=3, exit_router=hsdir)
            _log("Selected 3-hop path")
        except ValueError as e:
            _log(f"Failed to select 3-hop path: {e}")
            # If we can't build a 3-hop path, fall back to 1-hop
            circuit_path = None
            routers = [hsdir]
    else:
        circuit_path = None
        routers = [hsdir]
        _log("Using 1-hop direct connection")

    if circuit_path:
        routers = circuit_path.routers

    # Get ntor keys for all routers in the path
    ntor_keys: list[bytes] = []
    for router in routers:
        # Try cache first (using microdesc_hash, not fingerprint)
        if router.microdesc_hash:
            cached_result = get_ntor_key_from_cache(router.microdesc_hash)
            if cached_result:
                ntor_keys.append(cached_result[0])  # Extract just the key bytes
                _log(f"Got ntor key from cache for {router.nickname}")
                continue

        # Fetch via HTTP using fingerprint
        _log(f"Fetching ntor key for {router.nickname}...")
        result = fetch_ntor_key(router.fingerprint, int(timeout))
        if result is None:
            _log(f"Failed to fetch ntor key for {router.nickname}")
            return None
        ntor_keys.append(result[0])

    # Connect and build circuit
    first_router = routers[0]
    _log(f"Connecting to {first_router.nickname} ({first_router.ip}:{first_router.orport})")
    conn = RelayConnection(host=first_router.ip, port=first_router.orport, timeout=timeout)

    try:
        conn.connect()
        _log("Connected, starting handshake...")

        if not conn.handshake():
            _log("Handshake failed")
            return None
        _log("Handshake OK")

        # Create circuit
        circuit = Circuit.create(conn)
        _log(f"Created circuit {circuit.circ_id}")

        # Extend to each hop
        for i, (router, ntor_key) in enumerate(zip(routers, ntor_keys, strict=True)):
            _log(f"Extending to hop {i+1}: {router.nickname}")
            if i == 0:
                if not circuit.extend_to(router.fingerprint, ntor_key):
                    _log(f"Failed to extend to {router.nickname}")
                    circuit.destroy()
                    return None
            else:
                if not circuit.extend_to(
                    router.fingerprint, ntor_key, ip=router.ip, port=router.orport
                ):
                    _log(f"Failed to extend to {router.nickname}")
                    circuit.destroy()
                    return None
            _log(f"Extended to {router.nickname} OK")

        # Open directory stream via BEGIN_DIR
        _log("Opening BEGIN_DIR stream...")
        stream_id = circuit.begin_dir()
        if stream_id is None:
            _log("BEGIN_DIR failed")
            circuit.destroy()
            return None
        _log(f"BEGIN_DIR OK, stream_id={stream_id}")

        # Send HTTP GET request for the HS descriptor
        http_request = f"GET {path} HTTP/1.0\r\nHost: {hsdir.ip}\r\n\r\n"
        _log("Sending HTTP request...")
        circuit.send_data(stream_id, http_request.encode("ascii"))

        # Receive response
        response_data = b""
        for _ in range(1000):  # Up to ~500KB
            data = circuit.recv_data(stream_id)
            if data is None:
                break
            response_data += data

        _log(f"Received {len(response_data)} bytes")
        circuit.destroy()

        if not response_data:
            _log("No response data")
            return None

        # Parse HTTP response
        if b"\r\n\r\n" in response_data:
            header_end = response_data.index(b"\r\n\r\n")
            headers = response_data[:header_end].decode("ascii", errors="replace")
            body = response_data[header_end + 4 :]
            status_line = headers.split("\r\n")[0]
            _log(f"HTTP status: {status_line}")

            # Check for HTTP errors
            if "404" in status_line:
                _log("Got 404 Not Found")
                return None
            if "200" not in status_line:
                _log("Got non-200 status")
                return None

            _log(f"Success! Body is {len(body)} bytes")
            return body.decode("ascii", errors="replace"), hsdir

        _log("No HTTP headers in response")
        return None

    except (ConnectionError, OSError) as e:
        _log(f"Connection error: {e}")
        return None
    finally:
        conn.close()


def parse_hs_descriptor(content: str) -> HSDescriptor:
    """Parse a complete HS descriptor.

    Args:
        content: Raw descriptor text

    Returns:
        Parsed HSDescriptor

    Note:
        This only parses the outer layer. The introduction points
        require decryption which is not yet implemented.
    """
    outer = HSDescriptorOuter.parse(content)

    return HSDescriptor(
        outer=outer,
        introduction_points=[],
        decrypted=False,
        decryption_error="Decryption not yet implemented",
    )
