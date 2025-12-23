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
import struct
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from torscope.crypto import sha3_256, shake256
from torscope.crypto.proof_of_work import PowParams
from torscope.directory.models import ConsensusDocument, RouterStatusEntry
from torscope.onion.circuit import Circuit
from torscope.onion.connection import RelayConnection
from torscope.path import PathSelector

# Ed25519 certificate format (tor-spec appendix A.1)
# https://spec.torproject.org/cert-spec.html
#
# Certificate structure:
#   VERSION      (1 byte)  - offset 0
#   CERT_TYPE    (1 byte)  - offset 1
#   EXPIRATION   (4 bytes) - offset 2-5
#   KEY_TYPE     (1 byte)  - offset 6
#   CERTIFIED_KEY (32 bytes) - offset 7-38
#   N_EXTENSIONS (1 byte)  - offset 39
#   ...extensions...
ED25519_CERT_KEY_OFFSET = 7
ED25519_CERT_KEY_LEN = 32
ED25519_CERT_MIN_LEN = ED25519_CERT_KEY_OFFSET + ED25519_CERT_KEY_LEN  # 39 bytes


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

    # PoW parameters (from Proposal 327)
    pow_params: PowParams | None = None


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
    from torscope.microdesc import get_ntor_key

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
        _log(f"Getting ntor key for {router.nickname}...")
        result = get_ntor_key(router, consensus)
        if result is None:
            _log(f"Failed to get ntor key for {router.nickname}")
            return None
        ntor_key, source_name, source_type, from_cache = result
        _log(f"Got ntor key from {source_name} ({'cached' if from_cache else source_type})")
        ntor_keys.append(ntor_key)

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


def parse_hs_descriptor(
    content: str,
    blinded_key: bytes | None = None,
    subcredential: bytes | None = None,
    client_privkey: bytes | None = None,
) -> HSDescriptor:
    """Parse a complete HS descriptor.

    Args:
        content: Raw descriptor text
        blinded_key: 32-byte blinded public key (required for decryption)
        subcredential: 32-byte subcredential (required for decryption)
        client_privkey: Optional 32-byte X25519 private key for client auth

    Returns:
        Parsed HSDescriptor
    """
    outer = HSDescriptorOuter.parse(content)

    # Try to decrypt if keys are provided
    if blinded_key is not None and subcredential is not None:
        try:
            intro_points, pow_params = decrypt_descriptor(
                outer.superencrypted_blob,
                blinded_key,
                subcredential,
                outer.revision_counter,
                client_privkey=client_privkey,
            )
            return HSDescriptor(
                outer=outer,
                introduction_points=intro_points,
                decrypted=True,
                decryption_error=None,
                pow_params=pow_params,
            )
        except Exception as e:  # pylint: disable=broad-exception-caught
            return HSDescriptor(
                outer=outer,
                introduction_points=[],
                decrypted=False,
                decryption_error=str(e),
            )

    return HSDescriptor(
        outer=outer,
        introduction_points=[],
        decrypted=False,
        decryption_error="Keys not provided for decryption",
    )


# =============================================================================
# Descriptor Decryption (rend-spec-v3 section 2.5.1-2.5.3)
# =============================================================================

# Key lengths for AES-256-CTR
S_KEY_LEN = 32  # AES-256 key
S_IV_LEN = 16  # AES CTR IV/nonce
MAC_KEY_LEN = 32  # MAC key


def _decrypt_layer(
    encrypted_blob: bytes,
    secret_data: bytes,
    subcredential: bytes,
    revision_counter: int,
    string_constant: bytes,
) -> bytes:
    """Decrypt one layer of the HS descriptor.

    Args:
        encrypted_blob: The encrypted data (salt + ciphertext + mac)
        secret_data: SECRET_DATA for this layer (blinded_key for outer)
        subcredential: 32-byte subcredential
        revision_counter: Descriptor revision counter
        string_constant: String constant for this layer

    Returns:
        Decrypted plaintext

    Raises:
        ValueError: If MAC verification fails or data is malformed
    """
    # Minimum size: 16 (salt) + 32 (mac) = 48 bytes
    if len(encrypted_blob) < 48:
        raise ValueError(f"Encrypted blob too small: {len(encrypted_blob)} bytes")

    # Extract components: SALT (16) | ENCRYPTED | MAC (32)
    salt = encrypted_blob[:16]
    mac = encrypted_blob[-32:]
    ciphertext = encrypted_blob[16:-32]

    # Build secret_input = SECRET_DATA | subcredential | INT_8(revision_counter)
    secret_input = secret_data + subcredential + struct.pack(">Q", revision_counter)

    # Derive keys using SHAKE-256
    # keys = SHAKE256(secret_input | salt | STRING_CONSTANT, S_KEY_LEN + S_IV_LEN + MAC_KEY_LEN)
    kdf_input = secret_input + salt + string_constant
    keys = shake256(kdf_input, S_KEY_LEN + S_IV_LEN + MAC_KEY_LEN)

    secret_key = keys[:S_KEY_LEN]
    secret_iv = keys[S_KEY_LEN : S_KEY_LEN + S_IV_LEN]
    mac_key = keys[S_KEY_LEN + S_IV_LEN :]

    # Verify MAC
    # D_MAC = SHA3-256(mac_key_len | MAC_KEY | salt_len | SALT | ENCRYPTED)
    # mac_key_len and salt_len are 8-byte big-endian
    mac_input = (
        struct.pack(">Q", len(mac_key)) + mac_key + struct.pack(">Q", len(salt)) + salt + ciphertext
    )
    expected_mac = sha3_256(mac_input)

    if mac != expected_mac:
        raise ValueError("MAC verification failed")

    # Decrypt using AES-256-CTR
    cipher = Cipher(algorithms.AES(secret_key), modes.CTR(secret_iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext


def decrypt_outer_layer(
    superencrypted_blob: bytes,
    blinded_key: bytes,
    subcredential: bytes,
    revision_counter: int,
) -> bytes:
    """Decrypt the outer (superencrypted) layer.

    Args:
        superencrypted_blob: The superencrypted blob from the descriptor
        blinded_key: 32-byte blinded public key
        subcredential: 32-byte subcredential
        revision_counter: Descriptor revision counter

    Returns:
        Decrypted first layer plaintext
    """
    return _decrypt_layer(
        superencrypted_blob,
        blinded_key,
        subcredential,
        revision_counter,
        b"hsdir-superencrypted-data",
    )


def decrypt_inner_layer(
    encrypted_blob: bytes,
    blinded_key: bytes,
    subcredential: bytes,
    revision_counter: int,
    descriptor_cookie: bytes | None = None,
) -> bytes:
    """Decrypt the inner (encrypted) layer.

    Args:
        encrypted_blob: The encrypted blob from the first layer
        blinded_key: 32-byte blinded public key
        subcredential: 32-byte subcredential
        revision_counter: Descriptor revision counter
        descriptor_cookie: Optional 32-byte client auth cookie

    Returns:
        Decrypted second layer plaintext (introduction points)
    """
    # SECRET_DATA = blinded_key | descriptor_cookie (if client auth enabled)
    if descriptor_cookie:
        secret_data = blinded_key + descriptor_cookie
    else:
        secret_data = blinded_key

    return _decrypt_layer(
        encrypted_blob,
        secret_data,
        subcredential,
        revision_counter,
        b"hsdir-encrypted-data",
    )


def _parse_first_layer(plaintext: bytes) -> tuple[bytes, str]:
    """Parse the first layer plaintext to extract the encrypted blob.

    First layer format:
        desc-auth-type ...
        desc-auth-ephemeral-key ...
        auth-client ...
        encrypted
        -----BEGIN MESSAGE-----
        <base64>
        -----END MESSAGE-----

    Args:
        plaintext: Decrypted first layer

    Returns:
        Tuple of (encrypted_blob, first_layer_text)
        The text is needed for client auth parsing.
    """
    text = plaintext.decode("utf-8", errors="replace")
    lines = text.strip().split("\n")

    i = 0
    while i < len(lines):
        line = lines[i].strip()

        if line == "encrypted":
            # Read the MESSAGE block
            blob_lines = []
            i += 1
            while i < len(lines) and not lines[i].startswith("-----END"):
                if not lines[i].startswith("-----BEGIN"):
                    blob_lines.append(lines[i].strip())
                i += 1
            return base64.b64decode("".join(blob_lines)), text

        i += 1

    raise ValueError("No encrypted blob found in first layer")


def _parse_second_layer(
    plaintext: bytes,
) -> tuple[list[IntroductionPoint], PowParams | None]:
    """Parse introduction points and pow-params from decrypted second layer.

    Second layer format:
        create2-formats 2
        intro-auth-required ed25519
        single-onion-service  (optional)
        pow-params v1 <seed-b64> <suggested-effort> <expiration>  (optional)
        introduction-point <link-specifiers-base64>
        onion-key ntor <base64>
        auth-key
        -----BEGIN ED25519 CERT-----
        ...
        -----END ED25519 CERT-----
        enc-key ntor <base64>
        enc-key-cert
        -----BEGIN ED25519 CERT-----
        ...
        -----END ED25519 CERT-----

    Args:
        plaintext: Decrypted second layer

    Returns:
        Tuple of (IntroductionPoint list, PowParams or None)
    """
    text = plaintext.decode("utf-8", errors="replace")
    lines = text.strip().split("\n")

    intro_points: list[IntroductionPoint] = []
    current_ip: IntroductionPoint | None = None
    pow_params: PowParams | None = None

    i = 0
    while i < len(lines):
        line = lines[i].strip()

        if line.startswith("pow-params "):
            # Parse PoW parameters (Proposal 327)
            try:
                pow_params = PowParams.parse(line)
            except ValueError:
                # Invalid pow-params, skip silently
                pass

        elif line.startswith("introduction-point "):
            # Start a new introduction point
            if current_ip is not None:
                intro_points.append(current_ip)

            current_ip = IntroductionPoint()

            # Parse link specifiers
            link_spec_b64 = line.split()[1]
            # Add padding if needed
            padding = 4 - len(link_spec_b64) % 4
            if padding != 4:
                link_spec_b64 += "=" * padding
            link_spec_data = base64.b64decode(link_spec_b64)
            current_ip.link_specifiers = _parse_link_specifiers(link_spec_data)

        elif current_ip is not None:
            if line.startswith("onion-key ntor "):
                # Curve25519 key for ntor
                key_b64 = line.split()[2]
                padding = 4 - len(key_b64) % 4
                if padding != 4:
                    key_b64 += "=" * padding
                current_ip.onion_key_ntor = base64.b64decode(key_b64)

            elif line.startswith("enc-key ntor "):
                # X25519 encryption key
                key_b64 = line.split()[2]
                padding = 4 - len(key_b64) % 4
                if padding != 4:
                    key_b64 += "=" * padding
                current_ip.enc_key = base64.b64decode(key_b64)

            elif line.startswith("auth-key"):
                # Read Ed25519 auth key certificate
                cert_lines = []
                i += 1
                while i < len(lines) and not lines[i].startswith("-----END"):
                    if not lines[i].startswith("-----BEGIN"):
                        cert_lines.append(lines[i].strip())
                    i += 1
                cert_data = base64.b64decode("".join(cert_lines))
                # Extract the auth key (CERTIFIED_KEY) from the Ed25519 certificate
                if len(cert_data) >= ED25519_CERT_MIN_LEN:
                    current_ip.auth_key = cert_data[
                        ED25519_CERT_KEY_OFFSET : ED25519_CERT_KEY_OFFSET + ED25519_CERT_KEY_LEN
                    ]

        i += 1

    # Don't forget the last one
    if current_ip is not None:
        intro_points.append(current_ip)

    return intro_points, pow_params


def _parse_link_specifiers(data: bytes) -> list[tuple[int, bytes]]:
    """Parse link specifiers from binary data.

    Format:
        NSPEC (1 byte) - number of specifiers
        For each specifier:
            LSTYPE (1 byte) - type
            LSLEN (1 byte) - length
            LSDATA (LSLEN bytes) - data

    Link specifier types:
        0: TLS-TCP-IPv4 (6 bytes: 4 IP + 2 port)
        1: TLS-TCP-IPv6 (18 bytes: 16 IP + 2 port)
        2: Legacy identity (20 bytes: RSA fingerprint)
        3: Ed25519 identity (32 bytes)

    Args:
        data: Raw link specifier data

    Returns:
        List of (type, data) tuples
    """
    if len(data) < 1:
        return []

    nspec = data[0]
    specifiers: list[tuple[int, bytes]] = []
    offset = 1

    for _ in range(nspec):
        if offset + 2 > len(data):
            break

        lstype = data[offset]
        lslen = data[offset + 1]
        offset += 2

        if offset + lslen > len(data):
            break

        lsdata = data[offset : offset + lslen]
        specifiers.append((lstype, lsdata))
        offset += lslen

    return specifiers


def decrypt_descriptor(
    superencrypted_blob: bytes,
    blinded_key: bytes,
    subcredential: bytes,
    revision_counter: int,
    descriptor_cookie: bytes | None = None,
    client_privkey: bytes | None = None,
) -> tuple[list[IntroductionPoint], PowParams | None]:
    """Decrypt a v3 hidden service descriptor and parse introduction points.

    This performs both layers of decryption:
    1. Outer layer (superencrypted) -> reveals auth data and inner blob
    2. Inner layer (encrypted) -> reveals introduction points and pow-params

    For private hidden services with client authorization, either provide
    descriptor_cookie directly, or provide client_privkey to derive it.

    Args:
        superencrypted_blob: The superencrypted blob from the descriptor
        blinded_key: 32-byte blinded public key
        subcredential: 32-byte subcredential
        revision_counter: Descriptor revision counter
        descriptor_cookie: Optional 32-byte client auth cookie (direct)
        client_privkey: Optional 32-byte X25519 private key for client auth

    Returns:
        Tuple of (IntroductionPoint list, PowParams or None)

    Raises:
        ValueError: If decryption or parsing fails
    """
    # Decrypt outer layer
    first_layer_plaintext = decrypt_outer_layer(
        superencrypted_blob, blinded_key, subcredential, revision_counter
    )

    # Parse first layer to get the encrypted blob and text
    encrypted_blob, first_layer_text = _parse_first_layer(first_layer_plaintext)

    # Try to decrypt the inner layer.
    # All v3 descriptors have auth fields (for privacy), but public services
    # use random entries that don't correspond to real keys.
    # Strategy: try public decryption first, fall back to client auth if it fails.

    from torscope.directory.client_auth import get_descriptor_cookie

    # If client_privkey provided, try to derive descriptor_cookie
    if client_privkey is not None and descriptor_cookie is None:
        descriptor_cookie = get_descriptor_cookie(
            first_layer_text=first_layer_text,
            client_privkey=client_privkey,
            subcredential=subcredential,
        )

    # Try decryption - first without cookie (public), then with cookie if provided
    try:
        second_layer_plaintext = decrypt_inner_layer(
            encrypted_blob, blinded_key, subcredential, revision_counter, descriptor_cookie
        )
    except ValueError as e:
        if "MAC verification failed" in str(e):
            # Decryption failed - might need client authorization
            if client_privkey is None:
                raise ValueError("Client authorization required") from e
            raise ValueError("Client key not authorized for this service") from e
        raise

    # Parse second layer (introduction points and pow-params)
    return _parse_second_layer(second_layer_plaintext)
