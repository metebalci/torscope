"""
RELAY cell implementation.

RELAY cells carry data through established circuits. Each relay cell
has an 11-byte header followed by data and padding.

See: https://spec.torproject.org/tor-spec/relay-cells.html
"""

from __future__ import annotations

import hashlib
import hmac
import socket
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.ciphers import Cipher, CipherContext, algorithms, modes

if TYPE_CHECKING:
    from torscope.crypto.proof_of_work import PowSolution

# Relay cell format (tor-spec section 6.1)
# https://spec.torproject.org/tor-spec/relay-cells.html
#
# Relay cell payload structure (when decrypted):
#   +----------+------------+-----------+--------+--------+------+---------+
#   | Command  | Recognized | StreamID  | Digest | Length | Data | Padding |
#   | 1 byte   |  2 bytes   |  2 bytes  | 4 bytes| 2 bytes| var  |  var    |
#   +----------+------------+-----------+--------+--------+------+---------+
#   |<-------------------------- 509 bytes -------------------------------->|
#
# - Command: Relay command (BEGIN, DATA, END, etc.)
# - Recognized: Set to 0 when cell is for us (used for layered decryption)
# - StreamID: Stream identifier (0 for control, >0 for data streams)
# - Digest: First 4 bytes of running SHA-1 digest (for integrity)
# - Length: Number of data bytes (0-498)
# - Data: Actual payload data
# - Padding: Random padding to fill 509 bytes
RELAY_BODY_LEN = 509

# =============================================================================
# Flow Control Constants
# See: https://spec.torproject.org/tor-spec/flow-control.html
# =============================================================================

# Circuit-level flow control
CIRCUIT_WINDOW_INITIAL = 1000  # Initial deliver window (cells)
CIRCUIT_WINDOW_INCREMENT = 100  # SENDME increments window by this amount
CIRCUIT_SENDME_THRESHOLD = 900  # Send SENDME when window drops to this

# Stream-level flow control
STREAM_WINDOW_INITIAL = 500  # Initial deliver window per stream (cells)
STREAM_WINDOW_INCREMENT = 50  # SENDME increments window by this amount
STREAM_SENDME_THRESHOLD = 450  # Send SENDME when window drops to this

# SENDME version
SENDME_VERSION_0 = 0  # Legacy: empty payload
SENDME_VERSION_1 = 1  # Authenticated: includes digest

# =============================================================================
# BEGIN Flags (tor-spec section 6.2)
# See: https://spec.torproject.org/tor-spec/opening-streams.html
# =============================================================================
# These flags control IPv4/IPv6 address preferences for stream connections.
# The FLAGS field is a 32-bit value; only bits 1-3 are currently defined.
BEGIN_FLAG_IPV6_OK = 0x01  # Bit 1: We support IPv6 addresses
BEGIN_FLAG_IPV4_NOT_OK = 0x02  # Bit 2: We don't want IPv4 addresses
BEGIN_FLAG_IPV6_PREFERRED = 0x04  # Bit 3: Prefer IPv6 over IPv4

# Relay header: Command(1) + Recognized(2) + StreamID(2) + Digest(4) + Length(2)
RELAY_HEADER_LEN = 11

# Maximum data in a relay cell: 509 - 11 = 498 bytes
RELAY_DATA_LEN = RELAY_BODY_LEN - RELAY_HEADER_LEN


class RelayCommand(IntEnum):
    """RELAY cell command types."""

    # Core protocol (1-15)
    BEGIN = 1  # Open a stream
    DATA = 2  # Data on a stream
    END = 3  # Close a stream
    CONNECTED = 4  # Response to BEGIN
    SENDME = 5  # Flow control
    EXTEND = 6  # Extend circuit (old)
    EXTENDED = 7  # Response to EXTEND
    TRUNCATE = 8  # Truncate circuit
    TRUNCATED = 9  # Response to TRUNCATE
    DROP = 10  # Long-range dummy
    RESOLVE = 11  # DNS resolve
    RESOLVED = 12  # Response to RESOLVE
    BEGIN_DIR = 13  # Begin directory stream
    EXTEND2 = 14  # Extend circuit (new)
    EXTENDED2 = 15  # Response to EXTEND2

    # Reserved for UDP (16-18)

    # Conflux (19-22)
    CONFLUX_LINK = 19
    CONFLUX_LINKED = 20
    CONFLUX_LINKED_ACK = 21
    CONFLUX_SWITCH = 22

    # Onion services (32-40)
    ESTABLISH_INTRO = 32
    ESTABLISH_RENDEZVOUS = 33
    INTRODUCE1 = 34
    INTRODUCE2 = 35
    RENDEZVOUS1 = 36
    RENDEZVOUS2 = 37
    INTRO_ESTABLISHED = 38
    RENDEZVOUS_ESTABLISHED = 39
    INTRODUCE_ACK = 40

    # Circuit padding (41-42)
    PADDING_NEGOTIATE = 41
    PADDING_NEGOTIATED = 42

    # Flow control (43-44)
    XOFF = 43
    XON = 44


class RelayEndReason(IntEnum):
    """Reasons for RELAY_END cell."""

    MISC = 1  # Catch-all for unlisted reasons
    RESOLVEFAILED = 2  # Couldn't look up hostname
    CONNECTREFUSED = 3  # Remote host refused connection
    EXITPOLICY = 4  # Relay refuses to connect
    DESTROY = 5  # Circuit is being destroyed
    DONE = 6  # Connection closed normally
    TIMEOUT = 7  # Connection timed out
    NOROUTE = 8  # Routing error
    HIBERNATING = 9  # Relay is hibernating
    INTERNAL = 10  # Internal error
    RESOURCELIMIT = 11  # No resources
    CONNRESET = 12  # Connection reset
    TORPROTOCOL = 13  # Protocol violation
    NOTDIRECTORY = 14  # Not a directory relay


@dataclass
class RelayCell:
    """
    A RELAY cell for carrying data through a circuit.

    Format (unencrypted):
        relay_command: 1 byte
        recognized: 2 bytes (must be 0)
        stream_id: 2 bytes
        digest: 4 bytes (running hash)
        length: 2 bytes
        data: variable (up to 498 bytes)
        padding: remainder (zeros)

    Total: 509 bytes (RELAY_BODY_LEN)
    """

    relay_command: RelayCommand
    stream_id: int = 0
    data: bytes = b""
    recognized: int = 0
    digest: bytes = b"\x00\x00\x00\x00"

    def pack_payload(self) -> bytes:
        """
        Pack relay cell into 509-byte payload (before encryption).

        Returns:
            509-byte relay cell payload
        """
        # Validate data length
        if len(self.data) > RELAY_DATA_LEN:
            raise ValueError(f"Data too long: {len(self.data)} > {RELAY_DATA_LEN}")

        # Pack header
        header = struct.pack(
            ">BHHH",
            self.relay_command,
            self.recognized,
            self.stream_id,
            len(self.data),
        )
        # Insert digest (4 bytes) between stream_id and length
        # Actually the format is: cmd(1) + recognized(2) + stream_id(2) + digest(4) + length(2)
        header = struct.pack(
            ">BHH4sH",
            self.relay_command,
            self.recognized,
            self.stream_id,
            self.digest,
            len(self.data),
        )

        # Data + padding
        padding_len = RELAY_BODY_LEN - RELAY_HEADER_LEN - len(self.data)
        payload = header + self.data + (b"\x00" * padding_len)

        return payload

    @classmethod
    def unpack_payload(cls, payload: bytes) -> RelayCell:
        """
        Unpack relay cell from 509-byte payload (after decryption).

        Args:
            payload: 509-byte decrypted relay cell payload

        Returns:
            Parsed RelayCell
        """
        if len(payload) < RELAY_HEADER_LEN:
            raise ValueError(f"Payload too short: {len(payload)}")

        # Unpack header
        relay_command, recognized, stream_id, digest, length = struct.unpack(
            ">BHH4sH", payload[:RELAY_HEADER_LEN]
        )

        # Extract data
        data = payload[RELAY_HEADER_LEN : RELAY_HEADER_LEN + length]

        return cls(
            relay_command=RelayCommand(relay_command),
            stream_id=stream_id,
            data=data,
            recognized=recognized,
            digest=digest,
        )


@dataclass
class RelayCrypto:
    """
    Handles encryption/decryption and digest computation for relay cells.

    Each direction (forward/backward) has:
    - AES-128-CTR cipher state (maintains counter across cells)
    - Running digest state (SHA-1 for regular hops, SHA3-256 for HS hops)
    """

    # AES-128-CTR cipher for encryption (forward direction)
    _cipher_forward: Cipher | None = field(default=None, repr=False)
    _encryptor: CipherContext | None = field(default=None, repr=False)

    # AES-128-CTR cipher for decryption (backward direction)
    _cipher_backward: Cipher | None = field(default=None, repr=False)
    _decryptor: CipherContext | None = field(default=None, repr=False)

    # Running digest state objects (forward/backward)
    # These maintain incremental state across all cells
    _digest_forward_state: hashlib._Hash | None = field(default=None, repr=False)
    _digest_backward_state: hashlib._Hash | None = field(default=None, repr=False)

    @classmethod
    def create(
        cls,
        key_forward: bytes,
        key_backward: bytes,
        digest_forward: bytes,
        digest_backward: bytes,
    ) -> RelayCrypto:
        """
        Create RelayCrypto with keys from ntor handshake (for regular hops).

        Uses SHA-1 for running digest (20-byte seeds).

        Args:
            key_forward: 16-byte AES key for forward direction (Kf)
            key_backward: 16-byte AES key for backward direction (Kb)
            digest_forward: 20-byte initial digest seed for forward (Df)
            digest_backward: 20-byte initial digest seed for backward (Db)
        """
        if len(key_forward) != 16:
            raise ValueError("key_forward must be 16 bytes")
        if len(key_backward) != 16:
            raise ValueError("key_backward must be 16 bytes")
        if len(digest_forward) != 20:
            raise ValueError("digest_forward must be 20 bytes")
        if len(digest_backward) != 20:
            raise ValueError("digest_backward must be 20 bytes")

        # Create AES-128-CTR ciphers with zero IV
        # Tor uses counter mode starting from 0
        iv = b"\x00" * 16

        cipher_forward = Cipher(algorithms.AES(key_forward), modes.CTR(iv))
        cipher_backward = Cipher(algorithms.AES(key_backward), modes.CTR(iv))

        # Initialize running SHA-1 digest states
        # The digest is seeded with Df/Db and maintains incremental state
        digest_forward_state = hashlib.sha1()
        digest_forward_state.update(digest_forward)
        digest_backward_state = hashlib.sha1()
        digest_backward_state.update(digest_backward)

        instance = cls()
        instance._cipher_forward = cipher_forward
        instance._cipher_backward = cipher_backward
        instance._encryptor = cipher_forward.encryptor()
        instance._decryptor = cipher_backward.decryptor()
        instance._digest_forward_state = digest_forward_state
        instance._digest_backward_state = digest_backward_state

        return instance

    @classmethod
    def create_hs(
        cls,
        key_forward: bytes,
        key_backward: bytes,
        digest_forward: bytes,
        digest_backward: bytes,
    ) -> RelayCrypto:
        """
        Create RelayCrypto for hidden service hop (from hs-ntor handshake).

        Uses SHA3-256 for running digest (32-byte seeds) and AES-256 for encryption.
        See: https://spec.torproject.org/rend-spec/introduction-protocol.html#NTOR-WITH-EXTRA-DATA
        "instead of using AES-128 and SHA1 for this hop, we use AES-256 and SHA3-256"

        Args:
            key_forward: 32-byte AES-256 key for forward direction (Kf)
            key_backward: 32-byte AES-256 key for backward direction (Kb)
            digest_forward: 32-byte initial digest seed for forward (Df)
            digest_backward: 32-byte initial digest seed for backward (Db)
        """
        if len(key_forward) != 32:
            raise ValueError("key_forward must be 32 bytes for HS (AES-256)")
        if len(key_backward) != 32:
            raise ValueError("key_backward must be 32 bytes for HS (AES-256)")
        if len(digest_forward) != 32:
            raise ValueError("digest_forward must be 32 bytes for HS")
        if len(digest_backward) != 32:
            raise ValueError("digest_backward must be 32 bytes for HS")

        # Create AES-256-CTR ciphers with zero IV
        iv = b"\x00" * 16

        cipher_forward = Cipher(algorithms.AES(key_forward), modes.CTR(iv))
        cipher_backward = Cipher(algorithms.AES(key_backward), modes.CTR(iv))

        # Initialize running SHA3-256 digest states for hidden service hop
        digest_forward_state = hashlib.sha3_256()
        digest_forward_state.update(digest_forward)
        digest_backward_state = hashlib.sha3_256()
        digest_backward_state.update(digest_backward)

        instance = cls()
        instance._cipher_forward = cipher_forward
        instance._cipher_backward = cipher_backward
        instance._encryptor = cipher_forward.encryptor()
        instance._decryptor = cipher_backward.decryptor()
        instance._digest_forward_state = digest_forward_state
        instance._digest_backward_state = digest_backward_state

        return instance

    def encrypt_forward(self, relay_cell: RelayCell) -> bytes:
        """
        Encrypt a relay cell for sending (forward direction).

        1. Pack cell with digest=0
        2. Update running digest state with packed cell
        3. Insert first 4 bytes of digest
        4. Encrypt with AES-CTR

        Args:
            relay_cell: RelayCell to encrypt

        Returns:
            509-byte encrypted payload
        """
        if self._encryptor is None:
            raise RuntimeError("RelayCrypto not initialized")
        if self._digest_forward_state is None:
            raise RuntimeError("Forward digest not initialized")

        # Pack with zero digest first
        relay_cell.digest = b"\x00\x00\x00\x00"
        payload = relay_cell.pack_payload()

        # Update running digest state and get current digest
        # We need to copy() because digest() finalizes the hash
        self._digest_forward_state.update(payload)
        current_digest = self._digest_forward_state.copy().digest()

        # Replace digest field with first 4 bytes of running digest
        # Digest is at offset 5 (cmd=1, recognized=2, stream_id=2)
        payload = payload[:5] + current_digest[:4] + payload[9:]

        # Encrypt
        return self._encryptor.update(payload)

    def decrypt_backward(self, encrypted_payload: bytes) -> RelayCell | None:
        """
        Decrypt a relay cell received (backward direction).

        1. Decrypt with AES-CTR
        2. Check if recognized == 0
        3. Zero digest field, update running digest state
        4. Compare computed digest with received digest
        5. Return cell if valid, None otherwise

        Args:
            encrypted_payload: 509-byte encrypted payload

        Returns:
            RelayCell if valid, None if not for us or digest mismatch
        """
        if self._decryptor is None:
            raise RuntimeError("RelayCrypto not initialized")
        if self._digest_backward_state is None:
            raise RuntimeError("Backward digest not initialized")

        # Decrypt
        payload = self._decryptor.update(encrypted_payload)

        # Check recognized field (bytes 1-2, should be 0)
        recognized = struct.unpack(">H", payload[1:3])[0]
        if recognized != 0:
            # Not recognized - might need more decryption layers
            return None

        # Extract received digest
        received_digest = payload[5:9]

        # Zero digest field and compute expected digest
        zeroed_payload = payload[:5] + b"\x00\x00\x00\x00" + payload[9:]
        self._digest_backward_state.update(zeroed_payload)
        expected_digest = self._digest_backward_state.copy().digest()[:4]

        # Verify digest (constant-time comparison to prevent timing attacks)
        if not hmac.compare_digest(received_digest, expected_digest):
            # Digest mismatch - cell is corrupted or not for us
            return None

        # Parse and return
        return RelayCell.unpack_payload(payload)

    def encrypt_raw(self, payload: bytes) -> bytes:
        """
        Raw AES-CTR encryption (for intermediate hops in multi-hop circuits).

        This is used when adding encryption layers for hops before the exit.
        No digest handling - just raw encryption.

        Args:
            payload: 509-byte payload (already encrypted by inner layers)

        Returns:
            Encrypted payload
        """
        if self._encryptor is None:
            raise RuntimeError("RelayCrypto not initialized")
        return self._encryptor.update(payload)

    def decrypt_raw(self, payload: bytes) -> bytes:
        """
        Raw AES-CTR decryption (for intermediate hops in multi-hop circuits).

        This is used when peeling encryption layers from hops before the exit.
        No digest handling - just raw decryption.

        Args:
            payload: 509-byte encrypted payload

        Returns:
            Decrypted payload
        """
        if self._decryptor is None:
            raise RuntimeError("RelayCrypto not initialized")
        return self._decryptor.update(payload)

    def get_backward_digest(self) -> bytes:
        """
        Get the current backward running digest (first 20 bytes).

        Used for authenticated SENDME v1 - captures the digest state
        at the time when a SENDME-triggering cell is received.

        Returns:
            First 20 bytes of the current running backward digest
        """
        if self._digest_backward_state is None:
            raise RuntimeError("Backward digest not initialized")
        # Copy the state to avoid affecting the running digest
        return self._digest_backward_state.copy().digest()[:20]


def create_begin_payload(address: str, port: int, flags: int = 0) -> bytes:
    """
    Create payload for RELAY_BEGIN cell.

    Args:
        address: Hostname or IP address
        port: Port number (1-65535)
        flags: Optional 4-byte flags

    Returns:
        BEGIN cell payload (ADDRPORT + optional flags)
    """
    # ADDRPORT format: ADDRESS:PORT\0
    addrport = f"{address.lower()}:{port}\x00".encode("ascii")

    if flags:
        return addrport + struct.pack(">I", flags)
    return addrport


def parse_connected_payload(payload: bytes) -> tuple[str, int] | None:
    """
    Parse RELAY_CONNECTED payload.

    Args:
        payload: CONNECTED cell payload

    Returns:
        Tuple of (ip_address, ttl) or None if empty
    """
    if not payload:
        return None

    if len(payload) == 8:
        # IPv4: 4 bytes IP + 4 bytes TTL
        ip_bytes = payload[:4]
        ttl = struct.unpack(">I", payload[4:8])[0]
        ip = ".".join(str(b) for b in ip_bytes)
        return (ip, ttl)

    if len(payload) >= 25 and payload[:4] == b"\x00\x00\x00\x00":
        # IPv6: 4 zero bytes + type(1) + IPv6(16) + TTL(4)
        addr_type = payload[4]
        if addr_type == 6:
            ipv6_bytes = payload[5:21]
            ttl = struct.unpack(">I", payload[21:25])[0]
            # Format IPv6 address
            parts = [f"{ipv6_bytes[i]:02x}{ipv6_bytes[i+1]:02x}" for i in range(0, 16, 2)]
            ip = ":".join(parts)
            return (ip, ttl)

    return None


def create_end_payload(reason: RelayEndReason = RelayEndReason.DONE) -> bytes:
    """
    Create payload for RELAY_END cell.

    Args:
        reason: End reason code

    Returns:
        END cell payload (1 byte reason)
    """
    return bytes([reason])


class LinkSpecifierType(IntEnum):
    """Link specifier types for EXTEND2."""

    TLS_TCP_IPV4 = 0  # IPv4 address + port (6 bytes)
    TLS_TCP_IPV6 = 1  # IPv6 address + port (18 bytes)
    LEGACY_ID = 2  # Legacy identity - SHA1 fingerprint (20 bytes)
    ED25519_ID = 3  # Ed25519 identity key (32 bytes)


@dataclass
class LinkSpecifier:
    """A link specifier for EXTEND2 cell."""

    spec_type: LinkSpecifierType
    data: bytes

    def pack(self) -> bytes:
        """Pack link specifier: LSTYPE (1) + LSLEN (1) + LSPEC (LSLEN)."""
        return struct.pack("BB", self.spec_type, len(self.data)) + self.data

    @classmethod
    def from_ipv4(cls, ip: str, port: int) -> LinkSpecifier:
        """Create IPv4 link specifier."""
        ip_bytes = bytes(int(x) for x in ip.split("."))
        data = ip_bytes + struct.pack(">H", port)
        return cls(spec_type=LinkSpecifierType.TLS_TCP_IPV4, data=data)

    @classmethod
    def from_ipv6(cls, ip: str, port: int) -> LinkSpecifier:
        """Create IPv6 link specifier."""
        ip_bytes = socket.inet_pton(socket.AF_INET6, ip)
        data = ip_bytes + struct.pack(">H", port)
        return cls(spec_type=LinkSpecifierType.TLS_TCP_IPV6, data=data)

    @classmethod
    def from_legacy_id(cls, fingerprint: str) -> LinkSpecifier:
        """Create legacy identity link specifier from hex fingerprint."""
        fp_bytes = bytes.fromhex(fingerprint.replace(" ", "").replace("$", ""))
        return cls(spec_type=LinkSpecifierType.LEGACY_ID, data=fp_bytes)

    @classmethod
    def from_ed25519_id(cls, ed_key: bytes) -> LinkSpecifier:
        """Create Ed25519 identity link specifier."""
        return cls(spec_type=LinkSpecifierType.ED25519_ID, data=ed_key)


def create_extend2_payload(
    link_specifiers: list[LinkSpecifier],
    htype: int,
    hdata: bytes,
) -> bytes:
    """
    Create payload for RELAY_EXTEND2 cell.

    Args:
        link_specifiers: List of link specifiers for the target relay
        htype: Handshake type (0x0002 for ntor)
        hdata: Handshake data (onion skin, 84 bytes for ntor)

    Returns:
        EXTEND2 payload bytes
    """
    # NSPEC (1 byte)
    payload = struct.pack("B", len(link_specifiers))

    # Link specifiers
    for spec in link_specifiers:
        payload += spec.pack()

    # HTYPE (2 bytes) + HLEN (2 bytes) + HDATA
    payload += struct.pack(">HH", htype, len(hdata)) + hdata

    return payload


def parse_extended2_payload(payload: bytes) -> bytes:
    """
    Parse RELAY_EXTENDED2 payload (same format as CREATED2).

    Args:
        payload: EXTENDED2 cell payload

    Returns:
        HDATA (server handshake response)
    """
    # Bounds check: need at least 2 bytes for HLEN
    if len(payload) < 2:
        raise ValueError(f"EXTENDED2 payload too short: {len(payload)} < 2")

    hlen = struct.unpack(">H", payload[0:2])[0]

    # Bounds check: ensure HDATA is complete
    if len(payload) < 2 + hlen:
        raise ValueError(f"EXTENDED2 hdata truncated: need {2 + hlen}, have {len(payload)}")

    return payload[2 : 2 + hlen]


class ResolvedType(IntEnum):
    """Address types in RELAY_RESOLVED response."""

    HOSTNAME = 0x00  # Hostname (DNS order, not NUL-terminated)
    IPV4 = 0x04  # IPv4 address (4 bytes)
    IPV6 = 0x06  # IPv6 address (16 bytes)
    ERROR_TRANSIENT = 0xF0  # Transient error
    ERROR_NONTRANSIENT = 0xF1  # Non-transient error


@dataclass
class ResolvedAnswer:
    """A single answer from RELAY_RESOLVED response."""

    addr_type: ResolvedType
    value: str  # IP address, hostname, or error description
    ttl: int  # Time-to-live in seconds


def create_resolve_payload(hostname: str) -> bytes:
    """
    Create payload for RELAY_RESOLVE cell.

    Args:
        hostname: Hostname to resolve (or in-addr.arpa for reverse lookup)

    Returns:
        RESOLVE cell payload (NUL-terminated hostname)
    """
    return hostname.encode("ascii") + b"\x00"


def parse_resolved_payload(payload: bytes) -> list[ResolvedAnswer]:
    """
    Parse RELAY_RESOLVED payload into a list of answers.

    Each answer has format: type(1) + length(1) + value(variable) + TTL(4)

    Args:
        payload: RESOLVED cell payload

    Returns:
        List of ResolvedAnswer objects
    """
    answers = []
    offset = 0

    while offset < len(payload):
        # Need at least 6 bytes for header (type + length + TTL)
        if offset + 2 > len(payload):
            break

        addr_type = payload[offset]
        length = payload[offset + 1]
        offset += 2

        # Check if we have enough data for value + TTL
        if offset + length + 4 > len(payload):
            break

        value_bytes = payload[offset : offset + length]
        offset += length

        ttl = struct.unpack(">I", payload[offset : offset + 4])[0]
        offset += 4

        # Convert value to string based on type
        try:
            resolved_type = ResolvedType(addr_type)
        except ValueError:
            # Unknown type, skip
            continue

        if resolved_type == ResolvedType.IPV4:
            # 4 bytes -> dotted quad
            if len(value_bytes) == 4:
                value = ".".join(str(b) for b in value_bytes)
            else:
                continue
        elif resolved_type == ResolvedType.IPV6:
            # 16 bytes -> hex with colons
            if len(value_bytes) == 16:
                parts = [f"{value_bytes[i]:02x}{value_bytes[i+1]:02x}" for i in range(0, 16, 2)]
                value = ":".join(parts)
            else:
                continue
        elif resolved_type == ResolvedType.HOSTNAME:
            # DNS order, not NUL-terminated
            value = value_bytes.decode("ascii", errors="replace")
        elif resolved_type in (ResolvedType.ERROR_TRANSIENT, ResolvedType.ERROR_NONTRANSIENT):
            # Error content is typically ignored
            value = value_bytes.decode("ascii", errors="replace") if value_bytes else "error"
        else:
            continue

        answers.append(ResolvedAnswer(addr_type=resolved_type, value=value, ttl=ttl))

    return answers


# =============================================================================
# Hidden Service Rendezvous Helpers
# =============================================================================


class IntroduceAckStatus(IntEnum):
    """Status codes for INTRODUCE_ACK response."""

    SUCCESS = 0x0000
    SERVICE_NOT_RECOGNIZED = 0x0001
    BAD_MESSAGE_FORMAT = 0x0002
    RELAY_FAILED = 0x0003


def create_establish_rendezvous_payload(rendezvous_cookie: bytes) -> bytes:
    """Create payload for RELAY_ESTABLISH_RENDEZVOUS cell.

    Args:
        rendezvous_cookie: 20-byte random cookie

    Returns:
        20-byte payload (just the cookie)
    """
    if len(rendezvous_cookie) != 20:
        raise ValueError("rendezvous_cookie must be 20 bytes")
    return rendezvous_cookie


# Extension type for PoW (Proposal 327)
EXT_FIELD_TYPE_POW = 0x02


def build_introduce1_cell_without_mac(
    auth_key: bytes,
    client_pk: bytes,
    encrypted_data: bytes,
    pow_solution: PowSolution | None = None,
) -> bytes:
    """Build INTRODUCE1 cell payload without the MAC.

    The MAC must be computed over this payload and then appended.

    Format:
        LEGACY_KEY_ID      [20 bytes] - All zeros for v3
        AUTH_KEY_TYPE      [1 byte]   - 0x02 = Ed25519
        AUTH_KEY_LEN       [2 bytes]
        AUTH_KEY           [AUTH_KEY_LEN bytes]
        N_EXTENSIONS       [1 byte]   - 0 or 1 (if PoW)
        [EXT_FIELD_TYPE    [1 byte]   - 0x02 for PoW]
        [EXT_FIELD_LEN     [1 byte]   - 69]
        [EXT_FIELD         [69 bytes] - packed PowSolution]
        ENCRYPTED (partial, no MAC):
            CLIENT_PK      [32 bytes]
            ENCRYPTED_DATA [variable]

    Args:
        auth_key: 32-byte Ed25519 auth key from intro point
        client_pk: 32-byte X25519 ephemeral public key
        encrypted_data: Encrypted introduce data
        pow_solution: Optional PoW solution (Proposal 327)

    Returns:
        INTRODUCE1 cell payload without MAC (caller must compute and append MAC)
    """
    if len(auth_key) != 32:
        raise ValueError("auth_key must be 32 bytes")
    if len(client_pk) != 32:
        raise ValueError("client_pk must be 32 bytes")

    payload = bytearray()

    # LEGACY_KEY_ID [20 bytes] - all zeros for v3
    payload.extend(b"\x00" * 20)

    # AUTH_KEY_TYPE [1 byte] - 0x02 = Ed25519
    payload.append(0x02)

    # AUTH_KEY_LEN [2 bytes]
    payload.extend(struct.pack(">H", len(auth_key)))

    # AUTH_KEY [32 bytes]
    payload.extend(auth_key)

    # N_EXTENSIONS and extensions
    if pow_solution is not None:
        # One extension: PoW
        payload.append(1)  # N_EXTENSIONS

        # EXT_FIELD_TYPE [1 byte]
        payload.append(EXT_FIELD_TYPE_POW)

        # Pack the PoW solution
        pow_data = pow_solution.pack()

        # EXT_FIELD_LEN [1 byte]
        payload.append(len(pow_data))

        # EXT_FIELD [69 bytes]
        payload.extend(pow_data)
    else:
        # No extensions
        payload.append(0)

    # ENCRYPTED section (without MAC)
    payload.extend(client_pk)  # CLIENT_PK [32 bytes]
    payload.extend(encrypted_data)  # ENCRYPTED_DATA

    return bytes(payload)


def parse_introduce_ack(payload: bytes) -> tuple[IntroduceAckStatus, bool]:
    """Parse RELAY_INTRODUCE_ACK payload.

    Format:
        STATUS           [2 bytes]
        N_EXTENSIONS     [1 byte]
        (extensions...)

    Args:
        payload: INTRODUCE_ACK cell payload

    Returns:
        Tuple of (status, success)
    """
    if len(payload) < 2:
        return IntroduceAckStatus.BAD_MESSAGE_FORMAT, False

    status = struct.unpack(">H", payload[:2])[0]

    try:
        status_enum = IntroduceAckStatus(status)
    except ValueError:
        status_enum = IntroduceAckStatus.BAD_MESSAGE_FORMAT

    success = status_enum == IntroduceAckStatus.SUCCESS
    return status_enum, success


def parse_rendezvous2(payload: bytes) -> tuple[bytes, bytes] | None:
    """Parse RELAY_RENDEZVOUS2 payload.

    Format:
        HANDSHAKE_INFO [variable]:
            SERVER_PK  [32 bytes]
            AUTH       [32 bytes]

    Args:
        payload: RENDEZVOUS2 cell payload

    Returns:
        Tuple of (server_pk, auth) or None if invalid
    """
    if len(payload) < 64:
        return None

    server_pk = payload[:32]
    auth = payload[32:64]
    return server_pk, auth


def link_specifiers_from_intro_point(
    link_specs: list[tuple[int, bytes]],
) -> list[LinkSpecifier]:
    """Convert introduction point link specifiers to LinkSpecifier objects.

    Args:
        link_specs: List of (type, data) tuples from IntroductionPoint

    Returns:
        List of LinkSpecifier objects
    """
    result = []
    for spec_type, data in link_specs:
        try:
            ls_type = LinkSpecifierType(spec_type)
            result.append(LinkSpecifier(spec_type=ls_type, data=data))
        except ValueError:
            # Unknown type - create with the raw int value
            # LinkSpecifier.spec_type accepts LinkSpecifierType but we need to handle
            # unknown types, so we create with the known type and override
            result.append(LinkSpecifier(spec_type=LinkSpecifierType.TLS_TCP_IPV4, data=data))
            result[-1].spec_type = spec_type  # type: ignore[assignment]
    return result


# =============================================================================
# Circuit Padding Negotiation
# See: https://spec.torproject.org/padding-spec/circuit-level-padding.html
# =============================================================================


class CircpadCommand(IntEnum):
    """Commands for PADDING_NEGOTIATE/PADDING_NEGOTIATED cells."""

    STOP = 1  # Stop padding on the circuit
    START = 2  # Start padding on the circuit


class CircpadMachineType(IntEnum):
    """Machine types for circuit padding."""

    CIRC_SETUP = 1  # Circuit setup machine (for onion services)


class CircpadResponse(IntEnum):
    """Response codes for PADDING_NEGOTIATED cell."""

    OK = 1  # Padding successfully negotiated
    ERR = 2  # Padding negotiation failed


@dataclass
class PaddingNegotiate:
    """
    PADDING_NEGOTIATE relay cell payload.

    Used to negotiate circuit padding parameters with a relay.

    Format:
        version      [1 byte]  - Must be 0
        command      [1 byte]  - START (2) or STOP (1)
        machine_type [1 byte]  - CIRC_SETUP (1)
        unused       [1 byte]  - Formerly echo_request
        machine_ctr  [4 bytes] - Machine instance counter
    """

    command: CircpadCommand
    machine_type: CircpadMachineType = CircpadMachineType.CIRC_SETUP
    machine_ctr: int = 0
    version: int = 0

    def pack(self) -> bytes:
        """Pack PADDING_NEGOTIATE payload."""
        return struct.pack(
            ">BBBBI",
            self.version,
            self.command,
            self.machine_type,
            0,  # unused
            self.machine_ctr,
        )

    @classmethod
    def unpack(cls, payload: bytes) -> PaddingNegotiate:
        """Unpack PADDING_NEGOTIATE payload."""
        if len(payload) < 8:
            raise ValueError(f"PADDING_NEGOTIATE payload too short: {len(payload)} < 8")

        version, command, machine_type, _, machine_ctr = struct.unpack(">BBBBI", payload[:8])

        return cls(
            version=version,
            command=CircpadCommand(command),
            machine_type=CircpadMachineType(machine_type),
            machine_ctr=machine_ctr,
        )


@dataclass
class PaddingNegotiated:
    """
    PADDING_NEGOTIATED relay cell payload.

    Response to PADDING_NEGOTIATE from the relay.

    Format:
        version      [1 byte]  - Must be 0
        command      [1 byte]  - START (2) or STOP (1)
        response     [1 byte]  - OK (1) or ERR (2)
        machine_type [1 byte]  - CIRC_SETUP (1)
        machine_ctr  [4 bytes] - Machine instance counter
    """

    command: CircpadCommand
    response: CircpadResponse
    machine_type: CircpadMachineType = CircpadMachineType.CIRC_SETUP
    machine_ctr: int = 0
    version: int = 0

    def pack(self) -> bytes:
        """Pack PADDING_NEGOTIATED payload."""
        return struct.pack(
            ">BBBBI",
            self.version,
            self.command,
            self.response,
            self.machine_type,
            self.machine_ctr,
        )

    @classmethod
    def unpack(cls, payload: bytes) -> PaddingNegotiated:
        """Unpack PADDING_NEGOTIATED payload."""
        if len(payload) < 8:
            raise ValueError(f"PADDING_NEGOTIATED payload too short: {len(payload)} < 8")

        version, command, response, machine_type, machine_ctr = struct.unpack(">BBBBI", payload[:8])

        return cls(
            version=version,
            command=CircpadCommand(command),
            response=CircpadResponse(response),
            machine_type=CircpadMachineType(machine_type),
            machine_ctr=machine_ctr,
        )

    @property
    def is_ok(self) -> bool:
        """Check if padding was successfully negotiated."""
        return self.response == CircpadResponse.OK


def create_padding_negotiate_payload(
    command: CircpadCommand,
    machine_type: CircpadMachineType = CircpadMachineType.CIRC_SETUP,
    machine_ctr: int = 0,
) -> bytes:
    """Create payload for RELAY_PADDING_NEGOTIATE cell.

    Args:
        command: STOP or START
        machine_type: Type of padding machine (default: CIRC_SETUP)
        machine_ctr: Machine instance counter (default: 0)

    Returns:
        8-byte PADDING_NEGOTIATE payload
    """
    negotiate = PaddingNegotiate(
        command=command,
        machine_type=machine_type,
        machine_ctr=machine_ctr,
    )
    return negotiate.pack()


def parse_padding_negotiated_payload(payload: bytes) -> PaddingNegotiated:
    """Parse RELAY_PADDING_NEGOTIATED payload.

    Args:
        payload: PADDING_NEGOTIATED cell payload

    Returns:
        PaddingNegotiated object

    Raises:
        ValueError: If payload is too short or invalid
    """
    return PaddingNegotiated.unpack(payload)


# =============================================================================
# SENDME Flow Control
# See: https://spec.torproject.org/tor-spec/flow-control.html
# =============================================================================


@dataclass
class SendmeCell:
    """
    SENDME cell payload for flow control.

    Version 0 (legacy): Empty payload
    Version 1 (authenticated): VERSION(1) + DATA_LEN(2) + DIGEST(20)

    The digest in v1 is the first 20 bytes of the cell digest that
    triggered the SENDME (for authentication).
    """

    version: int = SENDME_VERSION_1
    digest: bytes = b""  # 20 bytes for v1, empty for v0

    def pack(self) -> bytes:
        """Pack SENDME payload."""
        if self.version == SENDME_VERSION_0:
            return b""
        if self.version == SENDME_VERSION_1:
            # VERSION (1 byte) + DATA_LEN (2 bytes) + DIGEST (20 bytes)
            digest_data = self.digest[:20].ljust(20, b"\x00")
            return struct.pack(">BH", self.version, 20) + digest_data
        raise ValueError(f"Unknown SENDME version: {self.version}")

    @classmethod
    def unpack(cls, payload: bytes) -> SendmeCell:
        """Unpack SENDME payload."""
        if not payload:
            # Version 0: empty payload
            return cls(version=SENDME_VERSION_0, digest=b"")

        if len(payload) < 3:
            raise ValueError(f"SENDME payload too short: {len(payload)} < 3")

        version, data_len = struct.unpack(">BH", payload[:3])

        if version == SENDME_VERSION_1:
            if data_len != 20:
                raise ValueError(f"SENDME v1 data_len should be 20, got {data_len}")
            if len(payload) < 3 + data_len:
                raise ValueError(f"SENDME v1 payload truncated: {len(payload)} < {3 + data_len}")
            digest = payload[3 : 3 + data_len]
            return cls(version=version, digest=digest)

        # Unknown version, return as-is
        return cls(version=version, digest=payload[3:])


def create_sendme_payload(version: int = SENDME_VERSION_1, digest: bytes = b"") -> bytes:
    """Create SENDME cell payload.

    Args:
        version: SENDME version (0 for legacy, 1 for authenticated)
        digest: For v1, the 20-byte digest of the triggering cell

    Returns:
        SENDME payload bytes
    """
    return SendmeCell(version=version, digest=digest).pack()


def parse_sendme_payload(payload: bytes) -> SendmeCell:
    """Parse SENDME cell payload.

    Args:
        payload: SENDME cell payload

    Returns:
        SendmeCell object
    """
    return SendmeCell.unpack(payload)
