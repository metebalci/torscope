"""
Tor cell format implementation.

Cells are the basic unit of communication in the Tor protocol.
Fixed-length cells are 512 bytes (514 for link protocol 4+).
Variable-length cells have a 2-byte length field.
"""

import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import ClassVar


class CellCommand(IntEnum):
    """Cell command types."""

    # Fixed-length cells (command < 128, except VERSIONS)
    PADDING = 0
    CREATE = 1
    CREATED = 2
    RELAY = 3
    DESTROY = 4
    CREATE_FAST = 5
    CREATED_FAST = 6
    NETINFO = 8
    RELAY_EARLY = 9
    CREATE2 = 10
    CREATED2 = 11
    PADDING_NEGOTIATE = 12

    # Variable-length cells (command >= 128, plus VERSIONS)
    VERSIONS = 7  # Special: variable-length despite being < 128
    VPADDING = 128
    CERTS = 129
    AUTH_CHALLENGE = 130
    AUTHENTICATE = 131
    AUTHORIZE = 132

    @classmethod
    def is_variable_length(cls, command: int) -> bool:
        """Check if a command uses variable-length cells."""
        return command == cls.VERSIONS or command >= 128


# Cell sizes (tor-spec section 3)
# https://spec.torproject.org/tor-spec/cell-packet-format.html
#
# Fixed-length cell format:
#   Link v3:  CircID(2) + Command(1) + Payload(509) = 512 bytes
#   Link v4+: CircID(4) + Command(1) + Payload(509) = 514 bytes
#
# Variable-length cell format:
#   Link v3:  CircID(2) + Command(1) + Length(2) + Payload(variable)
#   Link v4+: CircID(4) + Command(1) + Length(2) + Payload(variable)
CELL_LEN_V3 = 512  # Cell length for link protocol <= 3
CELL_LEN_V4 = 514  # Cell length for link protocol >= 4
CIRCID_LEN_V3 = 2  # CircID length for link protocol <= 3
CIRCID_LEN_V4 = 4  # CircID length for link protocol >= 4


@dataclass
class Cell:
    """Base class for Tor cells."""

    circ_id: int
    command: CellCommand
    payload: bytes = b""

    # Class variables for cell format
    HEADER_FORMAT_V3: ClassVar[str] = ">HB"  # CircID (2 bytes) + Command (1 byte)
    HEADER_FORMAT_V4: ClassVar[str] = ">IB"  # CircID (4 bytes) + Command (1 byte)
    HEADER_LEN_V3: ClassVar[int] = 3
    HEADER_LEN_V4: ClassVar[int] = 5

    def pack(self, link_protocol: int = 4) -> bytes:
        """
        Pack cell into bytes for transmission.

        Args:
            link_protocol: Link protocol version (affects CircID size)

        Returns:
            Packed cell bytes
        """
        if link_protocol >= 4:
            header = struct.pack(self.HEADER_FORMAT_V4, self.circ_id, self.command)
            cell_len = CELL_LEN_V4
            header_len = self.HEADER_LEN_V4
        else:
            header = struct.pack(self.HEADER_FORMAT_V3, self.circ_id, self.command)
            cell_len = CELL_LEN_V3
            header_len = self.HEADER_LEN_V3

        if CellCommand.is_variable_length(self.command):
            # Variable-length cell: header + length (2 bytes) + payload
            length = struct.pack(">H", len(self.payload))
            return header + length + self.payload

        # Fixed-length cell: header + payload padded to cell_len
        body_len = cell_len - header_len
        payload = self.payload[:body_len].ljust(body_len, b"\x00")
        return header + payload

    @classmethod
    def unpack(cls, data: bytes, link_protocol: int = 4) -> "Cell":
        """
        Unpack cell from bytes.

        Args:
            data: Raw cell bytes
            link_protocol: Link protocol version

        Returns:
            Parsed Cell object
        """
        if link_protocol >= 4:
            circ_id, command = struct.unpack(cls.HEADER_FORMAT_V4, data[:5])
            header_len = cls.HEADER_LEN_V4
        else:
            circ_id, command = struct.unpack(cls.HEADER_FORMAT_V3, data[:3])
            header_len = cls.HEADER_LEN_V3

        if CellCommand.is_variable_length(command):
            # Variable-length cell
            length = struct.unpack(">H", data[header_len : header_len + 2])[0]
            payload = data[header_len + 2 : header_len + 2 + length]
        else:
            # Fixed-length cell
            payload = data[header_len:]

        return cls(circ_id=circ_id, command=CellCommand(command), payload=payload)


@dataclass
class VersionsCell:
    """
    VERSIONS cell for link protocol negotiation.

    Sent by both sides immediately after TLS handshake.
    Contains list of supported link protocol versions.
    """

    versions: list[int] = field(default_factory=lambda: [4, 5])

    def pack(self) -> bytes:
        """Pack VERSIONS cell. Always uses 2-byte CircID."""
        # VERSIONS cell always uses CircID=0 and 2-byte CircID
        payload = b"".join(struct.pack(">H", v) for v in self.versions)
        header = struct.pack(">HBH", 0, CellCommand.VERSIONS, len(payload))
        return header + payload

    @classmethod
    def unpack(cls, data: bytes) -> "VersionsCell":
        """Unpack VERSIONS cell."""
        # Skip header (CircID=2 bytes, Command=1 byte, Length=2 bytes)
        payload = data[5:]
        versions = []
        for i in range(0, len(payload), 2):
            if i + 2 <= len(payload):
                versions.append(struct.unpack(">H", payload[i : i + 2])[0])
        return cls(versions=versions)


@dataclass
class NetInfoCell:
    """
    NETINFO cell for exchanging time and address information.

    Sent at the end of the link handshake by both sides.
    """

    timestamp: int = 0  # Unix timestamp
    other_address: tuple[int, bytes] = (4, b"\x00\x00\x00\x00")  # (type, address)
    my_addresses: list[tuple[int, bytes]] = field(default_factory=list)

    # Address types
    ADDR_TYPE_IPV4 = 4
    ADDR_TYPE_IPV6 = 6

    def pack(self, link_protocol: int = 4) -> bytes:
        """Pack NETINFO cell."""
        # Timestamp (4 bytes)
        payload = struct.pack(">I", self.timestamp or int(time.time()))

        # Other OR's address
        addr_type, addr_data = self.other_address
        payload += struct.pack("BB", addr_type, len(addr_data)) + addr_data

        # My addresses
        payload += struct.pack("B", len(self.my_addresses))
        for addr_type, addr_data in self.my_addresses:
            payload += struct.pack("BB", addr_type, len(addr_data)) + addr_data

        # Create cell
        cell = Cell(circ_id=0, command=CellCommand.NETINFO, payload=payload)
        return cell.pack(link_protocol)

    @classmethod
    def unpack(cls, data: bytes, link_protocol: int = 4) -> "NetInfoCell":
        """Unpack NETINFO cell."""
        cell = Cell.unpack(data, link_protocol)
        payload = cell.payload
        offset = 0

        # Timestamp
        timestamp = struct.unpack(">I", payload[offset : offset + 4])[0]
        offset += 4

        # Other OR's address
        addr_type = payload[offset]
        addr_len = payload[offset + 1]
        addr_data = payload[offset + 2 : offset + 2 + addr_len]
        other_address = (addr_type, addr_data)
        offset += 2 + addr_len

        # My addresses
        num_addrs = payload[offset]
        offset += 1
        my_addresses = []
        for _ in range(num_addrs):
            addr_type = payload[offset]
            addr_len = payload[offset + 1]
            addr_data = payload[offset + 2 : offset + 2 + addr_len]
            my_addresses.append((addr_type, addr_data))
            offset += 2 + addr_len

        return cls(
            timestamp=timestamp,
            other_address=other_address,
            my_addresses=my_addresses,
        )


class CertType(IntEnum):
    """Certificate types for CERTS cell."""

    RSA_LINK = 1  # RSA link key certificate
    RSA_IDENTITY = 2  # RSA identity certificate
    RSA_AUTHENTICATE = 3  # RSA AUTHENTICATE certificate
    ED25519_SIGNING = 4  # Ed25519 signing key
    ED25519_LINK = 5  # Ed25519 link certificate (TLS)
    ED25519_AUTHENTICATE = 6  # Ed25519 AUTHENTICATE certificate
    RSA_ED25519_CROSS = 7  # RSA->Ed25519 cross-certificate


@dataclass
class CertsCell:
    """
    CERTS cell containing certificates for authentication.

    Sent by responder (and optionally initiator) during link handshake.
    """

    certificates: list[tuple[int, bytes]] = field(default_factory=list)  # (type, cert_data)

    def pack(self, link_protocol: int = 4) -> bytes:
        """Pack CERTS cell."""
        # Number of certificates
        payload = struct.pack("B", len(self.certificates))

        # Each certificate: type (1 byte) + length (2 bytes) + data
        for cert_type, cert_data in self.certificates:
            payload += struct.pack(">BH", cert_type, len(cert_data)) + cert_data

        # Create variable-length cell
        if link_protocol >= 4:
            header = struct.pack(">IBH", 0, CellCommand.CERTS, len(payload))
        else:
            header = struct.pack(">HBH", 0, CellCommand.CERTS, len(payload))

        return header + payload

    @classmethod
    def unpack(cls, data: bytes, link_protocol: int = 4) -> "CertsCell":
        """Unpack CERTS cell."""
        # Parse header
        if link_protocol >= 4:
            header_len = 5 + 2  # CircID(4) + Command(1) + Length(2)
        else:
            header_len = 3 + 2  # CircID(2) + Command(1) + Length(2)

        payload = data[header_len:]
        offset = 0

        # Bounds check: need at least 1 byte for num_certs
        if len(payload) < 1:
            raise ValueError("CERTS payload too short: missing num_certs")

        # Number of certificates
        num_certs = payload[offset]
        offset += 1

        certificates = []
        for i in range(num_certs):
            # Bounds check: need at least 3 bytes for cert_type(1) + cert_len(2)
            if offset + 3 > len(payload):
                raise ValueError(
                    f"CERTS cell truncated at certificate {i}: need header at offset {offset}"
                )

            cert_type = payload[offset]
            cert_len = struct.unpack(">H", payload[offset + 1 : offset + 3])[0]

            # Bounds check: ensure cert_data is complete
            if offset + 3 + cert_len > len(payload):
                available = len(payload) - offset - 3
                raise ValueError(f"CERTS truncated: cert {i} needs {cert_len}B, have {available}B")

            cert_data = payload[offset + 3 : offset + 3 + cert_len]
            certificates.append((cert_type, cert_data))
            offset += 3 + cert_len

        return cls(certificates=certificates)


@dataclass
class AuthChallengeCell:
    """
    AUTH_CHALLENGE cell sent by responder.

    Contains a random challenge that the initiator must sign
    if it wants to authenticate.
    """

    challenge: bytes = b""  # 32 random bytes
    methods: list[int] = field(default_factory=list)  # Authentication methods

    # Authentication methods
    AUTH_RSA_SHA256_TLSSECRET = 1
    AUTH_ED25519_SHA256_RFC5705 = 3

    def pack(self, link_protocol: int = 4) -> bytes:
        """Pack AUTH_CHALLENGE cell."""
        # Challenge (32 bytes) + number of methods (2 bytes) + methods (2 bytes each)
        payload = self.challenge[:32].ljust(32, b"\x00")
        payload += struct.pack(">H", len(self.methods))
        for method in self.methods:
            payload += struct.pack(">H", method)

        # Create variable-length cell
        if link_protocol >= 4:
            header = struct.pack(">IBH", 0, CellCommand.AUTH_CHALLENGE, len(payload))
        else:
            header = struct.pack(">HBH", 0, CellCommand.AUTH_CHALLENGE, len(payload))

        return header + payload

    @classmethod
    def unpack(cls, data: bytes, link_protocol: int = 4) -> "AuthChallengeCell":
        """Unpack AUTH_CHALLENGE cell."""
        # Parse header
        if link_protocol >= 4:
            header_len = 5 + 2  # CircID(4) + Command(1) + Length(2)
        else:
            header_len = 3 + 2  # CircID(2) + Command(1) + Length(2)

        payload = data[header_len:]

        # Challenge (32 bytes)
        challenge = payload[:32]

        # Number of methods and methods
        num_methods = struct.unpack(">H", payload[32:34])[0]
        methods = []
        for i in range(num_methods):
            method = struct.unpack(">H", payload[34 + i * 2 : 36 + i * 2])[0]
            methods.append(method)

        return cls(challenge=challenge, methods=methods)


# Handshake types for CREATE2
HTYPE_TAP = 0x0000  # Obsolete
HTYPE_NTOR = 0x0002  # ntor (current)
HTYPE_NTOR_V3 = 0x0003  # ntor-v3


@dataclass
class Create2Cell:
    """
    CREATE2 cell for circuit creation.

    Used to create a circuit with a specified handshake type.
    """

    circ_id: int
    htype: int  # Handshake type (HTYPE_NTOR = 0x0002)
    hdata: bytes  # Handshake data (84 bytes for ntor)

    def pack(self, link_protocol: int = 4) -> bytes:
        """Pack CREATE2 cell."""
        # Payload: HTYPE (2 bytes) + HLEN (2 bytes) + HDATA
        payload = struct.pack(">HH", self.htype, len(self.hdata)) + self.hdata

        # Create fixed-length cell
        cell = Cell(circ_id=self.circ_id, command=CellCommand.CREATE2, payload=payload)
        return cell.pack(link_protocol)

    @classmethod
    def unpack(cls, data: bytes, link_protocol: int = 4) -> "Create2Cell":
        """Unpack CREATE2 cell."""
        cell = Cell.unpack(data, link_protocol)
        payload = cell.payload

        # Bounds check: need at least 4 bytes for HTYPE(2) + HLEN(2)
        if len(payload) < 4:
            raise ValueError(f"CREATE2 payload too short: {len(payload)} < 4")

        htype = struct.unpack(">H", payload[0:2])[0]
        hlen = struct.unpack(">H", payload[2:4])[0]

        # Bounds check: ensure HDATA is complete
        if len(payload) < 4 + hlen:
            raise ValueError(f"CREATE2 hdata truncated: need {4 + hlen}, have {len(payload)}")

        hdata = payload[4 : 4 + hlen]

        return cls(circ_id=cell.circ_id, htype=htype, hdata=hdata)


@dataclass
class Created2Cell:
    """
    CREATED2 cell - response to CREATE2.

    Contains server's handshake response.
    """

    circ_id: int
    hdata: bytes  # Server handshake data (64 bytes for ntor: Y + AUTH)

    def pack(self, link_protocol: int = 4) -> bytes:
        """Pack CREATED2 cell."""
        # Payload: HLEN (2 bytes) + HDATA
        payload = struct.pack(">H", len(self.hdata)) + self.hdata

        # Create fixed-length cell
        cell = Cell(circ_id=self.circ_id, command=CellCommand.CREATED2, payload=payload)
        return cell.pack(link_protocol)

    @classmethod
    def unpack(cls, data: bytes, link_protocol: int = 4) -> "Created2Cell":
        """Unpack CREATED2 cell."""
        cell = Cell.unpack(data, link_protocol)
        payload = cell.payload

        # Bounds check: need at least 2 bytes for HLEN
        if len(payload) < 2:
            raise ValueError(f"CREATED2 payload too short: {len(payload)} < 2")

        hlen = struct.unpack(">H", payload[0:2])[0]

        # Bounds check: ensure HDATA is complete
        if len(payload) < 2 + hlen:
            raise ValueError(f"CREATED2 hdata truncated: need {2 + hlen}, have {len(payload)}")

        hdata = payload[2 : 2 + hlen]

        return cls(circ_id=cell.circ_id, hdata=hdata)


# SHA1 output length (for CREATE_FAST key material)
SHA1_LEN = 20
# AES-128 key length
KEY_LEN = 16


@dataclass
class CreateFastCell:
    """
    CREATE_FAST cell for one-hop circuit creation.

    Uses a simpler key exchange that doesn't require public key operations.
    Only suitable for one-hop circuits where the client has already
    established the relay's identity via TLS.

    Payload: 20 random bytes (X)
    """

    circ_id: int
    x: bytes  # 20 random bytes

    def pack(self, link_protocol: int = 4) -> bytes:
        """Pack CREATE_FAST cell."""
        if len(self.x) != SHA1_LEN:
            raise ValueError(f"x must be {SHA1_LEN} bytes")

        cell = Cell(circ_id=self.circ_id, command=CellCommand.CREATE_FAST, payload=self.x)
        return cell.pack(link_protocol)

    @classmethod
    def unpack(cls, data: bytes, link_protocol: int = 4) -> "CreateFastCell":
        """Unpack CREATE_FAST cell."""
        cell = Cell.unpack(data, link_protocol)
        x = cell.payload[:SHA1_LEN]
        return cls(circ_id=cell.circ_id, x=x)


@dataclass
class CreatedFastCell:
    """
    CREATED_FAST cell - response to CREATE_FAST.

    Contains server's key material and a hash for verification.

    Payload: 20 bytes (Y) + 20 bytes (KH - derivative key hash)
    """

    circ_id: int
    y: bytes  # 20 random bytes from server
    kh: bytes  # 20-byte derivative key hash

    def pack(self, link_protocol: int = 4) -> bytes:
        """Pack CREATED_FAST cell."""
        if len(self.y) != SHA1_LEN:
            raise ValueError(f"y must be {SHA1_LEN} bytes")
        if len(self.kh) != SHA1_LEN:
            raise ValueError(f"kh must be {SHA1_LEN} bytes")

        payload = self.y + self.kh
        cell = Cell(circ_id=self.circ_id, command=CellCommand.CREATED_FAST, payload=payload)
        return cell.pack(link_protocol)

    @classmethod
    def unpack(cls, data: bytes, link_protocol: int = 4) -> "CreatedFastCell":
        """Unpack CREATED_FAST cell."""
        cell = Cell.unpack(data, link_protocol)
        payload = cell.payload

        if len(payload) < SHA1_LEN * 2:
            raise ValueError(f"CREATED_FAST payload too short: {len(payload)} < {SHA1_LEN * 2}")

        y = payload[:SHA1_LEN]
        kh = payload[SHA1_LEN : SHA1_LEN * 2]

        return cls(circ_id=cell.circ_id, y=y, kh=kh)


@dataclass
class DestroyCell:
    """
    DESTROY cell - tear down a circuit.

    Sent when a circuit should be closed.
    """

    circ_id: int
    reason: int = 0  # Destroy reason code

    # Destroy reason codes
    REASON_NONE = 0
    REASON_PROTOCOL = 1
    REASON_INTERNAL = 2
    REASON_REQUESTED = 3
    REASON_HIBERNATING = 4
    REASON_RESOURCELIMIT = 5
    REASON_CONNECTFAILED = 6
    REASON_OR_IDENTITY = 7
    REASON_CHANNEL_CLOSED = 8
    REASON_FINISHED = 9
    REASON_TIMEOUT = 10
    REASON_DESTROYED = 11
    REASON_NOSUCHSERVICE = 12

    def pack(self, link_protocol: int = 4) -> bytes:
        """Pack DESTROY cell."""
        # Payload: just the reason byte
        payload = bytes([self.reason])

        cell = Cell(circ_id=self.circ_id, command=CellCommand.DESTROY, payload=payload)
        return cell.pack(link_protocol)

    @classmethod
    def unpack(cls, data: bytes, link_protocol: int = 4) -> "DestroyCell":
        """Unpack DESTROY cell."""
        cell = Cell.unpack(data, link_protocol)
        reason = cell.payload[0] if cell.payload else 0
        return cls(circ_id=cell.circ_id, reason=reason)


# =============================================================================
# KDF-TOR Key Derivation Function (for CREATE_FAST and legacy TAP handshake)
# =============================================================================


def kdf_tor(k0: bytes, key_len: int) -> bytes:
    """
    KDF-TOR key derivation function.

    Generates a keystream using iterative SHA1:
        K = SHA1(K0 | [00]) | SHA1(K0 | [01]) | SHA1(K0 | [02]) | ...

    This KDF is obsolete for new handshakes but required for CREATE_FAST.

    See: https://spec.torproject.org/tor-spec/setting-circuit-keys.html#kdf-tor

    Args:
        k0: Base key material (for CREATE_FAST: X | Y, 40 bytes)
        key_len: Number of bytes to generate (max 5120)

    Returns:
        Derived key material

    Raises:
        ValueError: If key_len > 5120
    """
    import hashlib

    max_len = SHA1_LEN * 256  # 5120 bytes
    if key_len > max_len:
        raise ValueError(f"KDF-TOR cannot generate more than {max_len} bytes")

    result = b""
    counter = 0

    while len(result) < key_len:
        # K = K0 | counter (1 byte)
        h = hashlib.sha1(k0 + bytes([counter]))
        result += h.digest()
        counter += 1

    return result[:key_len]


@dataclass
class FastCircuitKeys:
    """
    Circuit keys derived from CREATE_FAST handshake.

    The KDF-TOR output is partitioned as:
        KH: 20 bytes - derivative key hash (for verification)
        Df: 20 bytes - forward digest seed
        Db: 20 bytes - backward digest seed
        Kf: 16 bytes - forward AES key
        Kb: 16 bytes - backward AES key
    """

    kh: bytes  # Derivative key hash (20 bytes)
    digest_forward: bytes  # Forward digest seed (20 bytes)
    digest_backward: bytes  # Backward digest seed (20 bytes)
    key_forward: bytes  # Forward AES-128 key (16 bytes)
    key_backward: bytes  # Backward AES-128 key (16 bytes)

    @classmethod
    def from_key_material(cls, x: bytes, y: bytes) -> "FastCircuitKeys":
        """
        Derive circuit keys from CREATE_FAST key exchange.

        Args:
            x: Client's 20 random bytes
            y: Server's 20 random bytes

        Returns:
            FastCircuitKeys with all derived keys
        """
        # K0 = X | Y
        k0 = x + y

        # Need: KH(20) + Df(20) + Db(20) + Kf(16) + Kb(16) = 92 bytes
        total_len = SHA1_LEN * 3 + KEY_LEN * 2  # 92 bytes
        derived = kdf_tor(k0, total_len)

        offset = 0
        kh = derived[offset : offset + SHA1_LEN]
        offset += SHA1_LEN
        df = derived[offset : offset + SHA1_LEN]
        offset += SHA1_LEN
        db = derived[offset : offset + SHA1_LEN]
        offset += SHA1_LEN
        kf = derived[offset : offset + KEY_LEN]
        offset += KEY_LEN
        kb = derived[offset : offset + KEY_LEN]

        return cls(
            kh=kh,
            digest_forward=df,
            digest_backward=db,
            key_forward=kf,
            key_backward=kb,
        )

    def verify(self, received_kh: bytes) -> bool:
        """
        Verify the derivative key hash matches what server sent.

        Args:
            received_kh: KH value from CREATED_FAST cell

        Returns:
            True if hashes match, False otherwise
        """
        import hmac

        return hmac.compare_digest(self.kh, received_kh)
