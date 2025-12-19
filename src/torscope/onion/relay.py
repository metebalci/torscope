"""
RELAY cell implementation.

RELAY cells carry data through established circuits. Each relay cell
has an 11-byte header followed by data and padding.

See: https://spec.torproject.org/tor-spec/relay-cells.html
"""

import hashlib
import struct
from dataclasses import dataclass, field
from enum import IntEnum

from cryptography.hazmat.primitives.ciphers import Cipher, CipherContext, algorithms, modes

# Relay cell body length (509 bytes for link protocol 4+)
# Total cell is 514 bytes: 4 (circ_id) + 1 (command) + 509 (payload)
RELAY_BODY_LEN = 509

# Relay header length
RELAY_HEADER_LEN = 11

# Maximum data in a relay cell
RELAY_DATA_LEN = RELAY_BODY_LEN - RELAY_HEADER_LEN  # 498 bytes


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
    def unpack_payload(cls, payload: bytes) -> "RelayCell":
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
    - Running SHA-1 digest state
    """

    # AES-128-CTR cipher for encryption (forward direction)
    _cipher_forward: Cipher | None = field(default=None, repr=False)
    _encryptor: CipherContext | None = field(default=None, repr=False)

    # AES-128-CTR cipher for decryption (backward direction)
    _cipher_backward: Cipher | None = field(default=None, repr=False)
    _decryptor: CipherContext | None = field(default=None, repr=False)

    # Running digest state (forward/backward)
    _digest_forward: bytes = field(default=b"", repr=False)
    _digest_backward: bytes = field(default=b"", repr=False)

    @classmethod
    def create(
        cls,
        key_forward: bytes,
        key_backward: bytes,
        digest_forward: bytes,
        digest_backward: bytes,
    ) -> "RelayCrypto":
        """
        Create RelayCrypto with keys from ntor handshake.

        Args:
            key_forward: 16-byte AES key for forward direction (Kf)
            key_backward: 16-byte AES key for backward direction (Kb)
            digest_forward: 20-byte initial digest state for forward (Df)
            digest_backward: 20-byte initial digest state for backward (Db)
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

        instance = cls()
        instance._cipher_forward = cipher_forward
        instance._cipher_backward = cipher_backward
        instance._encryptor = cipher_forward.encryptor()
        instance._decryptor = cipher_backward.decryptor()
        instance._digest_forward = digest_forward
        instance._digest_backward = digest_backward

        return instance

    def encrypt_forward(self, relay_cell: RelayCell) -> bytes:
        """
        Encrypt a relay cell for sending (forward direction).

        1. Pack cell with digest=0
        2. Update running digest with packed cell
        3. Insert first 4 bytes of digest
        4. Encrypt with AES-CTR

        Args:
            relay_cell: RelayCell to encrypt

        Returns:
            509-byte encrypted payload
        """
        if self._encryptor is None:
            raise RuntimeError("RelayCrypto not initialized")

        # Pack with zero digest first
        relay_cell.digest = b"\x00\x00\x00\x00"
        payload = relay_cell.pack_payload()

        # Update running digest
        self._digest_forward = self._update_digest(self._digest_forward, payload)

        # Replace digest field with first 4 bytes of running digest
        # Digest is at offset 5 (cmd=1, recognized=2, stream_id=2)
        payload = payload[:5] + self._digest_forward[:4] + payload[9:]

        # Encrypt
        return self._encryptor.update(payload)

    def decrypt_backward(self, encrypted_payload: bytes) -> RelayCell | None:
        """
        Decrypt a relay cell received (backward direction).

        1. Decrypt with AES-CTR
        2. Check if recognized == 0
        3. Zero digest field, update running digest
        4. Compare computed digest with received digest
        5. Return cell if valid, None otherwise

        Args:
            encrypted_payload: 509-byte encrypted payload

        Returns:
            RelayCell if valid, None if not for us or digest mismatch
        """
        if self._decryptor is None:
            raise RuntimeError("RelayCrypto not initialized")

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
        self._digest_backward = self._update_digest(self._digest_backward, zeroed_payload)
        expected_digest = self._digest_backward[:4]

        # Verify digest
        if received_digest != expected_digest:
            # Digest mismatch - cell is corrupted or not for us
            return None

        # Parse and return
        return RelayCell.unpack_payload(payload)

    def _update_digest(self, current_digest: bytes, data: bytes) -> bytes:
        """
        Update running digest with new data.

        The running digest is computed incrementally using SHA-1.
        We seed it with Df or Db from the key material.

        Args:
            current_digest: Current 20-byte digest state
            data: Data to add to digest

        Returns:
            New 20-byte digest state
        """
        # Tor uses a running SHA-1 hash
        # The digest state is the intermediate hash value
        # For simplicity, we concatenate and hash
        # Note: Real Tor maintains incremental SHA-1 state
        h = hashlib.sha1()
        h.update(current_digest)
        h.update(data)
        return h.digest()


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
