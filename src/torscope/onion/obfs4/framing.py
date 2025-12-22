"""
obfs4 frame encryption and decryption.

After the handshake, all data is encrypted using NaCl SecretBox
(XSalsa20-Poly1305) with length obfuscation using SipHash.

Frame format:
- Obfuscated length (2 bytes): XOR with SipHash output
- Encrypted frame: SecretBox(type || length || payload || padding)

Reference: https://github.com/Yawning/obfs4/blob/master/doc/obfs4-spec.txt
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import NamedTuple

from nacl.secret import SecretBox
from siphash import SipHash_2_4  # type: ignore[import-untyped]

# Frame type constants
TYPE_PAYLOAD = 0
TYPE_PRNG_SEED = 1

# Frame limits
MAX_FRAME_PAYLOAD_LENGTH = 1448
MIN_FRAME_LENGTH = 1 + 2 + 16  # type + length + SecretBox overhead
MAX_FRAME_LENGTH = MIN_FRAME_LENGTH + MAX_FRAME_PAYLOAD_LENGTH + 255  # max padding

# SecretBox constants
SECRETBOX_KEY_LENGTH = 32
SECRETBOX_NONCE_LENGTH = 24
SECRETBOX_OVERHEAD = 16  # Poly1305 tag

# Key layout (72 bytes per direction)
# offset 0-31: SecretBox key (32 bytes)
# offset 32-47: SipHash key (16 bytes)
# offset 48-63: Nonce prefix (16 bytes)
# offset 64-71: OFB IV for length obfuscation (8 bytes)


class FrameKeys(NamedTuple):
    """Keys for one direction of framing."""

    secret_key: bytes  # 32 bytes - SecretBox key
    sip_key: bytes  # 16 bytes - SipHash key
    nonce_prefix: bytes  # 16 bytes - Prefix for nonce
    ofb_iv: bytes  # 8 bytes - OFB IV for length


@dataclass
class Obfs4Framing:
    """
    obfs4 frame encryption and decryption.

    Handles the symmetric encryption layer after the handshake.
    Uses SecretBox (XSalsa20-Poly1305) for encryption and
    SipHash-2-4 in OFB mode for length obfuscation.
    """

    encrypt_keys: FrameKeys
    decrypt_keys: FrameKeys

    # Counters for nonce generation
    _encrypt_counter: int = 0
    _decrypt_counter: int = 0

    # OFB state for length obfuscation
    _encrypt_ofb: bytes = b""
    _decrypt_ofb: bytes = b""

    @classmethod
    def from_key_material(cls, key_material: bytes, is_client: bool = True) -> Obfs4Framing:
        """
        Create framing instance from handshake key material.

        Args:
            key_material: 144 bytes from handshake
            is_client: True for client, False for server

        The first 72 bytes are for client→server, the next 72 for server→client.
        """
        if len(key_material) != 144:
            raise ValueError(f"Expected 144 bytes, got {len(key_material)}")

        # Parse key material
        def parse_keys(data: bytes) -> FrameKeys:
            return FrameKeys(
                secret_key=data[0:32],
                sip_key=data[32:48],
                nonce_prefix=data[48:64],
                ofb_iv=data[64:72],
            )

        client_keys = parse_keys(key_material[0:72])
        server_keys = parse_keys(key_material[72:144])

        if is_client:
            return cls(encrypt_keys=client_keys, decrypt_keys=server_keys)
        return cls(encrypt_keys=server_keys, decrypt_keys=client_keys)

    def _get_siphash(self, key: bytes, data: bytes) -> bytes:
        """Compute SipHash-2-4 of data."""
        hasher = SipHash_2_4(key)
        hasher.update(data)
        result: bytes = hasher.digest()
        return result

    def _get_encrypt_nonce(self) -> bytes:
        """Generate nonce for encryption."""
        # nonce = prefix (16 bytes) || counter (8 bytes, little-endian)
        counter_bytes = self._encrypt_counter.to_bytes(8, "little")
        self._encrypt_counter += 1
        return self.encrypt_keys.nonce_prefix + counter_bytes

    def get_decrypt_nonce(self) -> bytes:
        """Generate nonce for decryption."""
        counter_bytes = self._decrypt_counter.to_bytes(8, "little")
        self._decrypt_counter += 1
        return self.decrypt_keys.nonce_prefix + counter_bytes

    def _obfuscate_length(self, length: int, encrypt: bool = True) -> bytes:
        """
        Obfuscate frame length using SipHash-OFB.

        This makes frame lengths indistinguishable from random.
        """
        if encrypt:
            keys = self.encrypt_keys
            if not self._encrypt_ofb:
                self._encrypt_ofb = keys.ofb_iv
            ofb = self._encrypt_ofb
        else:
            keys = self.decrypt_keys
            if not self._decrypt_ofb:
                self._decrypt_ofb = keys.ofb_iv
            ofb = self._decrypt_ofb

        # Generate OFB keystream using SipHash
        keystream = self._get_siphash(keys.sip_key, ofb)

        # Update OFB state
        if encrypt:
            self._encrypt_ofb = keystream
        else:
            self._decrypt_ofb = keystream

        # XOR length with first 2 bytes of keystream
        length_bytes = length.to_bytes(2, "big")
        obfuscated = bytes([length_bytes[i] ^ keystream[i] for i in range(2)])

        return obfuscated

    def deobfuscate_length(self, obfuscated: bytes) -> int:
        """Deobfuscate frame length."""
        keys = self.decrypt_keys

        if not self._decrypt_ofb:
            self._decrypt_ofb = keys.ofb_iv
        ofb = self._decrypt_ofb

        # Generate keystream
        keystream = self._get_siphash(keys.sip_key, ofb)

        # Update OFB state
        self._decrypt_ofb = keystream

        # XOR to recover length
        length_bytes = bytes([obfuscated[i] ^ keystream[i] for i in range(2)])
        return int.from_bytes(length_bytes, "big")

    def encrypt_frame(
        self,
        payload: bytes,
        frame_type: int = TYPE_PAYLOAD,
        pad_length: int = 0,
    ) -> bytes:
        """
        Encrypt a frame for transmission.

        Args:
            payload: Data to encrypt (max 1448 bytes)
            frame_type: Frame type (TYPE_PAYLOAD or TYPE_PRNG_SEED)
            pad_length: Amount of padding to add (0-255)

        Returns:
            Encrypted frame with obfuscated length prefix
        """
        if len(payload) > MAX_FRAME_PAYLOAD_LENGTH:
            raise ValueError(f"Payload too large: {len(payload)} > {MAX_FRAME_PAYLOAD_LENGTH}")

        if pad_length > 255:
            raise ValueError(f"Padding too large: {pad_length} > 255")

        # Build plaintext: type (1) || length (2) || payload || padding
        length = len(payload)
        plaintext = bytes([frame_type]) + struct.pack(">H", length) + payload
        if pad_length > 0:
            plaintext += os.urandom(pad_length)

        # Encrypt with SecretBox
        nonce = self._get_encrypt_nonce()
        box = SecretBox(self.encrypt_keys.secret_key)
        ciphertext = box.encrypt(plaintext, nonce).ciphertext

        # Total frame length (including overhead)
        frame_length = len(ciphertext)

        # Obfuscate length
        obfuscated_length = self._obfuscate_length(frame_length)

        return obfuscated_length + ciphertext

    def decrypt_frame(self, data: bytes) -> tuple[int, bytes, int]:
        """
        Decrypt a received frame.

        Args:
            data: Received data (may contain partial frames)

        Returns:
            Tuple of (frame_type, payload, bytes_consumed)

        Raises:
            ValueError: If frame is invalid or incomplete
        """
        if len(data) < 2:
            raise ValueError("Need at least 2 bytes for length")

        # Deobfuscate length
        frame_length = self.deobfuscate_length(data[:2])

        if frame_length < MIN_FRAME_LENGTH - 2:
            raise ValueError(f"Invalid frame length: {frame_length}")

        total_length = 2 + frame_length  # length field + frame

        if len(data) < total_length:
            raise ValueError(f"Incomplete frame: have {len(data)}, need {total_length}")

        # Decrypt
        nonce = self.get_decrypt_nonce()
        box = SecretBox(self.decrypt_keys.secret_key)

        try:
            plaintext = box.decrypt(data[2:total_length], nonce)
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}") from e

        if len(plaintext) < 3:
            raise ValueError("Plaintext too short")

        # Parse frame: type (1) || length (2) || payload || padding
        frame_type = plaintext[0]
        payload_length = struct.unpack(">H", plaintext[1:3])[0]

        if payload_length > len(plaintext) - 3:
            raise ValueError("Invalid payload length in frame")

        payload = plaintext[3 : 3 + payload_length]

        return frame_type, payload, total_length


class FrameReader:
    """
    Buffered frame reader for streaming decryption.

    Handles partial frames and provides an iterator interface.
    Caches the deobfuscated length to avoid advancing OFB state on partial reads.
    """

    def __init__(self, framing: Obfs4Framing):
        self.framing = framing
        self._buffer = b""
        self._pending_length: int | None = None

    def feed(self, data: bytes) -> None:
        """Add received data to the buffer."""
        self._buffer += data

    def read_frame(self) -> tuple[int, bytes] | None:
        """
        Try to read a complete frame from the buffer.

        Returns:
            Tuple of (frame_type, payload) or None if incomplete
        """
        if len(self._buffer) < 2:
            return None

        # Deobfuscate length only once (cache it)
        if self._pending_length is None:
            self._pending_length = self.framing.deobfuscate_length(self._buffer[:2])

        total_length = 2 + self._pending_length

        # Check if we have enough data
        if len(self._buffer) < total_length:
            return None

        # We have a complete frame - decrypt it
        nonce = self.framing.get_decrypt_nonce()
        box = SecretBox(self.framing.decrypt_keys.secret_key)

        try:
            plaintext = box.decrypt(self._buffer[2:total_length], nonce)
        except Exception as e:
            # Reset state on error
            self._pending_length = None
            raise ValueError(f"Decryption failed: {e}") from e

        if len(plaintext) < 3:
            self._pending_length = None
            raise ValueError("Plaintext too short")

        # Parse frame
        frame_type = plaintext[0]
        payload_length = struct.unpack(">H", plaintext[1:3])[0]

        if payload_length > len(plaintext) - 3:
            self._pending_length = None
            raise ValueError("Invalid payload length")

        payload = plaintext[3 : 3 + payload_length]

        # Consume the frame from buffer and reset pending length
        self._buffer = self._buffer[total_length:]
        self._pending_length = None

        return frame_type, payload

    def read_all_frames(self) -> list[tuple[int, bytes]]:
        """Read all complete frames from the buffer."""
        frames = []
        while True:
            frame = self.read_frame()
            if frame is None:
                break
            frames.append(frame)
        return frames
