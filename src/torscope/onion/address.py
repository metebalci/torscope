"""V3 Onion address parsing and cryptographic operations.

This module handles v3 onion addresses as defined in rend-spec-v3.txt.

V3 onion address format:
    address = base32(pubkey || checksum || version) + ".onion"
    - pubkey: 32-byte Ed25519 public key
    - checksum: 2-byte checksum
    - version: 1-byte version (0x03 for v3)
    - Total: 35 bytes → 56 base32 characters
"""

from __future__ import annotations

import base64
import struct
import time
from dataclasses import dataclass

from torscope.crypto import sha3_256

# Tor hidden service protocol constants
HS_VERSION_3 = 3
HS_TIME_PERIOD_LENGTH = 1440  # minutes (24 hours)
HS_TIME_PERIOD_LENGTH_SECONDS = HS_TIME_PERIOD_LENGTH * 60


@dataclass
class OnionAddress:
    """Parsed v3 onion address.

    Attributes:
        address: The full onion address (with or without .onion suffix)
        public_key: 32-byte Ed25519 public key
        checksum: 2-byte checksum
        version: Protocol version (should be 3)
    """

    address: str
    public_key: bytes
    checksum: bytes
    version: int

    @classmethod
    def parse(cls, address: str) -> OnionAddress:
        """Parse and validate a v3 onion address.

        Args:
            address: The onion address (with or without .onion suffix)

        Returns:
            Parsed OnionAddress object

        Raises:
            ValueError: If the address is invalid
        """
        # Normalize address
        addr = address.lower().strip()
        if addr.endswith(".onion"):
            addr = addr[:-6]

        # V3 addresses are 56 base32 characters
        if len(addr) != 56:
            raise ValueError(
                f"Invalid v3 onion address length: expected 56 characters, got {len(addr)}"
            )

        # Decode base32 (Tor uses RFC 4648 base32 without padding)
        try:
            # Add padding for standard base32 decoder
            padded = addr.upper() + "=" * ((8 - len(addr) % 8) % 8)
            decoded = base64.b32decode(padded)
        except Exception as e:
            raise ValueError(f"Invalid base32 encoding: {e}") from e

        if len(decoded) != 35:
            raise ValueError(f"Invalid decoded length: expected 35 bytes, got {len(decoded)}")

        # Extract components
        public_key = decoded[:32]
        checksum = decoded[32:34]
        version = decoded[34]

        # Validate version
        if version != HS_VERSION_3:
            raise ValueError(f"Unsupported onion address version: {version} (expected 3)")

        # Validate checksum
        expected_checksum = _compute_checksum(public_key, version)
        if checksum != expected_checksum:
            raise ValueError(
                f"Checksum mismatch: expected {expected_checksum.hex()}, got {checksum.hex()}"
            )

        return cls(
            address=addr + ".onion",
            public_key=public_key,
            checksum=checksum,
            version=version,
        )

    def compute_blinded_key(
        self,
        time_period: int,
        period_length: int = HS_TIME_PERIOD_LENGTH,
    ) -> bytes:
        """Derive the blinded public key for a given time period.

        This blinded key is used for:
        - The descriptor URL path: /tor/hs/3/<base64(blinded_key)>
        - Computing the hs_index (position on the hashring)
        - Verifying the descriptor certificate

        Implements the key blinding from rend-spec-v3 Appendix A:
            h = SHA3-256(BLIND_STRING | A | s | B | N)
            A' = h * A

        Note: The SRV is NOT used directly in blinded key derivation.
        The SRV is used for HSDir index computation (position on ring).

        Args:
            time_period: The time period number
            period_length: Time period length in minutes (default: 1440 = 24h)

        Returns:
            32-byte blinded public key
        """
        # Ed25519 basepoint as string (from Tor hs_common.c)
        ed25519_basepoint = (
            b"(15112221349535400772501151409588531511"
            b"454012693041857206046113283949847762202, "
            b"463168356949264781694283940034751631413"
            b"07993866256225615783033603165251855960)"
        )

        # BLIND_STRING = "Derive temporary signing key" + byte(0)
        blind_string = b"Derive temporary signing key\x00"

        # N = "key-blind" | INT_8(period_num) | INT_8(period_length)
        n_value = b"key-blind" + struct.pack(">QQ", time_period, period_length)

        # s = empty for public services (no client authorization)
        s = b""

        # secret_input = BLIND_STRING | A | s | B | N
        secret_input = blind_string + self.public_key + s + ed25519_basepoint + n_value

        # h = SHA3-256(secret_input)
        h = sha3_256(secret_input)

        # Derive blinded key: A' = h * A
        blinded_key = _derive_blinded_key(self.public_key, h)

        return blinded_key

    def compute_subcredential(self, time_period: int) -> bytes:
        """Compute the subcredential for descriptor decryption.

        The subcredential is used to decrypt the hidden service descriptor.

        Args:
            time_period: The time period number

        Returns:
            32-byte subcredential
        """
        # SUBCREDENTIAL = H("subcredential" || credential || blinded_public_key)
        # credential = H("credential" || public_key)
        credential = sha3_256(b"credential" + self.public_key)

        # Get blinded key for the specified time period
        blinded_key = self.compute_blinded_key(time_period)

        subcredential = sha3_256(b"subcredential" + credential + blinded_key)
        return subcredential

    def __str__(self) -> str:
        return self.address


def _compute_checksum(public_key: bytes, version: int) -> bytes:
    """Compute the onion address checksum.

    checksum = H(".onion checksum" || pubkey || version)[:2]

    Args:
        public_key: 32-byte Ed25519 public key
        version: Protocol version byte

    Returns:
        2-byte checksum
    """
    data = b".onion checksum" + public_key + bytes([version])
    full_hash = sha3_256(data)
    return full_hash[:2]


def _derive_blinded_key(public_key: bytes, blinding_factor: bytes) -> bytes:
    """Derive blinded public key using Ed25519 scalar multiplication.

    This implements the Ed25519 blinding as specified in rend-spec-v3 Appendix A:
    1. Clamp the blinding factor to a valid Ed25519 scalar
    2. Multiply the public key point by the scalar: A' = h * A

    Args:
        public_key: 32-byte Ed25519 public key (A)
        blinding_factor: 32-byte blinding factor from SHA3-256 (h)

    Returns:
        32-byte blinded public key (A')
    """
    from nacl.bindings import crypto_scalarmult_ed25519_noclamp

    # Clamp the blinding factor to valid Ed25519 scalar per spec:
    #   h[0] &= 248    // Clear lower 3 bits
    #   h[31] &= 63    // Clear upper 2 bits
    #   h[31] |= 64    // Set bit 6
    scalar = bytearray(blinding_factor[:32])
    scalar[0] &= 248
    scalar[31] &= 63
    scalar[31] |= 64

    # Perform Ed25519 scalar multiplication: A' = h * A
    # Using noclamp because we've already clamped the scalar
    blinded = crypto_scalarmult_ed25519_noclamp(bytes(scalar), public_key)

    return blinded


def get_current_time_period(
    reference_time: float | None = None,
    period_length: int = HS_TIME_PERIOD_LENGTH,
) -> int:
    """Get the current time period number.

    The time period is calculated as:
        period_num = (minutes_since_epoch - ROTATION_OFFSET) / period_length

    Args:
        reference_time: Unix timestamp (default: current time)
        period_length: Period length in minutes (default: 1440 = 24h)

    Returns:
        Current time period number
    """
    if reference_time is None:
        reference_time = time.time()

    # Time period rotation offset (matches Tor's implementation)
    # This is 12 hours from the start of the SRV protocol
    rotation_offset = 12 * 60  # 12 hours in minutes

    minutes_since_epoch = int(reference_time / 60)
    period_num = (minutes_since_epoch - rotation_offset) // period_length

    return period_num


def get_time_period_info(
    reference_time: float | None = None,
    period_length: int = HS_TIME_PERIOD_LENGTH,
) -> dict:
    """Get detailed time period information.

    Args:
        reference_time: Unix timestamp (default: current time)
        period_length: Period length in minutes (default: 1440 = 24h)

    Returns:
        Dictionary with time period details
    """
    if reference_time is None:
        reference_time = time.time()

    rotation_offset = 12 * 60
    minutes_since_epoch = int(reference_time / 60)
    period_num = (minutes_since_epoch - rotation_offset) // period_length

    # Calculate period start and end times
    period_start_minutes = period_num * period_length + rotation_offset
    period_start_time = period_start_minutes * 60
    period_end_time = (period_start_minutes + period_length) * 60

    # Time remaining in current period
    remaining_seconds = period_end_time - reference_time

    return {
        "period_num": period_num,
        "period_length": period_length,
        "period_start": period_start_time,
        "period_end": period_end_time,
        "remaining_seconds": remaining_seconds,
        "remaining_minutes": remaining_seconds / 60,
    }
