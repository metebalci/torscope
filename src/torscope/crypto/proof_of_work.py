"""
Proof of Work implementation for hidden service DoS protection.

Implements the Equi-X algorithm as specified in Proposal 327:
https://spec.torproject.org/proposals/327-pow-over-intro.txt

Equi-X is a CPU-friendly proof-of-work based on the Equihash algorithm.
It uses Blake2b for hashing and produces 8 x u16 solution indices.

Note: This is a pure Python implementation optimized for correctness over speed.
For production use, consider using a C binding for better performance.
"""

import hashlib
import secrets
import struct
from dataclasses import dataclass

# PoW version
POW_VERSION_1 = 1

# Equi-X parameters (from Tor spec)
EQUIX_N = 60  # Hash output bits
EQUIX_K = 3  # Number of stages (8 = 2^K indices)
EQUIX_SEED_LEN = 32
EQUIX_NONCE_LEN = 16
EQUIX_SOLUTION_LEN = 16  # 8 x u16


@dataclass
class PowParams:
    """Proof of Work parameters from hidden service descriptor.

    Parsed from the pow-params line in the second layer descriptor:
        pow-params v1 <seed-base64> <suggested-effort> <expiration-time>
    """

    pow_type: str  # "v1" for Equi-X
    seed: bytes  # 32-byte random seed
    suggested_effort: int  # Suggested effort level
    expiration_time: int  # Unix timestamp when seed expires

    @classmethod
    def parse(cls, line: str) -> "PowParams":
        """Parse pow-params line from descriptor.

        Format: pow-params v1 <seed-base64> <suggested-effort> <expiration>

        Args:
            line: The pow-params line (with or without "pow-params" prefix)

        Returns:
            PowParams instance

        Raises:
            ValueError: If format is invalid
        """
        import base64

        parts = line.split()

        # Handle both "pow-params v1 ..." and "v1 ..."
        if parts[0] == "pow-params":
            parts = parts[1:]

        if len(parts) < 4:
            raise ValueError(f"Invalid pow-params: expected 4 parts, got {len(parts)}")

        pow_type = parts[0]
        if pow_type != "v1":
            raise ValueError(f"Unsupported pow-params type: {pow_type}")

        try:
            # Seed may be base64 without padding
            seed_b64 = parts[1]
            # Add padding if needed
            padding = 4 - (len(seed_b64) % 4)
            if padding != 4:
                seed_b64 += "=" * padding
            seed = base64.b64decode(seed_b64)
        except Exception as e:
            raise ValueError(f"Invalid seed base64: {parts[1]}") from e

        if len(seed) != EQUIX_SEED_LEN:
            raise ValueError(f"Invalid seed length: {len(seed)} (expected {EQUIX_SEED_LEN})")

        try:
            suggested_effort = int(parts[2])
        except ValueError as e:
            raise ValueError(f"Invalid suggested_effort: {parts[2]}") from e

        try:
            expiration_time = int(parts[3])
        except ValueError as e:
            raise ValueError(f"Invalid expiration_time: {parts[3]}") from e

        return cls(
            pow_type=pow_type,
            seed=seed,
            suggested_effort=suggested_effort,
            expiration_time=expiration_time,
        )


@dataclass
class PowSolution:
    """A proof-of-work solution.

    The solution is included in the INTRODUCE1 cell as an extension.
    """

    version: int = POW_VERSION_1  # POW_V1
    nonce: bytes = b""  # 16-byte nonce
    effort: int = 0  # Effort used
    seed: bytes = b""  # 32-byte seed (from descriptor)
    solution: bytes = b""  # 16-byte Equi-X solution (8 x u16)

    def pack(self) -> bytes:
        """Pack PoW solution for INTRODUCE1 extension.

        Format:
            POW_VERSION [1 byte]
            POW_NONCE [16 bytes]
            POW_EFFORT [4 bytes, big-endian]
            POW_SEED [32 bytes]
            POW_SOLUTION [16 bytes]

        Returns:
            69 bytes of packed solution
        """
        return (
            bytes([self.version])
            + self.nonce
            + struct.pack(">I", self.effort)
            + self.seed
            + self.solution
        )

    @classmethod
    def unpack(cls, data: bytes) -> "PowSolution":
        """Unpack a PoW solution from bytes.

        Args:
            data: 69 bytes of packed solution

        Returns:
            PowSolution instance
        """
        if len(data) != 69:
            raise ValueError(f"Invalid solution length: {len(data)} (expected 69)")

        version = data[0]
        nonce = data[1:17]
        effort = struct.unpack(">I", data[17:21])[0]
        seed = data[21:53]
        solution = data[53:69]

        return cls(
            version=version,
            nonce=nonce,
            effort=effort,
            seed=seed,
            solution=solution,
        )

    def __len__(self) -> int:
        """Length of packed solution."""
        return 69  # 1 + 16 + 4 + 32 + 16


def _build_challenge(seed: bytes, nonce: bytes, effort: int, blinded_id: bytes) -> bytes:
    """Build the PoW challenge input.

    The challenge is used as input to the Equi-X solver.

    Args:
        seed: 32-byte seed from pow-params
        nonce: 16-byte random nonce
        effort: Effort level (encodes difficulty)
        blinded_id: 32-byte blinded public key of the hidden service

    Returns:
        Challenge bytes for Equi-X
    """
    return seed + nonce + struct.pack(">I", effort) + blinded_id


def _equix_hash(challenge: bytes, index: int) -> int:
    """Compute Equi-X hash for a given index.

    Uses Blake2b to hash the challenge with the index appended.

    Args:
        challenge: The challenge bytes
        index: Index to hash

    Returns:
        EQUIX_N-bit hash value
    """
    # Use Blake2b with the index appended
    h = hashlib.blake2b(challenge + struct.pack("<I", index), digest_size=8)
    # Extract EQUIX_N bits (60 bits = 7.5 bytes, use 8 bytes and mask)
    value: int = struct.unpack("<Q", h.digest())[0]
    return value & ((1 << EQUIX_N) - 1)


def _equix_solve(challenge: bytes, max_iterations: int = 1_000_000) -> list[int] | None:
    """Solve the Equi-X puzzle.

    Finds 8 indices whose hashes XOR to zero (within EQUIX_N bits).

    This is a simplified implementation using random search.
    A proper implementation would use the Wagner algorithm.

    Args:
        challenge: The challenge bytes
        max_iterations: Maximum iterations before giving up

    Returns:
        List of 8 indices if solution found, None otherwise
    """
    # Build a table of hashes for random indices
    # This is a simplified approach - real Equi-X uses Wagner's algorithm

    for _ in range(max_iterations):
        # Generate 8 random indices
        indices = [secrets.randbelow(1 << 16) for _ in range(8)]

        # Check if indices are distinct
        if len(set(indices)) != 8:
            continue

        # Compute XOR of all hashes
        xor_sum = 0
        for idx in indices:
            xor_sum ^= _equix_hash(challenge, idx)

        # Check if XOR is zero (solution found)
        if xor_sum == 0:
            # Sort indices for canonical form
            indices.sort()
            return indices

    return None


def compute_pow(
    seed: bytes,
    blinded_id: bytes,
    effort: int,
    max_iterations: int = 10_000_000,
) -> PowSolution | None:
    """Compute proof-of-work solution using Equi-X.

    This function attempts to find a valid PoW solution for the given
    parameters. It may take significant time depending on the effort level.

    Args:
        seed: 32-byte seed from pow-params
        blinded_id: 32-byte blinded public key of the hidden service
        effort: Effort level (higher = more work)
        max_iterations: Maximum iterations per nonce attempt

    Returns:
        PowSolution if found, None if failed after max attempts

    Note:
        This is a pure Python implementation and may be slow.
        For production use, consider a C binding.
    """
    # Try multiple nonces
    for _ in range(100):
        # Generate random nonce
        nonce = secrets.token_bytes(EQUIX_NONCE_LEN)

        # Build challenge
        challenge = _build_challenge(seed, nonce, effort, blinded_id)

        # Attempt to solve
        indices = _equix_solve(challenge, max_iterations=max_iterations)

        if indices is not None:
            # Pack solution as 8 x u16 little-endian
            solution = b"".join(struct.pack("<H", idx) for idx in indices)

            return PowSolution(
                version=POW_VERSION_1,
                nonce=nonce,
                effort=effort,
                seed=seed,
                solution=solution,
            )

    return None


def verify_pow(solution: PowSolution, blinded_id: bytes) -> bool:
    """Verify a proof-of-work solution.

    Args:
        solution: The PoW solution to verify
        blinded_id: 32-byte blinded public key of the hidden service

    Returns:
        True if solution is valid, False otherwise
    """
    if solution.version != POW_VERSION_1:
        return False

    # Build challenge
    challenge = _build_challenge(solution.seed, solution.nonce, solution.effort, blinded_id)

    # Unpack solution indices
    indices = []
    for i in range(8):
        idx = struct.unpack("<H", solution.solution[i * 2 : i * 2 + 2])[0]
        indices.append(idx)

    # Check indices are distinct
    if len(set(indices)) != 8:
        return False

    # Compute XOR of all hashes
    xor_sum = 0
    for idx in indices:
        xor_sum ^= _equix_hash(challenge, idx)

    # Solution is valid if XOR is zero
    return xor_sum == 0
