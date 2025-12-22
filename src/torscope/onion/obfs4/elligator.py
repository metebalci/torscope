"""
Elligator2 encoding for obfs4 pluggable transport.

Elligator2 is a map that allows encoding elliptic curve points as
uniform random strings, making them indistinguishable from random data.

This is essential for obfs4's traffic obfuscation - without it,
Curve25519 public keys would be identifiable.

For Curve25519 (Montgomery form): v² = u³ + Au² + u where A = 486662
The non-square constant: u = 2

Reference: http://elligator.cr.yp.to/elligator-20130828.pdf
obfs4 spec: https://github.com/Yawning/obfs4/blob/master/doc/obfs4-spec.txt
"""

from __future__ import annotations

# Field prime: p = 2^255 - 19
P = 2**255 - 19

# Montgomery curve constant A = 486662
A = 486662

# Non-square in the field (u = 2 for Curve25519)
U = 2

# Precomputed: (p - 1) // 2 for Legendre symbol
P_MINUS_1_HALF = (P - 1) // 2

# Precomputed: (p + 3) // 8 for sqrt
P_PLUS_3_DIV_8 = (P + 3) // 8

# Precomputed: 2^((p-1)/4) = sqrt(-1) mod p
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _legendre(a: int) -> int:
    """Compute Legendre symbol (a/p). Returns 1, -1, or 0."""
    r = pow(a, P_MINUS_1_HALF, P)
    if r == P - 1:
        return -1
    return r


def _sqrt(a: int) -> int | None:
    """
    Compute square root mod p if it exists.

    For p ≡ 5 (mod 8), we use: sqrt(a) = a^((p+3)/8) or sqrt(-1) * a^((p+3)/8)
    """
    if a == 0:
        return 0

    if _legendre(a) != 1:
        return None

    x = pow(a, P_PLUS_3_DIV_8, P)

    if (x * x) % P == a:
        return x

    x = (x * SQRT_M1) % P
    if (x * x) % P == a:
        return x

    return None


def _inv(a: int) -> int:
    """Compute modular inverse using Fermat's little theorem."""
    return pow(a, P - 2, P)


def elligator2_decode(representative: bytes) -> bytes:
    """
    Decode an Elligator2 representative to a Curve25519 public key.

    The Elligator2 direct map: r → u

    Args:
        representative: 32-byte Elligator2 representative

    Returns:
        32-byte Curve25519 public key (x-coordinate)
    """
    if len(representative) != 32:
        raise ValueError("representative must be 32 bytes")

    # Clear high bits and convert to integer
    r_bytes = bytearray(representative)
    r_bytes[31] &= 0x3F
    r = int.from_bytes(bytes(r_bytes), "little") % P

    # Elligator2 direct map: v = -A / (1 + u*r²)
    r_sq = (r * r) % P
    ur_sq = (U * r_sq) % P
    denom = (1 + ur_sq) % P

    if denom == 0:
        v = P - A
    else:
        v = ((P - A) * _inv(denom)) % P

    # e = Legendre(v³ + Av² + v)
    v_sq = (v * v) % P
    v_cu = (v * v_sq) % P
    expr = (v_cu + A * v_sq + v) % P
    e = _legendre(expr)

    # x = e*v - (1-e)*A/2
    if e == 1:
        x = v
    else:
        x = (P - v - A) % P

    return x.to_bytes(32, "little")


def elligator2_encode(public_key: bytes) -> bytes | None:
    """
    Encode a Curve25519 public key using Elligator2.

    The Elligator2 inverse map: u → r
    Not all points are encodable (~50% success rate).

    Args:
        public_key: 32-byte Curve25519 public key

    Returns:
        32-byte representative, or None if not encodable
    """
    if len(public_key) != 32:
        raise ValueError("public_key must be 32 bytes")

    u = int.from_bytes(public_key, "little") % P

    # Not encodable if u = -A or u = 0
    if u in (0, (P - A) % P):
        return None

    # Need -(u+A)/(u*U) to be a quadratic residue
    u_plus_A = (u + A) % P
    inner = ((P - u_plus_A) * _inv((u * U) % P)) % P

    r = _sqrt(inner)
    if r is None:
        return None

    # Choose canonical form (smaller of r or p-r)
    if r > P // 2:
        r = P - r

    r_bytes = r.to_bytes(32, "little")

    # Verify roundtrip
    if elligator2_decode(r_bytes) != public_key:
        r = P - r
        r_bytes = r.to_bytes(32, "little")
        if elligator2_decode(r_bytes) != public_key:
            return None

    return r_bytes


def generate_encodable_keypair() -> tuple[bytes, bytes, bytes]:
    """
    Generate a Curve25519 keypair that is Elligator2-encodable.

    Returns:
        Tuple of (private_key, public_key, representative)
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    while True:
        private_key = X25519PrivateKey.generate()
        private_bytes = private_key.private_bytes_raw()
        public_bytes = private_key.public_key().public_bytes_raw()

        representative = elligator2_encode(public_bytes)
        if representative is not None:
            return private_bytes, public_bytes, representative
