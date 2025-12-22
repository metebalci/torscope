"""
CLI helper functions for torscope.

These functions extract common patterns from the CLI to reduce code duplication
and improve maintainability.
"""

from __future__ import annotations

import sys
from typing import IO, TYPE_CHECKING

if TYPE_CHECKING:
    from torscope.directory.hs_descriptor import HSDescriptor, IntroductionPoint
    from torscope.directory.models import ConsensusDocument, RouterStatusEntry


def find_router(consensus: ConsensusDocument, query: str) -> RouterStatusEntry | None:
    """
    Find router by fingerprint or nickname.

    Args:
        consensus: Network consensus document
        query: Fingerprint prefix or nickname (case-insensitive)

    Returns:
        Router entry if found, None otherwise
    """
    query_upper = query.strip().upper()
    for r in consensus.routers:
        if r.fingerprint.startswith(query_upper):
            return r
        if r.nickname.upper() == query_upper:
            return r
    return None


def resolve_router_or_fail(
    consensus: ConsensusDocument,
    query: str,
    role: str = "Router",
) -> RouterStatusEntry | None:
    """
    Find router by query, printing error message if not found.

    Args:
        consensus: Network consensus document
        query: Fingerprint prefix or nickname
        role: Role name for error message (e.g., "Guard", "Exit")

    Returns:
        Router entry if found, None otherwise (with error printed to stderr)
    """
    router = find_router(consensus, query)
    if router is None:
        print(f"{role} router not found: {query}", file=sys.stderr)
    return router


def parse_address_port(addr_port: str) -> tuple[str, int]:
    """
    Parse address:port string, handling IPv6 bracket notation.

    Examples:
        example.com:80 -> ("example.com", 80)
        [::1]:8080 -> ("::1", 8080)
        192.168.1.1:443 -> ("192.168.1.1", 443)

    Args:
        addr_port: Address and port in format "host:port" or "[ipv6]:port"

    Returns:
        Tuple of (address, port)

    Raises:
        ValueError: If the format is invalid or port is out of range
    """
    # Handle IPv6 bracket notation
    if addr_port.startswith("["):
        # IPv6 format: [address]:port
        bracket_end = addr_port.find("]")
        if bracket_end == -1:
            raise ValueError(f"Invalid IPv6 address format (missing ]): {addr_port}")
        if bracket_end + 1 >= len(addr_port) or addr_port[bracket_end + 1] != ":":
            raise ValueError(f"Invalid format (expected ]:port): {addr_port}")
        address = addr_port[1:bracket_end]
        port_str = addr_port[bracket_end + 2 :]
    else:
        # Regular format: address:port
        parts = addr_port.rsplit(":", 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid address:port format: {addr_port}")
        address, port_str = parts

    # Parse and validate port
    try:
        port = int(port_str)
    except ValueError as e:
        raise ValueError(f"Invalid port number: {port_str}") from e

    if port < 1 or port > 65535:
        raise ValueError(f"Port out of range (1-65535): {port}")

    return address, port


def print_descriptor_info(descriptor: HSDescriptor, file: IO[str] = sys.stdout) -> None:
    """
    Print hidden service descriptor information.

    Args:
        descriptor: Parsed HS descriptor
        file: Output file (default: stdout)
    """
    print("\nDescriptor Info:", file=file)
    print(f"  Version: {descriptor.outer.version}", file=file)
    print(f"  Lifetime: {descriptor.outer.descriptor_lifetime} minutes", file=file)
    print(f"  Revision: {descriptor.outer.revision_counter}", file=file)
    print(f"  Signing cert: {len(descriptor.outer.signing_key_cert)} bytes", file=file)
    print(f"  Superencrypted: {len(descriptor.outer.superencrypted_blob)} bytes", file=file)
    print(f"  Signature: {len(descriptor.outer.signature)} bytes", file=file)


def print_introduction_points(
    intro_points: list[IntroductionPoint],
    file: IO[str] = sys.stdout,
) -> None:
    """
    Print introduction points information.

    Args:
        intro_points: List of introduction points
        file: Output file (default: stdout)
    """
    print(f"\nIntroduction Points ({len(intro_points)}):", file=file)
    for i, ip in enumerate(intro_points):
        ip_addr = ip.ip_address or "unknown"
        port = ip.port or 0
        fp = ip.fingerprint or "unknown"
        print(f"  [{i+1}] {ip_addr}:{port} (fp: {fp[:16]}...)", file=file)
        if ip.onion_key_ntor:
            print(f"      onion-key: {len(ip.onion_key_ntor)} bytes", file=file)
        if ip.enc_key:
            print(f"      enc-key: {len(ip.enc_key)} bytes", file=file)


def print_decryption_error(error: str | None, file: IO[str] = sys.stderr) -> None:
    """
    Print decryption error with hints for common issues.

    Args:
        error: Error message (or None)
        file: Output file (default: stderr)
    """
    error = error or "unknown error"
    print(f"\n[Decryption failed: {error}]", file=file)

    if "authorization required" in error.lower():
        print(
            "Hint: Use --auth-key-file to provide client authorization.",
            file=file,
        )
    elif "not authorized" in error.lower():
        print(
            "Hint: The provided key is not in the service's authorized client list.",
            file=file,
        )


def fetch_hs_descriptor_latest(
    consensus: ConsensusDocument,
    hsdirs: list[RouterStatusEntry],
    blinded_key: bytes,
    timeout: float,
    verbose: bool = False,
) -> tuple[str, RouterStatusEntry] | None:
    """
    Fetch HS descriptor from all HSDirs and return the one with highest revision.

    This is useful when HSDirs have stale cached descriptors and you want to
    find the most recent one.

    Args:
        consensus: Network consensus
        hsdirs: List of HSDir routers to query
        blinded_key: Blinded public key for the hidden service
        timeout: Timeout for each fetch attempt
        verbose: If True, print progress

    Returns:
        Tuple of (descriptor_text, hsdir_used) with highest revision, or None if all fail
    """
    from torscope.directory.hs_descriptor import HSDescriptorOuter, fetch_hs_descriptor

    results: list[tuple[str, RouterStatusEntry, int]] = []

    for hsdir in hsdirs[:6]:
        if verbose:
            print(f"  Querying {hsdir.nickname}...", file=sys.stderr)
        try:
            result = fetch_hs_descriptor(
                consensus=consensus,
                hsdir=hsdir,
                blinded_key=blinded_key,
                timeout=timeout,
                verbose=False,
            )
            if result:
                descriptor_text, hsdir_used = result
                # Parse to get revision counter
                outer = HSDescriptorOuter.parse(descriptor_text)
                revision = outer.revision_counter
                results.append((descriptor_text, hsdir_used, revision))
                if verbose:
                    print(f"    Revision: {revision}", file=sys.stderr)
        except Exception:  # pylint: disable=broad-exception-caught
            if verbose:
                print("    Failed", file=sys.stderr)

    if not results:
        return None

    # Sort by revision (highest first) and return the best one
    results.sort(key=lambda x: x[2], reverse=True)
    best = results[0]

    if verbose:
        print(f"  Using descriptor from {best[1].nickname} (revision {best[2]})", file=sys.stderr)

    return (best[0], best[1])
