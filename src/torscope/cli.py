"""
CLI interface for torscope.

Provides command-line tools for exploring the Tor network.
"""

import argparse
import os
import sys
import traceback
from collections.abc import Callable

import httpx

from torscope import __version__, output
from torscope.cache import (
    cleanup_stale_microdescriptors,
    clear_cache,
    load_consensus,
    save_consensus,
)
from torscope.directory.authority import get_authorities
from torscope.directory.certificates import KeyCertificateParser
from torscope.directory.client import DirectoryClient
from torscope.directory.consensus import ConsensusParser
from torscope.directory.descriptor import ServerDescriptorParser
from torscope.directory.extra_info import ExtraInfoParser
from torscope.directory.fallback import get_fallbacks
from torscope.directory.hs_descriptor import fetch_hs_descriptor, parse_hs_descriptor
from torscope.directory.hsdir import HSDirectoryRing
from torscope.directory.models import ConsensusDocument, RouterStatusEntry
from torscope.microdesc import get_ntor_key
from torscope.onion.address import OnionAddress, get_current_time_period, get_time_period_info
from torscope.onion.circuit import Circuit
from torscope.onion.connection import RelayConnection
from torscope.onion.rendezvous import RendezvousError, rendezvous_connect
from torscope.path import PathSelector

# Default timeout for network operations (can be overridden with TORSCOPE_TIMEOUT env var)
DEFAULT_TIMEOUT = 30.0


def get_timeout() -> float:
    """Get timeout from TORSCOPE_TIMEOUT env var or use default."""
    env_timeout = os.environ.get("TORSCOPE_TIMEOUT")
    if env_timeout:
        try:
            return float(env_timeout)
        except ValueError:
            print(f"Warning: Invalid TORSCOPE_TIMEOUT value: {env_timeout}", file=sys.stderr)
    return DEFAULT_TIMEOUT


def verify_consensus_signatures(consensus: ConsensusDocument) -> tuple[int, int]:
    """
    Verify consensus signatures against authority key certificates.

    Supports both SHA1 (full/ns consensus) and SHA256 (microdesc consensus)
    signature verification.

    Args:
        consensus: ConsensusDocument to verify

    Returns:
        Tuple of (verified_count, total_signatures)
    """
    try:
        # Fetch authority key certificates
        client = DirectoryClient()
        cert_content, _ = client.fetch_key_certificates()
        certificates = KeyCertificateParser.parse(cert_content)

        # Verify signatures
        verified = consensus.verify_signatures(certificates)
        return verified, len(consensus.signatures)
    except Exception:  # pylint: disable=broad-exception-caught
        return 0, len(consensus.signatures)


def get_consensus(no_cache: bool = False) -> ConsensusDocument:
    """
    Get consensus from cache or fetch from network.

    Always verifies consensus signatures against authority key certificates.

    Args:
        no_cache: If True, bypass cache and always fetch

    Returns:
        ConsensusDocument

    Raises:
        Exception: If fetch fails
    """
    output.explain("Loading network consensus (list of all Tor relays)")

    # Try cache first (unless disabled)
    if not no_cache:
        output.verbose("Checking local cache for consensus")
        cached = load_consensus()
        if cached is not None:
            consensus, meta = cached
            source = meta["source"]
            source_type = meta["source_type"]
            msg = f"Using network consensus ({consensus.total_routers:,} routers) "
            msg += f"from {source} ({source_type})"
            print(msg, file=sys.stderr)

            # Always verify signatures
            output.explain("Verifying consensus signatures from directory authorities")
            verified, total = verify_consensus_signatures(consensus)
            print(f"Verified {verified}/{total} consensus signatures", file=sys.stderr)
            output.verbose(f"Signature verification: {verified}/{total} valid")

            return consensus

        # Check if there's an expired consensus
        expired = load_consensus(allow_expired=True)
        if expired is not None:
            _, meta = expired
            print(
                f"Cached consensus from {meta['source']} ({meta['source_type']}) expired",
                file=sys.stderr,
            )

    # Fetch from network
    output.explain("Fetching consensus from directory authority")
    client = DirectoryClient()
    content, used_authority = client.fetch_consensus(None, "microdesc")
    output.verbose(f"Fetched consensus from {used_authority.nickname}")
    consensus = ConsensusParser.parse(content, used_authority.nickname)
    output.debug(f"Consensus size: {len(content)} bytes, {consensus.total_routers} routers")
    msg = f"Fetched network consensus ({consensus.total_routers:,} routers) "
    msg += f"from {used_authority.nickname} (authority)"
    print(msg, file=sys.stderr)

    # Always verify signatures
    verified, total = verify_consensus_signatures(consensus)
    print(f"Verified {verified}/{total} consensus signatures", file=sys.stderr)

    # Save consensus to cache
    save_consensus(content, used_authority.nickname, "authority")

    # Clean up stale microdescriptors not in the new consensus
    removed = cleanup_stale_microdescriptors(consensus)
    if removed > 0:
        print(f"Cleaned up {removed} stale microdescriptor(s) from cache", file=sys.stderr)

    return consensus


def cmd_version(args: argparse.Namespace) -> int:  # pylint: disable=unused-argument
    """Display the torscope version."""
    print(__version__)
    return 0


def cmd_clear(args: argparse.Namespace) -> int:  # pylint: disable=unused-argument
    """Clear the cached consensus."""
    clear_cache()
    print("Cache cleared.")
    return 0


def cmd_authorities(args: argparse.Namespace) -> int:  # pylint: disable=unused-argument
    """List all directory authorities."""
    output.explain("Loading hardcoded list of Tor directory authorities")
    authorities = get_authorities()
    output.verbose(f"Found {len(authorities)} directory authorities")
    print("Directory Authorities:\n")
    for i, auth in enumerate(authorities, 1):
        print(f"  [{i}] {auth.nickname}")
        print(f"      Address: {auth.address}")
        print(f"      Identity: {auth.v3ident}")
        if auth.ipv6_address:
            print(f"      IPv6: {auth.ipv6_address}")
        print()
    return 0


def cmd_fallbacks(args: argparse.Namespace) -> int:  # pylint: disable=unused-argument
    """List fallback directories."""
    output.explain("Loading hardcoded list of fallback directory relays")
    fallbacks = get_fallbacks()
    output.verbose(f"Found {len(fallbacks)} fallback directories")
    print(f"Fallback Directories ({len(fallbacks)} total):\n")
    for i, fb in enumerate(fallbacks, 1):
        name = fb.nickname or "unnamed"
        print(f"  [{i:3}] {name}")
        print(f"        Address: {fb.address}")
        print(f"        Fingerprint: {fb.fingerprint}")
        if fb.ipv6_address:
            print(f"        IPv6: {fb.ipv6_address}")
        print()
    return 0


def cmd_routers(args: argparse.Namespace) -> int:
    """List routers from network consensus."""
    try:
        output.explain("Listing routers from network consensus")
        consensus = get_consensus()

        # List available flags if requested
        if args.list_flags:
            output.verbose("Collecting all router flags")
            all_flags: set[str] = set()
            for router in consensus.routers:
                all_flags.update(router.flags)
            print("Available flags:")
            for flag in sorted(all_flags):
                count = sum(1 for r in consensus.routers if flag in r.flags)
                print(f"  {flag:<15} ({count:,} routers)")
            return 0

        # Filter routers
        routers = consensus.routers
        if args.flags:
            filter_flags = [f.strip() for f in args.flags.split(",")]
            output.verbose(f"Filtering routers by flags: {filter_flags}")
            routers = [r for r in routers if all(r.has_flag(flag) for flag in filter_flags)]
            output.verbose(f"Found {len(routers)} routers matching flags")

        # Display header
        print(f"\nRouters ({len(routers):,} total):\n")
        print(f"{'Nickname':<20} {'Fingerprint':<11} {'Flags'}")
        print("-" * 70)

        # Display routers
        for router in routers:
            nickname = (
                router.nickname[:17] + "..." if len(router.nickname) > 20 else router.nickname
            )
            fp = router.short_fingerprint
            flags = ",".join(router.flags)
            print(f"{nickname:<20} {fp:<11} {flags}")

        return 0

    # pylint: disable-next=broad-exception-caught
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_router(args: argparse.Namespace) -> int:
    """Show details for a specific router."""
    try:
        output.explain("Looking up router details from consensus")
        consensus = get_consensus()

        # Find router by fingerprint or nickname
        query = args.query.upper()
        output.verbose(f"Searching for router: {args.query}")
        router = None

        for r in consensus.routers:
            # Match by fingerprint (full or partial)
            if r.fingerprint.startswith(query):
                router = r
                break
            # Match by nickname (case-insensitive)
            if r.nickname.upper() == query:
                router = r
                break

        if router is None:
            print(f"Router not found: {args.query}", file=sys.stderr)
            return 1

        output.verbose(f"Found router: {router.nickname} ({router.fingerprint[:8]}...)")

        # Display consensus info
        print(f"\nRouter: {router.nickname}")
        print("=" * 70)
        print(f"  Fingerprint:  {router.fingerprint}")
        print(f"  Address:      {router.ip}:{router.orport}")
        if router.dirport:
            print(f"  DirPort:      {router.dirport}")
        if router.ipv6_addresses:
            for addr in router.ipv6_addresses:
                print(f"  IPv6:         {addr}")
        print(f"  Published:    {router.published} UTC")
        print(f"  Flags:        {', '.join(router.flags)}")
        if router.version:
            print(f"  Version:      {router.version}")
        if router.bandwidth:
            bw_mbps = router.bandwidth / 1_000_000
            print(f"  Bandwidth:    {bw_mbps:.2f} MB/s")

        # Fetch full descriptor for additional details
        output.explain("Fetching full server descriptor from directory")
        client = DirectoryClient()
        print("\nFetching full descriptor...", file=sys.stderr)
        content, source = client.fetch_server_descriptors([router.fingerprint])
        output.verbose(f"Fetched descriptor from {source.nickname}")
        output.debug(f"Descriptor size: {len(content)} bytes")
        descriptors = ServerDescriptorParser.parse(content)

        if descriptors:
            desc = descriptors[0]

            print("\n  Descriptor Details:")
            print("  " + "-" * 40)

            if desc.platform:
                print(f"  Platform:       {desc.platform}")

            print("  Bandwidth:")
            print(f"    Average:      {desc.bandwidth_avg / 1_000_000:.2f} MB/s")
            print(f"    Burst:        {desc.bandwidth_burst / 1_000_000:.2f} MB/s")
            print(f"    Observed:     {desc.bandwidth_observed / 1_000_000:.2f} MB/s")

            if desc.uptime is not None:
                days = desc.uptime_days
                print(f"  Uptime:         {days:.1f} days ({desc.uptime:,} seconds)")

            if desc.contact:
                print(f"  Contact:        {desc.contact}")

            if desc.family:
                print(f"  Family:         {len(desc.family)} members")
                for member in desc.family[:5]:
                    print(f"                  {member}")
                if len(desc.family) > 5:
                    print(f"                  ... and {len(desc.family) - 5} more")

            if desc.exit_policy:
                print(f"\n  Exit Policy ({len(desc.exit_policy)} rules):")
                for rule in desc.exit_policy[:10]:
                    print(f"    {rule}")
                if len(desc.exit_policy) > 10:
                    print(f"    ... and {len(desc.exit_policy) - 10} more rules")

            # Flags
            flags = []
            if desc.hibernating:
                flags.append("hibernating")
            if desc.caches_extra_info:
                flags.append("caches-extra-info")
            if desc.tunnelled_dir_server:
                flags.append("tunnelled-dir-server")
            if flags:
                print(f"\n  Descriptor Flags: {', '.join(flags)}")

        return 0

    # pylint: disable-next=broad-exception-caught
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_extra_info(args: argparse.Namespace) -> int:
    """Show extra-info statistics for a router."""
    try:
        output.explain("Looking up extra-info descriptor for router")
        consensus = get_consensus()

        # Find router by fingerprint or nickname
        query = args.query.upper()
        output.verbose(f"Searching for router: {args.query}")
        router = None

        for r in consensus.routers:
            if r.fingerprint.startswith(query):
                router = r
                break
            if r.nickname.upper() == query:
                router = r
                break

        if router is None:
            print(f"Router not found: {args.query}", file=sys.stderr)
            return 1

        output.verbose(f"Found router: {router.nickname}")

        # Fetch extra-info
        output.explain("Fetching extra-info descriptor from directory")
        client = DirectoryClient()
        print(f"Fetching extra-info for {router.nickname}...", file=sys.stderr)
        extra_content, source = client.fetch_extra_info([router.fingerprint])
        output.verbose(f"Fetched extra-info from {source.nickname}")
        output.debug(f"Extra-info size: {len(extra_content)} bytes")
        extra_infos = ExtraInfoParser.parse(extra_content)

        if not extra_infos:
            print(f"No extra-info available for {router.nickname}", file=sys.stderr)
            return 1

        extra = extra_infos[0]

        # Display header
        print(f"\nExtra-Info: {router.nickname}")
        print("=" * 70)
        print(f"  Fingerprint:  {router.fingerprint}")
        print(f"  Published:    {extra.published} UTC")

        # Bandwidth history
        if extra.write_history or extra.read_history:
            print("\n  Bandwidth History:")
            print("  " + "-" * 40)
            if extra.write_history:
                avg = extra.write_history.average_bytes_per_second / 1_000_000
                total = extra.write_history.total_bytes / 1_000_000_000
                print(f"  Write:  {avg:.2f} MB/s avg, {total:.2f} GB total")
            if extra.read_history:
                avg = extra.read_history.average_bytes_per_second / 1_000_000
                total = extra.read_history.total_bytes / 1_000_000_000
                print(f"  Read:   {avg:.2f} MB/s avg, {total:.2f} GB total")

        # Directory request stats
        if extra.dirreq_v3_ips:
            print("\n  Directory Requests:")
            print("  " + "-" * 40)
            total_ips = sum(extra.dirreq_v3_ips.values())
            print(f"  Unique IPs:  {total_ips:,}")
            top = sorted(extra.dirreq_v3_ips.items(), key=lambda x: x[1], reverse=True)[:10]
            print("  By country:  " + ", ".join(f"{c}={n}" for c, n in top))

        # Entry stats (for guards)
        if extra.entry_ips:
            print("\n  Entry/Guard Statistics:")
            print("  " + "-" * 40)
            total = sum(extra.entry_ips.values())
            print(f"  Unique IPs:  {total:,}")
            top = sorted(extra.entry_ips.items(), key=lambda x: x[1], reverse=True)[:10]
            print("  By country:  " + ", ".join(f"{c}={n}" for c, n in top))

        # Exit stats
        if extra.exit_streams_opened or extra.exit_kibibytes_written:
            print("\n  Exit Statistics:")
            print("  " + "-" * 40)
            if extra.exit_streams_opened:
                total = sum(extra.exit_streams_opened.values())
                print(f"  Streams:     {total:,} opened")
                top_items = extra.exit_streams_opened.items()
                top = sorted(top_items, key=lambda x: x[1], reverse=True)[:10]
                print("  Top ports:   " + ", ".join(f"{p}={n}" for p, n in top))
            if extra.exit_kibibytes_written:
                written = sum(extra.exit_kibibytes_written.values()) / 1024
                if extra.exit_kibibytes_read:
                    read = sum(extra.exit_kibibytes_read.values()) / 1024
                else:
                    read = 0
                print(f"  Traffic:     {written:.2f} MiB written, {read:.2f} MiB read")

        # Hidden service stats
        has_rend = extra.hidserv_rend_relayed_cells is not None
        has_onions = extra.hidserv_dir_onions_seen is not None
        if has_rend or has_onions:
            print("\n  Hidden Service Statistics:")
            print("  " + "-" * 40)
            if extra.hidserv_rend_relayed_cells is not None:
                print(f"  Rend cells relayed:  {extra.hidserv_rend_relayed_cells:,}")
            if extra.hidserv_dir_onions_seen is not None:
                print(f"  Onions seen:         {extra.hidserv_dir_onions_seen:,}")

        return 0

    # pylint: disable-next=broad-exception-caught
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_path(args: argparse.Namespace) -> int:
    """Select a path through the Tor network using bandwidth-weighted selection."""
    try:
        output.explain("Selecting a path through the Tor network")
        consensus = get_consensus()

        num_hops = args.hops
        target_port = args.port
        output.verbose(f"Path parameters: {num_hops} hops, target port: {target_port or 'any'}")

        # Create path selector
        output.explain("Creating path selector with bandwidth weighting")
        selector = PathSelector(consensus=consensus)

        # Resolve pre-selected routers if specified
        exit_spec = vars(args).get("exit")  # 'exit' is a builtin name
        guard = None
        middle = None
        exit_router = None

        if args.guard:
            guard = _find_router(consensus, args.guard.strip())
            if guard is None:
                print(f"Guard router not found: {args.guard}", file=sys.stderr)
                return 1

        if args.middle and num_hops >= 3:
            middle = _find_router(consensus, args.middle.strip())
            if middle is None:
                print(f"Middle router not found: {args.middle}", file=sys.stderr)
                return 1

        if exit_spec and num_hops >= 2:
            exit_router = _find_router(consensus, exit_spec.strip())
            if exit_router is None:
                print(f"Exit router not found: {exit_spec}", file=sys.stderr)
                return 1

        # Select path
        try:
            path = selector.select_path(
                num_hops=num_hops,
                target_port=target_port,
                guard=guard,
                middle=middle,
                exit_router=exit_router,
            )
        except ValueError as e:
            print(f"Path selection failed: {e}", file=sys.stderr)
            return 1

        # Display path information
        print(f"\nSelected {path.hops}-hop path:")
        print("=" * 70)

        for role, router in zip(path.roles, path.routers, strict=True):
            bw_mbps = (router.bandwidth or 0) / 1_000_000

            print(f"\n  {role}: {router.nickname}")
            print(f"    Fingerprint: {router.fingerprint}")
            print(f"    Address:     {router.ip}:{router.orport}")
            print(f"    Bandwidth:   {bw_mbps:.2f} MB/s")
            print(f"    Flags:       {', '.join(router.flags)}")
            if router.exit_policy:
                print(f"    Exit Policy: {router.exit_policy}")

        # Summary
        print("\n" + "=" * 70)
        min_bw = min((r.bandwidth or 0) for r in path.routers)
        print(f"Path bandwidth (bottleneck): {min_bw / 1_000_000:.2f} MB/s")

        # Show as single line for easy copying
        print(f"\nPath: {' -> '.join(r.nickname for r in path.routers)}")

        return 0

    # pylint: disable-next=broad-exception-caught
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if output.is_debug():
            traceback.print_exc()
        return 1


def _find_router(consensus: ConsensusDocument, query: str) -> RouterStatusEntry | None:
    """Find router by fingerprint or nickname."""
    query_upper = query.upper()
    for r in consensus.routers:
        if r.fingerprint.startswith(query_upper):
            return r
        if r.nickname.upper() == query_upper:
            return r
    return None


def _parse_address_port(addr_port: str) -> tuple[str, int]:
    """Parse address:port string, handling IPv6 bracket notation.

    Examples:
        example.com:80 -> ("example.com", 80)
        192.168.1.1:443 -> ("192.168.1.1", 443)
        [::1]:8080 -> ("::1", 8080)
        [2001:db8::1]:80 -> ("2001:db8::1", 80)

    Raises:
        ValueError: If format is invalid
    """
    if addr_port.startswith("["):
        # IPv6 with brackets: [addr]:port
        bracket_end = addr_port.find("]")
        if bracket_end == -1:
            raise ValueError(f"Invalid IPv6 address format: {addr_port}")
        addr = addr_port[1:bracket_end]
        rest = addr_port[bracket_end + 1 :]
        if not rest.startswith(":"):
            raise ValueError(f"Missing port after IPv6 address: {addr_port}")
        try:
            port = int(rest[1:])
        except ValueError:
            raise ValueError(f"Invalid port: {rest[1:]}") from None
    else:
        # IPv4 or hostname: addr:port
        if ":" not in addr_port:
            raise ValueError(f"Missing port in address: {addr_port}")
        # Find the last colon (in case of bare IPv6 without brackets, though not recommended)
        last_colon = addr_port.rfind(":")
        addr = addr_port[:last_colon]
        try:
            port = int(addr_port[last_colon + 1 :])
        except ValueError:
            raise ValueError(f"Invalid port: {addr_port[last_colon + 1:]}") from None

    if not 1 <= port <= 65535:
        raise ValueError(f"Port out of range: {port}")

    return addr, port


def cmd_circuit(args: argparse.Namespace) -> int:
    """Build a Tor circuit (1-3 hops)."""
    try:
        output.explain("Building a Tor circuit through multiple relays")
        consensus = get_consensus()

        num_hops = args.hops
        output.verbose(f"Circuit will have {num_hops} hop(s)")

        # Resolve pre-specified routers
        exit_spec = vars(args).get("exit")  # 'exit' is a builtin name
        guard = None
        middle = None
        exit_router = None

        if args.guard:
            guard = _find_router(consensus, args.guard.strip())
            if guard is None:
                print(f"Guard router not found: {args.guard}", file=sys.stderr)
                return 1

        if args.middle and num_hops >= 3:
            middle = _find_router(consensus, args.middle.strip())
            if middle is None:
                print(f"Middle router not found: {args.middle}", file=sys.stderr)
                return 1

        if exit_spec and num_hops >= 2:
            exit_router = _find_router(consensus, exit_spec.strip())
            if exit_router is None:
                print(f"Exit router not found: {exit_spec}", file=sys.stderr)
                return 1

        # Use PathSelector for bandwidth-weighted selection with exclusions
        output.explain("Selecting path through the network (bandwidth-weighted)")
        selector = PathSelector(consensus=consensus)
        try:
            path = selector.select_path(
                num_hops=num_hops,
                target_port=args.port,
                guard=guard,
                middle=middle,
                exit_router=exit_router,
            )
        except ValueError as e:
            print(f"Path selection failed: {e}", file=sys.stderr)
            return 1

        routers = path.routers
        roles = path.roles
        output.verbose(f"Selected path: {' → '.join(r.nickname for r in routers)}")

        # Fetch ntor keys for all routers
        ntor_keys = []
        for router in routers:
            result = get_ntor_key(router, consensus)
            if result is None:
                print(f"No ntor-onion-key for {router.nickname}", file=sys.stderr)
                return 1
            ntor_key, source_name, source_type, from_cache = result
            ntor_keys.append(ntor_key)

            # Report source for each router
            action = "Using" if from_cache else "Fetched"
            if source_type in ("dircache", "authority"):
                label = "cache" if source_type == "dircache" else "authority"
                msg = f"{action} {router.nickname}'s microdescriptor from {source_name} ({label})"
                print(msg, file=sys.stderr)
            elif source_type == "descriptor":
                msg = f"{action} {router.nickname}'s descriptor from {source_name}"
                print(msg, file=sys.stderr)
            else:
                print(f"{action} {router.nickname}'s microdescriptor from cache", file=sys.stderr)

        print(f"\nBuilding {num_hops}-hop circuit:")
        for i, (role, r) in enumerate(zip(roles, routers, strict=True)):
            print(f"  [{i+1}] {role}: {r.nickname} ({r.ip}:{r.orport})")

        # Connect to first router
        first_router = routers[0]
        output.explain("Establishing TLS connection to guard relay")
        print(f"\nConnecting to {first_router.nickname}...")
        conn = RelayConnection(
            host=first_router.ip, port=first_router.orport, timeout=get_timeout()
        )

        try:
            conn.connect()
            print("  TLS connection established")
            output.verbose(f"TLS connected to {first_router.ip}:{first_router.orport}")

            output.explain("Performing link protocol handshake")
            if not conn.handshake():
                print("  Link handshake failed", file=sys.stderr)
                return 1
            print(f"  Link protocol: v{conn.link_protocol}")
            output.verbose(f"Link protocol version: {conn.link_protocol}")

            # Create circuit and extend through all hops
            circuit = Circuit.create(conn)
            print(f"  Circuit ID: {circuit.circ_id:#010x}")
            output.debug(f"Circuit ID: {circuit.circ_id:#010x}")

            for i, (router, ntor_key) in enumerate(zip(routers, ntor_keys, strict=True)):
                if i == 0:
                    # First hop - use CREATE2
                    output.explain("Performing ntor handshake with guard relay")
                    print(f"\n  Hop {i+1}: Creating circuit to {router.nickname}...")
                    output.verbose(f"CREATE2 → {router.nickname}")
                    output.debug(f"ntor-onion-key: {ntor_key.hex()}")
                    if not circuit.extend_to(router.fingerprint, ntor_key):
                        print("    CREATE2 failed", file=sys.stderr)
                        return 1
                    print("    CREATE2/CREATED2 successful")
                    output.verbose(f"CREATED2 ← {router.nickname}")
                else:
                    # Subsequent hops - use RELAY_EXTEND2
                    output.explain(f"Extending circuit to {'middle' if i == 1 else 'exit'} relay")
                    print(f"\n  Hop {i+1}: Extending to {router.nickname}...")
                    output.verbose(f"RELAY_EXTEND2 → {router.nickname}")
                    output.debug(f"ntor-onion-key: {ntor_key.hex()}")
                    if not circuit.extend_to(
                        router.fingerprint, ntor_key, ip=router.ip, port=router.orport
                    ):
                        print("    EXTEND2 failed", file=sys.stderr)
                        return 1
                    print("    RELAY_EXTEND2/EXTENDED2 successful")
                    output.verbose(f"EXTENDED2 ← {router.nickname}")

            print(f"\n  Circuit built with {len(circuit.hops)} hops!")

            # Show all hops
            print("\n  Hops:")
            for i, hop in enumerate(circuit.hops):
                if hop.keys:
                    kf = hop.keys.key_forward.hex()[:8]
                    print(f"    [{i+1}] {hop.fingerprint[:16]}... Kf={kf}...")

            # Clean up
            circuit.destroy()
            print("\n  Circuit destroyed")
            return 0

        except ConnectionError as e:
            print(f"  Connection error: {e}", file=sys.stderr)
            return 1
        finally:
            conn.close()

    # pylint: disable-next=broad-exception-caught
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        traceback.print_exc()
        return 1


def cmd_resolve(args: argparse.Namespace) -> int:
    """Resolve a hostname through the Tor network."""
    try:
        output.explain("Resolving hostname through the Tor network")
        consensus = get_consensus()

        # Build 3-hop circuit for DNS resolution using PathSelector
        output.explain("Selecting 3-hop path for DNS resolution")
        selector = PathSelector(consensus=consensus)
        try:
            path = selector.select_path(num_hops=3)
        except ValueError as e:
            print(f"Path selection failed: {e}", file=sys.stderr)
            return 1

        routers = path.routers
        output.verbose(f"Selected path: {' → '.join(r.nickname for r in routers)}")

        # Fetch ntor keys for all routers
        output.explain("Fetching cryptographic keys for each relay")
        ntor_keys = []
        for router in routers:
            result = get_ntor_key(router, consensus)
            if result is None:
                print(f"No ntor-onion-key for {router.nickname}", file=sys.stderr)
                return 1
            ntor_key, source_name, source_type, from_cache = result
            ntor_keys.append(ntor_key)

            # Report source
            action = "Using" if from_cache else "Fetched"
            if source_name and source_type:
                type_label = "cache" if source_type == "dircache" else source_type
                msg = f"{action} {router.nickname}'s microdescriptor "
                msg += f"from {source_name} ({type_label})"
            else:
                # Old cache entries may lack source info
                msg = f"{action} {router.nickname}'s microdescriptor from cache"
            print(msg, file=sys.stderr)

        print("\nBuilding 3-hop circuit for DNS resolution:")
        roles = ["Guard", "Middle", "Exit"]
        for i, r in enumerate(routers):
            print(f"  [{i+1}] {roles[i]}: {r.nickname} ({r.ip}:{r.orport})")

        # Connect to first router
        first_router = routers[0]
        output.explain("Establishing TLS connection to guard relay")
        print(f"\nConnecting to {first_router.nickname}...")
        conn = RelayConnection(host=first_router.ip, port=first_router.orport, timeout=30.0)

        try:
            conn.connect()
            print("  TLS connection established")
            output.verbose(f"TLS connected to {first_router.ip}:{first_router.orport}")

            output.explain("Performing link protocol handshake")
            if not conn.handshake():
                print("  Link handshake failed", file=sys.stderr)
                return 1
            print(f"  Link protocol: v{conn.link_protocol}")
            output.verbose(f"Negotiated link protocol v{conn.link_protocol}")

            # Create circuit and extend through all hops
            circuit = Circuit.create(conn)
            print(f"  Circuit ID: {circuit.circ_id:#010x}")
            output.debug(f"Circuit ID: {circuit.circ_id:#010x}")

            for i, (router, ntor_key) in enumerate(zip(routers, ntor_keys, strict=True)):
                if i == 0:
                    output.explain("Performing ntor handshake with guard relay")
                    print(f"\n  Hop {i+1}: Creating circuit to {router.nickname}...")
                    output.verbose(f"CREATE2 → {router.nickname}")
                    output.debug(f"ntor-onion-key: {ntor_key.hex()}")
                    if not circuit.extend_to(router.fingerprint, ntor_key):
                        print("    CREATE2 failed", file=sys.stderr)
                        return 1
                    print("    CREATE2/CREATED2 successful")
                    output.verbose(f"CREATED2 ← {router.nickname}")
                else:
                    role = "middle" if i == 1 else "exit"
                    output.explain(f"Extending circuit to {role} relay")
                    print(f"\n  Hop {i+1}: Extending to {router.nickname}...")
                    output.verbose(f"RELAY_EXTEND2 → {router.nickname}")
                    output.debug(f"ntor-onion-key: {ntor_key.hex()}")
                    if not circuit.extend_to(
                        router.fingerprint, ntor_key, ip=router.ip, port=router.orport
                    ):
                        print("    EXTEND2 failed", file=sys.stderr)
                        return 1
                    print("    RELAY_EXTEND2/EXTENDED2 successful")
                    output.verbose(f"EXTENDED2 ← {router.nickname}")

            print(f"\n  Circuit built with {len(circuit.hops)} hops!")
            output.verbose(f"Circuit complete with {len(circuit.hops)} hops")

            # Resolve the hostname
            hostname = args.hostname
            output.explain("Sending DNS resolution request through circuit")
            print(f"\n  Resolving {hostname}...")
            output.verbose(f"RELAY_RESOLVE → {hostname}")
            answers = circuit.resolve(hostname)
            output.verbose(f"RELAY_RESOLVED ← {len(answers) if answers else 0} answers")

            if not answers:
                print("  Resolution failed - no answers", file=sys.stderr)
                circuit.destroy()
                return 1

            # Display results
            print(f"\n  DNS Resolution Results for {hostname}:")
            print("  " + "-" * 50)
            for answer in answers:
                # Import here to avoid circular import issues
                # pylint: disable-next=import-outside-toplevel
                from torscope.onion.relay import ResolvedType

                if answer.addr_type == ResolvedType.IPV4:
                    print(f"  A     {answer.value} (TTL: {answer.ttl}s)")
                elif answer.addr_type == ResolvedType.IPV6:
                    print(f"  AAAA  {answer.value} (TTL: {answer.ttl}s)")
                elif answer.addr_type == ResolvedType.HOSTNAME:
                    print(f"  PTR   {answer.value} (TTL: {answer.ttl}s)")
                elif answer.addr_type == ResolvedType.ERROR_TRANSIENT:
                    print(f"  ERROR (transient): {answer.value}")
                elif answer.addr_type == ResolvedType.ERROR_NONTRANSIENT:
                    print(f"  ERROR (permanent): {answer.value}")
            print("  " + "-" * 50)

            circuit.destroy()
            print("\n  Circuit destroyed")
            return 0

        except ConnectionError as e:
            print(f"  Connection error: {e}", file=sys.stderr)
            return 1
        finally:
            conn.close()

    # pylint: disable-next=broad-exception-caught
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        traceback.print_exc()
        return 1


def cmd_hidden_service(args: argparse.Namespace) -> int:
    """Access a Tor hidden service (v3 onion address)."""
    try:
        output.explain("Accessing v3 hidden service (.onion address)")

        # Parse the onion address
        output.explain("Parsing and validating onion address")
        try:
            onion = OnionAddress.parse(args.address)
        except ValueError as e:
            print(f"Invalid onion address: {e}", file=sys.stderr)
            return 1

        output.verbose(f"Onion address version: {onion.version}")
        output.debug(f"Public key: {onion.public_key.hex()}")
        output.debug(f"Checksum: {onion.checksum.hex()}")

        # Display parsed address info
        print(f"Onion Address: {onion.address}")
        print(f"  Version: {onion.version}")
        print(f"  Public key: {onion.public_key.hex()}")
        print(f"  Checksum: {onion.checksum.hex()}")

        # Time period info
        output.explain("Computing current time period for descriptor lookup")
        time_period = get_current_time_period()
        period_info = get_time_period_info()
        output.verbose(f"Time period: {time_period}")
        output.debug(f"Remaining: {period_info['remaining_minutes']:.1f} minutes")
        print(f"\nTime Period: {time_period}")
        print(f"  Remaining: {period_info['remaining_minutes']:.1f} minutes")

        # Get consensus for HSDir selection
        consensus = get_consensus()

        # Pre-fetch Ed25519 identities for all HSDir relays (only do this once)
        output.explain("Fetching Ed25519 identities for HSDir relays")
        print("\nFetching HSDir Ed25519 identities...")
        ed25519_map = HSDirectoryRing.fetch_ed25519_map(consensus)
        output.verbose(f"Found {len(ed25519_map)} Ed25519 identities")
        print(f"Found {len(ed25519_map)} Ed25519 identities")

        # Decode SRV values from consensus
        import base64

        srv_current = None  # SRV#(current_period)
        srv_previous = None  # SRV#(current_period-1)

        if consensus.shared_rand_current:
            srv_current = base64.b64decode(consensus.shared_rand_current[1])
        if consensus.shared_rand_previous:
            srv_previous = base64.b64decode(consensus.shared_rand_previous[1])

        if output.is_debug():
            srv_cur_hex = srv_current.hex() if srv_current else "None"
            srv_prev_hex = srv_previous.hex() if srv_previous else "None"
            output.debug(f"SRV current (SRV#{time_period}): {srv_cur_hex}")
            output.debug(f"SRV previous (SRV#{time_period-1}): {srv_prev_hex}")

        # Empirically verified: Tor uses shared_rand_current for hsdir_index computation.
        # The blinded key is derived from the time period (SRV is not used in blinding).
        # The hsdir_index uses: H("node-idx" | ed25519_id | SRV_current | period | length)

        descriptor_text = None
        hsdir_used = None
        tp = time_period

        if srv_current is None:
            print("Error: No current SRV in consensus (needed for HSDir ring)", file=sys.stderr)
            return 1

        # Compute blinded key and subcredential for this time period
        output.explain("Computing blinded public key for this time period")
        blinded_key = onion.compute_blinded_key(tp)
        subcredential = onion.compute_subcredential(tp)
        output.verbose(f"Blinded key computed for period {tp}")
        output.debug(f"Blinded key: {blinded_key.hex()}")
        output.debug(f"Subcredential: {subcredential.hex()}")
        print(f"\nBlinded Key (period {tp}): {blinded_key.hex()}")

        # Build HSDir hashring using the SRV from the period start.
        # The SRV voting happens every 12 hours (00:00 and 12:00 UTC).
        # Time periods are 24 hours starting at 12:00 UTC.
        #
        # Each time period has a "matching SRV" - the one voted at period start (12:00 UTC).
        # But the consensus fields (shared_rand_current/previous) shift as new votes happen:
        #
        # First half of period (12:00 UTC - 00:00 UTC next day):
        #   - No new SRV vote has happened since period start
        #   - shared_rand_current = SRV from period start (use this)
        #   - shared_rand_previous = older SRV
        #
        # Second half of period (00:00 UTC - 12:00 UTC):
        #   - A new SRV vote happened at 00:00 UTC
        #   - shared_rand_current = new SRV (don't use this)
        #   - shared_rand_previous = SRV from period start (use this)
        #
        # See: https://spec.torproject.org/rend-spec/shared-random.html
        hours_into_period = period_info["remaining_minutes"] / 60
        hours_into_period = 24 - hours_into_period  # Convert remaining to elapsed
        use_previous_srv = hours_into_period >= 12  # Second half of period

        if output.is_debug():
            srv_choice = "previous" if use_previous_srv else "current"
            output.debug(f"Hours into period: {hours_into_period:.1f}, using SRV {srv_choice}")

        output.explain("Building HSDir hashring for descriptor lookup")
        hsdir_ring = HSDirectoryRing(
            consensus, tp, use_second_srv=use_previous_srv, ed25519_map=ed25519_map
        )

        if hsdir_ring.size == 0:
            print("Error: No HSDirs in ring", file=sys.stderr)
            return 1

        srv_label = "previous" if use_previous_srv else "current"
        output.verbose(f"HSDir ring: {hsdir_ring.size} relays, using SRV {srv_label}")
        print(f"\nHSDir Ring (using SRV {srv_label}, period {tp}): {hsdir_ring.size} relays")

        # Find responsible HSDirs (or use manually specified one)
        output.explain("Finding responsible HSDirs for this onion address")
        if args.hsdir:
            # Manual HSDir selection
            output.verbose(f"Using manually specified HSDir: {args.hsdir}")
            hsdir = _find_router(consensus, args.hsdir.strip())
            if hsdir is None:
                print(f"HSDir not found: {args.hsdir}", file=sys.stderr)
                return 1
            if "HSDir" not in hsdir.flags:
                print(f"Warning: {hsdir.nickname} does not have HSDir flag")
            hsdirs = [hsdir]
        else:
            # Automatic HSDir selection
            hsdirs = hsdir_ring.get_responsible_hsdirs(blinded_key)
            output.verbose(f"Found {len(hsdirs)} responsible HSDirs")
            print(f"Responsible HSDirs ({len(hsdirs)}):")
            for i, hsdir in enumerate(hsdirs):
                output.debug(f"HSDir {i+1}: {hsdir.nickname} ({hsdir.fingerprint[:16]}...)")
                print(f"  [{i+1}] {hsdir.nickname} ({hsdir.ip}:{hsdir.orport})")

        # Fetch descriptor from HSDirs (try first 6)
        output.explain("Fetching hidden service descriptor from HSDir")
        for hsdir in hsdirs[:6]:
            output.verbose(f"Trying HSDir: {hsdir.nickname}")
            print(f"\nFetching descriptor from {hsdir.nickname}...")
            try:
                result = fetch_hs_descriptor(
                    consensus=consensus,
                    hsdir=hsdir,
                    blinded_key=blinded_key,
                    timeout=get_timeout(),
                    verbose=output.is_verbose() or output.is_debug(),
                )
                if result:
                    descriptor_text, hsdir_used = result
                    print(f"  Descriptor fetched from {hsdir_used.nickname}")
                    break
                print(f"  Failed to fetch from {hsdir.nickname}")
            except (
                ConnectionError,
                OSError,
                TimeoutError,
                httpx.ConnectError,
                httpx.TimeoutException,
                httpx.NetworkError,
            ) as e:
                # Connection errors - retry with next HSDir
                if output.is_debug():
                    output.debug(f"Connection error: {e}")
                else:
                    print(f"  Failed to connect to {hsdir.nickname}, trying next...")
            except Exception as e:  # pylint: disable=broad-exception-caught
                # Other errors - log and retry
                if output.is_debug():
                    traceback.print_exc()
                else:
                    print(f"  Failed: {type(e).__name__}, trying next...")

        if descriptor_text is None:
            print("\nFailed to fetch descriptor from any HSDir", file=sys.stderr)
            return 1

        output.verbose(f"Descriptor fetched: {len(descriptor_text)} bytes")

        # Parse and decrypt the descriptor
        output.explain("Parsing and decrypting hidden service descriptor")
        try:
            descriptor = parse_hs_descriptor(descriptor_text, blinded_key, subcredential)
        except ValueError as e:
            print(f"\nFailed to parse descriptor: {e}", file=sys.stderr)
            return 1

        output.verbose(f"Descriptor parsed: version {descriptor.outer.version}")
        output.debug(f"Revision counter: {descriptor.outer.revision_counter}")

        # Display descriptor info
        print("\nDescriptor Info:")
        print(f"  Version: {descriptor.outer.version}")
        print(f"  Lifetime: {descriptor.outer.descriptor_lifetime} minutes")
        print(f"  Revision: {descriptor.outer.revision_counter}")
        print(f"  Signing cert: {len(descriptor.outer.signing_key_cert)} bytes")
        print(f"  Superencrypted: {len(descriptor.outer.superencrypted_blob)} bytes")
        print(f"  Signature: {len(descriptor.outer.signature)} bytes")

        if descriptor.decrypted:
            print(f"\nIntroduction Points ({len(descriptor.introduction_points)}):")
            for i, ip in enumerate(descriptor.introduction_points):
                ip_addr = ip.ip_address or "unknown"
                port = ip.port or 0
                fp = ip.fingerprint or "unknown"
                print(f"  [{i+1}] {ip_addr}:{port} (fp: {fp[:16]}...)")
                if ip.onion_key_ntor:
                    print(f"      onion-key: {len(ip.onion_key_ntor)} bytes")
                if ip.enc_key:
                    print(f"      enc-key: {len(ip.enc_key)} bytes")
        else:
            print(f"\n[Descriptor decryption failed: {descriptor.decryption_error}]")

        return 0

    # pylint: disable-next=broad-exception-caught
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        traceback.print_exc()
        return 1


def cmd_connect(args: argparse.Namespace) -> int:  # noqa: PLR0915
    """Connect to a destination through Tor (clearnet or .onion)."""
    try:
        output.explain("Connecting to destination through Tor network")

        # Parse address:port
        try:
            target_addr, target_port = _parse_address_port(args.destination)
        except ValueError as e:
            print(f"Invalid destination format: {e}", file=sys.stderr)
            return 1

        output.verbose(f"Target: {target_addr}:{target_port}")

        # Detect if this is an onion address
        is_onion = target_addr.endswith(".onion")

        if is_onion:
            output.explain("Detected .onion address, using hidden service protocol")
            return _connect_onion(args, target_addr, target_port)
        output.explain("Connecting to clearnet destination through exit relay")
        return _connect_clearnet(args, target_addr, target_port)

    # pylint: disable-next=broad-exception-caught
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        traceback.print_exc()
        return 1


def _connect_clearnet(args: argparse.Namespace, target_addr: str, target_port: int) -> int:
    """Connect to a clearnet destination through Tor."""
    output.explain("Building circuit to connect to clearnet destination")
    consensus = get_consensus()

    num_hops = getattr(args, "hops", 3)
    output.verbose(f"Building {num_hops}-hop circuit for port {target_port}")

    # Resolve pre-specified routers
    exit_spec = vars(args).get("exit")
    guard = None
    middle = None
    exit_router = None

    if args.guard:
        guard = _find_router(consensus, args.guard.strip())
        if guard is None:
            print(f"Guard router not found: {args.guard}", file=sys.stderr)
            return 1

    if args.middle and num_hops >= 3:
        middle = _find_router(consensus, args.middle.strip())
        if middle is None:
            print(f"Middle router not found: {args.middle}", file=sys.stderr)
            return 1

    if exit_spec and num_hops >= 2:
        exit_router = _find_router(consensus, exit_spec.strip())
        if exit_router is None:
            print(f"Exit router not found: {exit_spec}", file=sys.stderr)
            return 1

    # Use PathSelector for bandwidth-weighted selection
    output.explain("Selecting path through the network (bandwidth-weighted)")
    selector = PathSelector(consensus=consensus)
    try:
        path = selector.select_path(
            num_hops=num_hops,
            target_port=target_port,
            guard=guard,
            middle=middle,
            exit_router=exit_router,
        )
    except ValueError as e:
        print(f"Path selection failed: {e}", file=sys.stderr)
        return 1

    routers = path.routers
    roles = path.roles
    output.verbose(f"Selected path: {' → '.join(r.nickname for r in routers)}")

    # Warn if exit doesn't have Exit flag
    if path.exit is not None and "Exit" not in path.exit.flags:
        print(f"Warning: {path.exit.nickname} does not have Exit flag", file=sys.stderr)

    # Fetch ntor keys for all routers
    output.explain("Fetching cryptographic keys for each relay")
    ntor_keys = []
    for router in routers:
        result = get_ntor_key(router, consensus)
        if result is None:
            print(f"No ntor-onion-key for {router.nickname}", file=sys.stderr)
            return 1
        ntor_key, source_name, source_type, from_cache = result
        ntor_keys.append(ntor_key)

        action = "Using" if from_cache else "Fetched"
        if source_type in ("dircache", "authority"):
            label = "cache" if source_type == "dircache" else "authority"
            msg = f"{action} {router.nickname}'s microdescriptor from {source_name} ({label})"
            print(msg, file=sys.stderr)
        elif source_type == "descriptor":
            msg = f"{action} {router.nickname}'s descriptor from {source_name}"
            print(msg, file=sys.stderr)
        else:
            print(f"{action} {router.nickname}'s microdescriptor from cache", file=sys.stderr)

    print(f"\nBuilding {num_hops}-hop circuit:")
    for i, (role, r) in enumerate(zip(roles, routers, strict=True)):
        print(f"  [{i+1}] {role}: {r.nickname} ({r.ip}:{r.orport})")

    # Connect to first router
    first_router = routers[0]
    output.explain("Establishing TLS connection to guard relay")
    print(f"\nConnecting to {first_router.nickname}...")
    conn = RelayConnection(host=first_router.ip, port=first_router.orport, timeout=get_timeout())

    try:
        conn.connect()
        print("  TLS connection established")
        output.verbose(f"TLS connected to {first_router.ip}:{first_router.orport}")

        output.explain("Performing link protocol handshake")
        if not conn.handshake():
            print("  Link handshake failed", file=sys.stderr)
            return 1
        print(f"  Link protocol: v{conn.link_protocol}")
        output.verbose(f"Link protocol version: {conn.link_protocol}")

        # Create circuit and extend through all hops
        circuit = Circuit.create(conn)
        print(f"  Circuit ID: {circuit.circ_id:#010x}")
        output.debug(f"Circuit ID: {circuit.circ_id:#010x}")

        for i, (router, ntor_key) in enumerate(zip(routers, ntor_keys, strict=True)):
            if i == 0:
                print(f"\n  Hop {i+1}: Creating circuit to {router.nickname}...")
                if not circuit.extend_to(router.fingerprint, ntor_key):
                    print("    CREATE2 failed", file=sys.stderr)
                    return 1
                print("    CREATE2/CREATED2 successful")
            else:
                print(f"\n  Hop {i+1}: Extending to {router.nickname}...")
                if not circuit.extend_to(
                    router.fingerprint, ntor_key, ip=router.ip, port=router.orport
                ):
                    print("    EXTEND2 failed", file=sys.stderr)
                    return 1
                print("    RELAY_EXTEND2/EXTENDED2 successful")

        print(f"\n  Circuit built with {len(circuit.hops)} hops!")

        # Open stream
        print(f"\n  Opening stream to {target_addr}:{target_port}...")
        stream_id = circuit.begin_stream(target_addr, target_port)

        if stream_id is None:
            print("    Stream rejected by exit router", file=sys.stderr)
            circuit.destroy()
            return 1

        print(f"    Stream opened (stream_id={stream_id})")

        # Send and receive data
        return _send_and_receive(args, circuit, stream_id, target_addr)

    except ConnectionError as e:
        print(f"  Connection error: {e}", file=sys.stderr)
        return 1
    finally:
        conn.close()


def _connect_onion(args: argparse.Namespace, target_addr: str, target_port: int) -> int:
    """Connect to an onion service through Tor."""
    # Parse the onion address
    try:
        onion = OnionAddress.parse(target_addr)
    except ValueError as e:
        print(f"Invalid onion address: {e}", file=sys.stderr)
        return 1

    print(f"Connecting to {target_addr}:{target_port}", file=sys.stderr)
    print(f"  Public key: {onion.public_key.hex()[:32]}...", file=sys.stderr)

    # Get consensus
    consensus = get_consensus()

    # Time period info
    time_period = get_current_time_period()
    period_info = get_time_period_info()

    # Pre-fetch Ed25519 identities for HSDir relays
    print("\nFetching HSDir Ed25519 identities...", file=sys.stderr)
    ed25519_map = HSDirectoryRing.fetch_ed25519_map(consensus)
    print(f"Found {len(ed25519_map)} Ed25519 identities", file=sys.stderr)

    # Decode SRV values
    import base64

    srv_current = None
    if consensus.shared_rand_current:
        srv_current = base64.b64decode(consensus.shared_rand_current[1])

    if srv_current is None:
        print("Error: No current SRV in consensus", file=sys.stderr)
        return 1

    # Compute blinded key and subcredential
    blinded_key = onion.compute_blinded_key(time_period)
    subcredential = onion.compute_subcredential(time_period)

    # Determine which SRV to use
    hours_into_period = 24 - (period_info["remaining_minutes"] / 60)
    use_previous_srv = hours_into_period >= 12

    hsdir_ring = HSDirectoryRing(
        consensus, time_period, use_second_srv=use_previous_srv, ed25519_map=ed25519_map
    )

    if hsdir_ring.size == 0:
        print("Error: No HSDirs in ring", file=sys.stderr)
        return 1

    # Find responsible HSDirs (or use manually specified one)
    hsdir_arg = getattr(args, "hsdir", None)
    if hsdir_arg:
        hsdir = _find_router(consensus, hsdir_arg.strip())
        if hsdir is None:
            print(f"HSDir not found: {hsdir_arg}", file=sys.stderr)
            return 1
        hsdirs = [hsdir]
    else:
        hsdirs = hsdir_ring.get_responsible_hsdirs(blinded_key)

    # Fetch descriptor
    descriptor_text = None
    for hsdir in hsdirs[:6]:
        print(f"\nFetching descriptor from {hsdir.nickname}...", file=sys.stderr)
        try:
            result = fetch_hs_descriptor(
                consensus=consensus,
                hsdir=hsdir,
                blinded_key=blinded_key,
                timeout=get_timeout(),
                use_3hop_circuit=True,
                verbose=output.is_verbose() or output.is_debug(),
            )
            if result:
                descriptor_text, hsdir_used = result
                print(f"  Descriptor fetched from {hsdir_used.nickname}", file=sys.stderr)
                break
            print(f"  Failed to fetch from {hsdir.nickname}", file=sys.stderr)
        except (ConnectionError, OSError, TimeoutError, httpx.HTTPError) as e:
            if output.is_debug():
                output.debug(f"Connection error: {e}")
            else:
                print(f"  Failed to connect to {hsdir.nickname}, trying next...", file=sys.stderr)
        except Exception as e:  # pylint: disable=broad-exception-caught
            if output.is_debug():
                traceback.print_exc()
            else:
                print(f"  Failed: {type(e).__name__}, trying next...", file=sys.stderr)

    if descriptor_text is None:
        print("\nFailed to fetch descriptor from any HSDir", file=sys.stderr)
        return 1

    # Parse and decrypt descriptor
    try:
        descriptor = parse_hs_descriptor(descriptor_text, blinded_key, subcredential)
    except ValueError as e:
        print(f"\nFailed to parse descriptor: {e}", file=sys.stderr)
        return 1

    if not descriptor.decrypted or not descriptor.introduction_points:
        error = descriptor.decryption_error or "no introduction points"
        print(f"\nCannot connect: {error}", file=sys.stderr)
        return 1

    print(f"\nFound {len(descriptor.introduction_points)} introduction points", file=sys.stderr)

    # Perform rendezvous
    try:
        rend_result = rendezvous_connect(
            consensus=consensus,
            onion_address=onion,
            introduction_points=descriptor.introduction_points,
            subcredential=subcredential,
            timeout=get_timeout(),
            verbose=output.is_verbose() or output.is_debug(),
        )

        print(f"\nConnected! Opening stream to port {target_port}...", file=sys.stderr)
        stream_id = rend_result.circuit.begin_stream(target_addr, target_port)
        if stream_id is None:
            print("Failed to open stream", file=sys.stderr)
            rend_result.circuit.destroy()
            rend_result.connection.close()
            return 1

        print(f"Stream opened (id={stream_id})", file=sys.stderr)

        # Send and receive data
        exit_code = _send_and_receive(args, rend_result.circuit, stream_id, target_addr)

        rend_result.circuit.destroy()
        rend_result.connection.close()
        return exit_code

    except RendezvousError as e:
        print(f"\nRendezvous failed: {e}", file=sys.stderr)
        return 1


def _send_and_receive(
    args: argparse.Namespace, circuit: Circuit, stream_id: int, target_addr: str
) -> int:
    """Send data and receive response on a stream."""
    http_get = getattr(args, "http_get", False)
    request_file: str | None = getattr(args, "file", None)

    if request_file or http_get:
        if http_get:
            request_bytes = (
                f"GET / HTTP/1.1\r\nHost: {target_addr}\r\nConnection: close\r\n\r\n".encode(
                    "ascii"
                )
            )
        elif request_file == "-":
            # Read from stdin
            request_bytes = sys.stdin.buffer.read()
        else:
            assert request_file is not None  # Guaranteed by the if condition
            with open(request_file, "rb") as f:
                request_bytes = f.read()

        print(f"\n  Sending {len(request_bytes)} bytes...")
        circuit.send_data(stream_id, request_bytes)

        # Receive response
        print("  Waiting for response...")
        response_data = b""
        for _ in range(100):
            chunk = circuit.recv_data(stream_id, debug=output.is_debug())
            if chunk is None:
                break
            response_data += chunk

        if response_data:
            print(f"\n  Response ({len(response_data)} bytes):")
            print("  " + "-" * 50)
            response_text = response_data[:2000].decode("utf-8", errors="replace")
            for line in response_text.split("\n"):
                print(f"  {line}")
            if len(response_data) > 2000:
                print("  ...")
            print("  " + "-" * 50)
        else:
            print("  No response data received")

    circuit.destroy()
    print("\n  Connection closed")
    return 0


class _SubcommandHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Custom formatter to clean up subcommand help display."""

    def __init__(self, prog: str) -> None:
        super().__init__(prog, max_help_position=28)

    def _metavar_formatter(
        self, action: argparse.Action, default_metavar: str
    ) -> Callable[[int], tuple[str, ...]]:
        if action.metavar == "":
            return lambda tuple_size: ("",) * tuple_size
        return super()._metavar_formatter(action, default_metavar)

    def _format_action(self, action: argparse.Action) -> str:
        # pylint: disable-next=protected-access
        if isinstance(action, argparse._SubParsersAction):
            # Custom formatting for subcommands with fixed column width
            lines = []
            # _choices_actions contains the help info for each subcommand
            for choice_action in action._choices_actions:  # pylint: disable=protected-access
                name = choice_action.metavar or choice_action.dest
                cmd_help = choice_action.help or ""
                # Fixed width of 24 chars for command name, 2 space indent
                lines.append(f"  {name:<24}{cmd_help}")
            return "\n".join(lines) + "\n"
        return super()._format_action(action)


def main() -> int:
    """Main entry point for the torscope CLI."""
    parser = argparse.ArgumentParser(
        prog="torscope",
        description="Tor Network Information Tool",
        formatter_class=_SubcommandHelpFormatter,
    )

    # Global flags (available on all commands)
    parser.add_argument(
        "-e", "--explain", action="store_true", help="Show brief explanations of what's happening"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v for protocol info, -vv for debug)",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="", title="commands")

    # version command
    subparsers.add_parser("version", help="Display the torscope version")

    # clear command
    subparsers.add_parser("clear", help="Clear cache")

    # authorities command
    subparsers.add_parser("authorities", help="List all directory authorities")

    # fallbacks command
    subparsers.add_parser("fallbacks", help="List fallback directories")

    # routers command
    routers_parser = subparsers.add_parser("routers", help="List routers from network consensus")
    routers_parser.add_argument(
        "--flags", metavar="FLAGS", help="Filter by flags (comma-separated)"
    )
    routers_parser.add_argument("--list-flags", action="store_true", help="List available flags")

    # router command
    router_parser = subparsers.add_parser(
        "router", help="Show server descriptor for a specific router"
    )
    router_parser.add_argument(
        "query", metavar="nickname|fingerprint", help="Router nickname or fingerprint (partial ok)"
    )

    # extra-info command
    extra_info_parser = subparsers.add_parser(
        "extra-info", help="Show extra-info for a specific router"
    )
    extra_info_parser.add_argument(
        "query", metavar="nickname|fingerprint", help="Router nickname or fingerprint"
    )

    # hidden-service command
    hs_parser = subparsers.add_parser("hidden-service", help="Show onion service descriptor")
    hs_parser.add_argument("address", metavar="ADDRESS", help="Onion address (v3, 56 chars)")
    hs_parser.add_argument(
        "--auth-key", metavar="BASE64", help="Client authorization key for private HS"
    )
    hs_parser.add_argument("--hsdir", metavar="FINGERPRINT", help="Manually specify HSDir to use")

    # select-path command
    path_parser = subparsers.add_parser(
        "select-path", help="Select a path through the Tor network (bandwidth-weighted)"
    )
    path_parser.add_argument(
        "--hops", type=int, choices=[1, 2, 3], default=3, help="Number of hops (default: 3)"
    )
    path_parser.add_argument("--guard", metavar="ROUTER", help="Guard router (default: random)")
    path_parser.add_argument("--middle", metavar="ROUTER", help="Middle router (default: random)")
    path_parser.add_argument("--exit", metavar="ROUTER", help="Exit router (default: random)")
    path_parser.add_argument("--port", type=int, metavar="PORT", help="Target port (filters exits)")

    # build-circuit command
    circuit_parser = subparsers.add_parser("build-circuit", help="Build a Tor circuit (1-3 hops)")
    circuit_parser.add_argument(
        "--hops", type=int, choices=[1, 2, 3], default=3, help="Number of hops (default: 3)"
    )
    circuit_parser.add_argument("--guard", metavar="ROUTER", help="Guard router (default: random)")
    circuit_parser.add_argument(
        "--middle", metavar="ROUTER", help="Middle router (default: random)"
    )
    circuit_parser.add_argument("--exit", metavar="ROUTER", help="Exit router (default: random)")
    circuit_parser.add_argument(
        "--port", type=int, metavar="PORT", help="Target port (filters exits)"
    )

    # resolve command
    resolve_parser = subparsers.add_parser(
        "resolve", help="Resolve hostname through Tor network (DNS)"
    )
    resolve_parser.add_argument("hostname", metavar="HOSTNAME", help="Hostname to resolve")

    # connect command
    connect_parser = subparsers.add_parser(
        "connect", help="Connect to a destination through Tor (clearnet or .onion)"
    )
    connect_parser.add_argument(
        "destination",
        metavar="ADDR:PORT",
        help="Destination address:port (use [ipv6]:port for IPv6)",
    )
    connect_parser.add_argument(
        "--file", metavar="FILE", help="File containing request to send (use - for stdin)"
    )
    connect_parser.add_argument("--http-get", action="store_true", help="Send HTTP GET request")
    connect_parser.add_argument(
        "--hops", type=int, choices=[1, 2, 3], default=3, help="Number of hops (default: 3)"
    )
    connect_parser.add_argument("--guard", metavar="ROUTER", help="Guard router (clearnet only)")
    connect_parser.add_argument("--middle", metavar="ROUTER", help="Middle router (clearnet only)")
    connect_parser.add_argument("--exit", metavar="ROUTER", help="Exit router (clearnet only)")
    connect_parser.add_argument("--hsdir", metavar="FINGERPRINT", help="HSDir to use (onion only)")
    connect_parser.add_argument(
        "--auth-key", metavar="BASE64", help="Client authorization key (onion only)"
    )

    args = parser.parse_args()

    # Configure output verbosity from global flags
    # -v enables verbose, -vv enables both verbose and debug
    verbosity = args.verbose
    output.configure(
        explain=args.explain,
        verbose=verbosity >= 1,
        debug=verbosity >= 2,
    )

    if args.command is None:
        parser.print_help()
        return 0

    # Dispatch to command handler
    commands: dict[str, Callable[[argparse.Namespace], int]] = {
        "version": cmd_version,
        "clear": cmd_clear,
        "authorities": cmd_authorities,
        "fallbacks": cmd_fallbacks,
        "routers": cmd_routers,
        "router": cmd_router,
        "extra-info": cmd_extra_info,
        "select-path": cmd_path,
        "build-circuit": cmd_circuit,
        "resolve": cmd_resolve,
        "hidden-service": cmd_hidden_service,
        "connect": cmd_connect,
    }

    try:
        return commands[args.command](args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
