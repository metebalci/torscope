"""
CLI interface for torscope.

Provides command-line tools for exploring the Tor network.
"""

import argparse
import random
import sys
import traceback
from collections.abc import Callable

import httpx

from torscope import __version__
from torscope.cache import (
    clear_cache,
    get_ntor_key_from_cache,
    load_consensus,
    save_consensus,
    save_microdescriptors,
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
from torscope.directory.microdescriptor import MicrodescriptorParser
from torscope.directory.models import ConsensusDocument, RouterStatusEntry
from torscope.directory.or_client import fetch_ntor_key
from torscope.onion.address import OnionAddress, get_current_time_period, get_time_period_info
from torscope.onion.circuit import Circuit
from torscope.onion.connection import RelayConnection
from torscope.path import PathSelector


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
    # Try cache first (unless disabled)
    if not no_cache:
        cached = load_consensus()
        if cached is not None:
            consensus, meta = cached
            source = meta["source"]
            source_type = meta["source_type"]
            msg = f"Using network consensus ({consensus.total_routers:,} routers) "
            msg += f"from {source} ({source_type})"
            print(msg, file=sys.stderr)

            # Always verify signatures
            verified, total = verify_consensus_signatures(consensus)
            print(f"Verified {verified}/{total} consensus signatures", file=sys.stderr)

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
    client = DirectoryClient()
    content, used_authority = client.fetch_consensus(None, "microdesc")
    consensus = ConsensusParser.parse(content, used_authority.nickname)
    msg = f"Fetched network consensus ({consensus.total_routers:,} routers) "
    msg += f"from {used_authority.nickname} (authority)"
    print(msg, file=sys.stderr)

    # Always verify signatures
    verified, total = verify_consensus_signatures(consensus)
    print(f"Verified {verified}/{total} consensus signatures", file=sys.stderr)

    # Save consensus to cache
    save_consensus(content, used_authority.nickname, "authority")

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
    print("Directory Authorities:\n")
    for i, auth in enumerate(get_authorities(), 1):
        print(f"  [{i}] {auth.nickname}")
        print(f"      Address: {auth.address}")
        print(f"      Identity: {auth.v3ident}")
        if auth.ipv6_address:
            print(f"      IPv6: {auth.ipv6_address}")
        print()
    return 0


def cmd_fallbacks(args: argparse.Namespace) -> int:  # pylint: disable=unused-argument
    """List fallback directories."""
    fallbacks = get_fallbacks()
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
        consensus = get_consensus()

        # Filter routers
        routers = consensus.routers
        if args.flags:
            filter_flags = [f.strip() for f in args.flags.split(",")]
            routers = [r for r in routers if all(r.has_flag(flag) for flag in filter_flags)]

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
        consensus = get_consensus()

        # Find router by fingerprint or nickname
        query = args.query.upper()
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
        client = DirectoryClient()
        print("\nFetching full descriptor...", file=sys.stderr)
        content, _ = client.fetch_server_descriptors([router.fingerprint])
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
        consensus = get_consensus()

        # Find router by fingerprint or nickname
        query = args.query.upper()
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

        # Fetch extra-info
        client = DirectoryClient()
        print(f"Fetching extra-info for {router.nickname}...", file=sys.stderr)
        extra_content, _ = client.fetch_extra_info([router.fingerprint])
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
        consensus = get_consensus()

        num_hops = args.hops
        target_port = args.port

        # Create path selector
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
        if args.debug if hasattr(args, "debug") else False:
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


def _select_v2dir_router(
    consensus: ConsensusDocument, exclude: list[str] | None = None
) -> RouterStatusEntry | None:
    """Select a random V2Dir router with a DirPort for fetching directory documents."""
    exclude_set = set(exclude) if exclude else set()
    candidates = [
        r
        for r in consensus.routers
        if r.has_flag("V2Dir")
        and r.has_flag("Fast")
        and r.has_flag("Stable")
        and r.dirport > 0  # Must have a DirPort
        and r.fingerprint not in exclude_set
    ]
    if not candidates:
        return None
    return random.choice(candidates)


def _fetch_microdesc_from_router(
    router: RouterStatusEntry, hashes: list[str]
) -> tuple[bytes, RouterStatusEntry] | None:
    """Fetch microdescriptors from a V2Dir router's DirPort."""
    # Build URL for the router's DirPort
    hash_string = "-".join(h.rstrip("=") for h in hashes)
    url = f"http://{router.ip}:{router.dirport}/tor/micro/d/{hash_string}"

    headers = {
        "Accept-Encoding": "deflate, gzip",
        "User-Agent": "torscope/0.1.0",
    }

    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.get(url, headers=headers, follow_redirects=True)
            response.raise_for_status()
            return response.content, router
    except httpx.HTTPError:
        return None


def _get_ntor_key(
    router: RouterStatusEntry, consensus: ConsensusDocument
) -> tuple[bytes, str, str, bool] | None:
    """
    Get ntor-onion-key for a router, using cache or fetching on-demand.

    Args:
        router: Router status entry with fingerprint and microdesc_hash
        consensus: Network consensus for finding V2Dir routers

    Returns:
        Tuple of (32-byte ntor key, source_name, source_type, from_cache) or None
        source_type is "dircache", "authority", or "descriptor"
        from_cache indicates if this was retrieved from local cache
    """
    # Try cached microdescriptor first
    if router.microdesc_hash:
        cache_result = get_ntor_key_from_cache(router.microdesc_hash)
        if cache_result is not None:
            ntor_key, source_name, source_type = cache_result
            return ntor_key, source_name, source_type, True

        # Try fetching from a V2Dir router (directory cache)
        v2dir_router = _select_v2dir_router(consensus, exclude=[router.fingerprint])
        if v2dir_router:
            result = _fetch_microdesc_from_router(v2dir_router, [router.microdesc_hash])
            if result:
                md_content, used_router = result
                microdescriptors = MicrodescriptorParser.parse(md_content)
                if microdescriptors:
                    save_microdescriptors(microdescriptors, used_router.nickname, "dircache")
                    cache_result = get_ntor_key_from_cache(router.microdesc_hash)
                    if cache_result is not None:
                        return cache_result[0], used_router.nickname, "dircache", False

        # Fall back to authority
        try:
            client = DirectoryClient()
            md_content, authority = client.fetch_microdescriptors([router.microdesc_hash])
            microdescriptors = MicrodescriptorParser.parse(md_content)
            if microdescriptors:
                save_microdescriptors(microdescriptors, authority.nickname, "authority")
                cache_result = get_ntor_key_from_cache(router.microdesc_hash)
                if cache_result is not None:
                    return cache_result[0], authority.nickname, "authority", False
        # pylint: disable-next=broad-exception-caught
        except Exception:
            pass  # Fall through to server descriptor

    # Fall back to fetching server descriptor
    desc_result = fetch_ntor_key(router.fingerprint)
    if desc_result is not None:
        ntor_key, source_name = desc_result
        return ntor_key, source_name, "descriptor", False
    return None


def cmd_circuit(args: argparse.Namespace) -> int:  # pylint: disable=too-many-return-statements
    """Build a circuit (1-3 hops), optionally open a stream and send data."""
    try:
        consensus = get_consensus()

        num_hops = args.hops
        target_port = args.port  # For exit policy matching

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

        # Check if stream requested
        has_stream = args.target is not None and args.port is not None

        # Warn if exit doesn't have Exit flag (only for multi-hop with stream)
        if has_stream and path.exit is not None and "Exit" not in path.exit.flags:
            print(f"Warning: {path.exit.nickname} does not have Exit flag", file=sys.stderr)

        # Fetch descriptors for all routers
        ntor_keys = []
        for router in routers:
            result = _get_ntor_key(router, consensus)
            if result is None:
                print(f"No ntor-onion-key for {router.nickname}", file=sys.stderr)
                return 1
            ntor_key, source_name, source_type, from_cache = result
            ntor_keys.append(ntor_key)

            # Report source for each router
            if from_cache:
                # Using locally cached microdescriptor
                if source_type == "dircache":
                    msg = f"Using {router.nickname}'s microdescriptor "
                    msg += f"from {source_name} (cache)"
                    print(msg, file=sys.stderr)
                elif source_type == "authority":
                    msg = f"Using {router.nickname}'s microdescriptor "
                    msg += f"from {source_name} (authority)"
                    print(msg, file=sys.stderr)
                else:
                    print(f"Using {router.nickname}'s microdescriptor from cache", file=sys.stderr)
            else:
                # Freshly fetched
                if source_type == "dircache":
                    msg = f"Fetched {router.nickname}'s microdescriptor "
                    msg += f"from {source_name} (cache)"
                    print(msg, file=sys.stderr)
                elif source_type == "authority":
                    msg = f"Fetched {router.nickname}'s microdescriptor "
                    msg += f"from {source_name} (authority)"
                    print(msg, file=sys.stderr)
                elif source_type == "descriptor":
                    msg = f"Fetched {router.nickname}'s descriptor "
                    msg += f"from {source_name} (authority)"
                    print(msg, file=sys.stderr)

        print(f"\nBuilding {num_hops}-hop circuit:")
        for i, (role, r) in enumerate(zip(roles, routers, strict=True)):
            print(f"  [{i+1}] {role}: {r.nickname} ({r.ip}:{r.orport})")

        # Connect to first router
        first_router = routers[0]
        print(f"\nConnecting to {first_router.nickname}...")
        conn = RelayConnection(host=first_router.ip, port=first_router.orport, timeout=args.timeout)

        try:
            conn.connect()
            print("  TLS connection established")

            if not conn.handshake():
                print("  Link handshake failed", file=sys.stderr)
                return 1
            print(f"  Link protocol: v{conn.link_protocol}")

            # Create circuit and extend through all hops
            circuit = Circuit.create(conn)
            print(f"  Circuit ID: {circuit.circ_id:#010x}")

            for i, (router, ntor_key) in enumerate(zip(routers, ntor_keys, strict=True)):
                if i == 0:
                    # First hop - use CREATE2
                    print(f"\n  Hop {i+1}: Creating circuit to {router.nickname}...")
                    if not circuit.extend_to(router.fingerprint, ntor_key):
                        print("    CREATE2 failed", file=sys.stderr)
                        return 1
                    print("    CREATE2/CREATED2 successful")
                else:
                    # Subsequent hops - use RELAY_EXTEND2
                    print(f"\n  Hop {i+1}: Extending to {router.nickname}...")
                    if not circuit.extend_to(
                        router.fingerprint, ntor_key, ip=router.ip, port=router.orport
                    ):
                        print("    EXTEND2 failed", file=sys.stderr)
                        return 1
                    print("    RELAY_EXTEND2/EXTENDED2 successful")

            print(f"\n  Circuit built with {len(circuit.hops)} hops!")

            # Show all hops
            print("\n  Hops:")
            for i, hop in enumerate(circuit.hops):
                if hop.keys:
                    kf = hop.keys.key_forward.hex()[:8]
                    print(f"    [{i+1}] {hop.fingerprint[:16]}... Kf={kf}...")

            # Open stream if target specified
            if has_stream:
                print(f"\n  Opening stream to {args.target}:{args.port}...")
                stream_id = circuit.begin_stream(args.target, args.port)

                if stream_id is None:
                    print("    Stream rejected by exit router", file=sys.stderr)
                    circuit.destroy()
                    return 1

                print(f"    Stream opened (stream_id={stream_id})")

                # Send data if provided
                if args.data:
                    # Decode escape sequences like \r\n
                    request_data = args.data.encode("utf-8").decode("unicode_escape")
                    print(f"\n  Sending {len(request_data)} bytes...")
                    circuit.send_data(stream_id, request_data.encode("ascii"))

                    # Receive response
                    print("  Waiting for response...")
                    response_data = b""
                    debug = getattr(args, "debug", False)
                    for _ in range(10):  # Read up to 10 data cells
                        data = circuit.recv_data(stream_id, debug=debug)
                        if data is None:
                            break
                        response_data += data

                    if response_data:
                        print(f"\n  Response ({len(response_data)} bytes):")
                        print("  " + "-" * 50)
                        # Show response (limit to 1000 chars)
                        response_text = response_data[:1000].decode("utf-8", errors="replace")
                        for line in response_text.split("\n"):
                            print(f"  {line}")
                        if len(response_data) > 1000:
                            print("  ...")
                        print("  " + "-" * 50)
                    else:
                        print("  No response data received")

                print("\n  Stream test successful!")

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
        consensus = get_consensus()

        # Build 3-hop circuit for DNS resolution using PathSelector
        selector = PathSelector(consensus=consensus)
        try:
            path = selector.select_path(num_hops=3)
        except ValueError as e:
            print(f"Path selection failed: {e}", file=sys.stderr)
            return 1

        routers = path.routers

        # Fetch ntor keys for all routers
        ntor_keys = []
        for router in routers:
            result = _get_ntor_key(router, consensus)
            if result is None:
                print(f"No ntor-onion-key for {router.nickname}", file=sys.stderr)
                return 1
            ntor_key, source_name, source_type, from_cache = result
            ntor_keys.append(ntor_key)

            # Report source
            action = "Using" if from_cache else "Fetched"
            type_label = "cache" if source_type == "dircache" else source_type
            msg = f"{action} {router.nickname}'s microdescriptor from {source_name} ({type_label})"
            print(msg, file=sys.stderr)

        print("\nBuilding 3-hop circuit for DNS resolution:")
        roles = ["Guard", "Middle", "Exit"]
        for i, r in enumerate(routers):
            print(f"  [{i+1}] {roles[i]}: {r.nickname} ({r.ip}:{r.orport})")

        # Connect to first router
        first_router = routers[0]
        print(f"\nConnecting to {first_router.nickname}...")
        conn = RelayConnection(host=first_router.ip, port=first_router.orport, timeout=30.0)

        try:
            conn.connect()
            print("  TLS connection established")

            if not conn.handshake():
                print("  Link handshake failed", file=sys.stderr)
                return 1
            print(f"  Link protocol: v{conn.link_protocol}")

            # Create circuit and extend through all hops
            circuit = Circuit.create(conn)
            print(f"  Circuit ID: {circuit.circ_id:#010x}")

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

            # Resolve the hostname
            hostname = args.hostname
            print(f"\n  Resolving {hostname}...")
            answers = circuit.resolve(hostname)

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
        # Parse the onion address
        try:
            onion = OnionAddress.parse(args.address)
        except ValueError as e:
            print(f"Invalid onion address: {e}", file=sys.stderr)
            return 1

        # Display parsed address info
        print(f"Onion Address: {onion.address}")
        print(f"  Version: {onion.version}")
        print(f"  Public key: {onion.public_key.hex()}")
        print(f"  Checksum: {onion.checksum.hex()}")

        # Time period info
        time_period = get_current_time_period()
        period_info = get_time_period_info()
        print(f"\nTime Period: {time_period}")
        print(f"  Remaining: {period_info['remaining_minutes']:.1f} minutes")

        # Get consensus for HSDir selection
        consensus = get_consensus()

        # Pre-fetch Ed25519 identities for all HSDir relays (only do this once)
        print("\nFetching HSDir Ed25519 identities...")
        ed25519_map = HSDirectoryRing.fetch_ed25519_map(consensus)
        print(f"Found {len(ed25519_map)} Ed25519 identities")

        # Decode SRV values from consensus
        import base64

        srv_current = None  # SRV#(current_period)
        srv_previous = None  # SRV#(current_period-1)

        if consensus.shared_rand_current:
            srv_current = base64.b64decode(consensus.shared_rand_current[1])
        if consensus.shared_rand_previous:
            srv_previous = base64.b64decode(consensus.shared_rand_previous[1])

        if getattr(args, "debug", False):
            srv_cur_hex = srv_current.hex() if srv_current else "None"
            srv_prev_hex = srv_previous.hex() if srv_previous else "None"
            print(f"\n[debug] SRV current (SRV#{time_period}): {srv_cur_hex}")
            print(f"[debug] SRV previous (SRV#{time_period-1}): {srv_prev_hex}")

        # Empirically verified: Tor uses shared_rand_current for hsdir_index computation.
        # The blinded key is derived from the time period (SRV is not used in blinding).
        # The hsdir_index uses: H("node-idx" | ed25519_id | SRV_current | period | length)

        descriptor_text = None
        hsdir_used = None
        tp = time_period

        if srv_current is None:
            print("Error: No current SRV in consensus (needed for HSDir ring)", file=sys.stderr)
            return 1

        # Compute blinded key for this time period (no SRV needed)
        blinded_key = onion.compute_blinded_key(tp)
        print(f"\nBlinded Key (period {tp}): {blinded_key.hex()}")

        # Build HSDir hashring using shared_rand_current
        # use_second_srv=False means use shared_rand_current
        hsdir_ring = HSDirectoryRing(consensus, tp, use_second_srv=False, ed25519_map=ed25519_map)

        if hsdir_ring.size == 0:
            print("Error: No HSDirs in ring", file=sys.stderr)
            return 1

        print(f"\nHSDir Ring (using SRV current, period {tp}): {hsdir_ring.size} relays")

        # Find responsible HSDirs (or use manually specified one)
        if args.hsdir:
            # Manual HSDir selection
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
            print(f"Responsible HSDirs ({len(hsdirs)}):")
            for i, hsdir in enumerate(hsdirs[:3]):  # Show first 3
                print(f"  [{i+1}] {hsdir.nickname} ({hsdir.ip}:{hsdir.orport})")
            if len(hsdirs) > 3:
                print(f"  ... and {len(hsdirs) - 3} more")

        # Fetch descriptor from HSDirs (try first 6)
        for hsdir in hsdirs[:6]:
            print(f"\nFetching descriptor from {hsdir.nickname}...")
            result = fetch_hs_descriptor(
                consensus=consensus,
                hsdir=hsdir,
                blinded_key=blinded_key,
                timeout=args.timeout,
                use_3hop_circuit=not getattr(args, "direct", False),
                verbose=getattr(args, "debug", False),
            )
            if result:
                descriptor_text, hsdir_used = result
                print(f"  Descriptor fetched from {hsdir_used.nickname}")
                break
            print(f"  Failed to fetch from {hsdir.nickname}")

        if descriptor_text is None:
            print("\nFailed to fetch descriptor from any HSDir", file=sys.stderr)
            return 1

        # Parse the descriptor
        try:
            descriptor = parse_hs_descriptor(descriptor_text)
        except ValueError as e:
            print(f"\nFailed to parse descriptor: {e}", file=sys.stderr)
            return 1

        # Display descriptor info
        print("\nDescriptor Info:")
        print(f"  Version: {descriptor.outer.version}")
        print(f"  Lifetime: {descriptor.outer.descriptor_lifetime} minutes")
        print(f"  Revision: {descriptor.outer.revision_counter}")
        print(f"  Signing cert: {len(descriptor.outer.signing_key_cert)} bytes")
        print(f"  Superencrypted: {len(descriptor.outer.superencrypted_blob)} bytes")
        print(f"  Signature: {len(descriptor.outer.signature)} bytes")

        if not descriptor.decrypted:
            print(f"\n[Descriptor decryption: {descriptor.decryption_error}]")

        # TODO: Rendezvous (if --connect)
        if args.connect:
            print("\n[Rendezvous protocol not yet implemented]")

        return 0

    # pylint: disable-next=broad-exception-caught
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        traceback.print_exc()
        return 1


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
        usage="torscope [options] <command> [command_options]",
        formatter_class=_SubcommandHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", metavar="", title="commands")

    # version command
    subparsers.add_parser("version", help="Display the torscope version")

    # clear command
    subparsers.add_parser("clear", help="Clear cached consensus")

    # authorities command
    subparsers.add_parser("authorities", help="List all directory authorities")

    # fallbacks command
    subparsers.add_parser("fallbacks", help="List fallback directories")

    # routers command
    routers_parser = subparsers.add_parser("routers", help="List routers from network consensus")
    routers_parser.add_argument(
        "--flags", metavar="FLAGS", help="Filter by flags (comma-separated)"
    )

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

    # path command
    path_parser = subparsers.add_parser(
        "path", help="Select a path through the Tor network (bandwidth-weighted)"
    )
    path_parser.add_argument(
        "--hops", type=int, choices=[1, 2, 3], default=3, help="Number of hops (default: 3)"
    )
    path_parser.add_argument("--guard", metavar="ROUTER", help="Guard router (default: random)")
    path_parser.add_argument("--middle", metavar="ROUTER", help="Middle router (default: random)")
    path_parser.add_argument("--exit", metavar="ROUTER", help="Exit router (default: random)")
    path_parser.add_argument("--port", type=int, metavar="PORT", help="Target port (filters exits)")
    path_parser.add_argument("--debug", action="store_true", help="Enable debug output")

    # circuit command
    circuit_parser = subparsers.add_parser(
        "circuit", help="Build a Tor circuit (1-3 hops), optionally open stream"
    )
    circuit_parser.add_argument(
        "--hops", type=int, choices=[1, 2, 3], default=3, help="Number of hops (default: 3)"
    )
    circuit_parser.add_argument("--guard", metavar="ROUTER", help="Guard router (default: random)")
    circuit_parser.add_argument(
        "--middle", metavar="ROUTER", help="Middle router (default: random)"
    )
    circuit_parser.add_argument("--exit", metavar="ROUTER", help="Exit router (default: random)")
    circuit_parser.add_argument("--target", metavar="HOST", help="Target hostname to connect to")
    circuit_parser.add_argument("--port", type=int, metavar="PORT", help="Target port")
    circuit_parser.add_argument(
        "--data", metavar="DATA", help="ASCII data to send (use \\r\\n for line breaks)"
    )
    circuit_parser.add_argument(
        "--timeout", type=float, default=30.0, help="Connection timeout (default: 30s)"
    )
    circuit_parser.add_argument("--debug", action="store_true", help="Enable debug output")

    # resolve command
    resolve_parser = subparsers.add_parser(
        "resolve", help="Resolve hostname through Tor network (DNS)"
    )
    resolve_parser.add_argument("hostname", metavar="HOSTNAME", help="Hostname to resolve")

    # hidden-service command
    hs_parser = subparsers.add_parser(
        "hidden-service", help="Access a Tor hidden service (v3 onion)"
    )
    hs_parser.add_argument("address", metavar="ADDRESS", help="Onion address (56 chars)")
    hs_parser.add_argument(
        "--connect", type=int, metavar="PORT", help="Connect to hidden service on PORT"
    )
    hs_parser.add_argument(
        "--data", metavar="DATA", help="ASCII data to send (use \\r\\n for line breaks)"
    )
    hs_parser.add_argument(
        "--timeout", type=float, default=30.0, help="Connection timeout (default: 30s)"
    )
    hs_parser.add_argument(
        "--auth-key", metavar="BASE64", help="Client authorization key for private HS"
    )
    hs_parser.add_argument("--hsdir", metavar="FINGERPRINT", help="Manually specify HSDir to use")
    hs_parser.add_argument(
        "--direct", action="store_true", help="Connect directly to HSDir (1-hop, less privacy)"
    )
    hs_parser.add_argument("--debug", action="store_true", help="Enable debug output")

    args = parser.parse_args()

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
        "path": cmd_path,
        "circuit": cmd_circuit,
        "resolve": cmd_resolve,
        "hidden-service": cmd_hidden_service,
    }

    try:
        return commands[args.command](args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
