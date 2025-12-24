"""
CLI interface for torscope.

Provides command-line tools for exploring the Tor network.
"""

import argparse
import sys
import threading
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from torscope import __version__, output
from torscope.cache import (
    cleanup_stale_microdescriptors,
    clear_cache,
    load_consensus,
    save_consensus,
)
from torscope.cli_helpers import (
    fetch_hs_descriptor_latest,
    find_router,
    parse_address_port,
    print_decryption_error,
    print_descriptor_info,
    print_introduction_points,
)
from torscope.directory.authority import get_authorities
from torscope.directory.bridge import BridgeParseError, parse_bridge_line
from torscope.directory.certificates import KeyCertificateParser
from torscope.directory.client import DirectoryClient
from torscope.directory.client_auth import parse_client_auth_key, read_client_auth_file
from torscope.directory.consensus import ConsensusParser
from torscope.directory.descriptor import ServerDescriptorParser
from torscope.directory.extra_info import ExtraInfoParser
from torscope.directory.fallback import get_fallbacks
from torscope.directory.hs_descriptor import fetch_hs_descriptor, parse_hs_descriptor
from torscope.directory.hsdir import HSDirectoryRing
from torscope.directory.models import ConsensusDocument
from torscope.microdesc import get_ntor_key
from torscope.onion.address import OnionAddress, get_current_time_period, get_time_period_info
from torscope.onion.circuit import Circuit
from torscope.onion.connection import RelayConnection
from torscope.onion.relay import (
    BEGIN_FLAG_IPV4_NOT_OK,
    BEGIN_FLAG_IPV6_OK,
    BEGIN_FLAG_IPV6_PREFERRED,
)
from torscope.onion.rendezvous import RendezvousError, rendezvous_connect
from torscope.path import PathSelector

# Default timeout for network operations
DEFAULT_TIMEOUT = 30.0

# Module-level timeout (set by --timeout flag)
_timeout: float = DEFAULT_TIMEOUT


def get_timeout() -> float:
    """Get timeout from --timeout flag or default."""
    return _timeout


@dataclass
class PaddingStrategy:
    """Parsed padding strategy from CLI."""

    strategy: str  # e.g., "count"
    count: int = 0  # Number of cells to send
    interval_ms: int = 0  # Interval between cells in milliseconds

    @classmethod
    def parse(cls, value: str) -> "PaddingStrategy":
        """
        Parse a padding strategy string.

        Formats:
            count:N           - Send N cells as fast as possible
            count:N,INTERVAL  - Send N cells with INTERVAL ms between each

        Args:
            value: Strategy string (e.g., "count:10" or "count:10,50")

        Returns:
            PaddingStrategy instance

        Raises:
            ValueError: If format is invalid
        """
        if ":" not in value:
            raise ValueError(f"Invalid padding strategy format: {value} (expected STRATEGY:PARAMS)")

        strategy, params = value.split(":", 1)

        if strategy != "count":
            raise ValueError(f"Unknown padding strategy: {strategy} (only 'count' is supported)")

        parts = params.split(",")
        if len(parts) == 1:
            # count:N
            try:
                count = int(parts[0])
            except ValueError as e:
                raise ValueError(f"Invalid count: {parts[0]}") from e
            return cls(strategy="count", count=count, interval_ms=0)
        if len(parts) == 2:
            # count:N,INTERVAL
            try:
                count = int(parts[0])
                interval_ms = int(parts[1])
            except ValueError as e:
                raise ValueError(f"Invalid count or interval: {params}") from e
            return cls(strategy="count", count=count, interval_ms=interval_ms)
        raise ValueError(f"Invalid count format: {params} (expected N or N,INTERVAL)")


def get_begin_flags(args: argparse.Namespace) -> int:
    """
    Compute BEGIN flags from CLI arguments.

    Args:
        args: Parsed CLI arguments with --ipv6-ok, --ipv4-not-ok, --ipv6-preferred

    Returns:
        32-bit flags value for RELAY_BEGIN cell
    """
    flags = 0
    if getattr(args, "ipv6_ok", False):
        flags |= BEGIN_FLAG_IPV6_OK
    if getattr(args, "ipv4_not_ok", False):
        flags |= BEGIN_FLAG_IPV4_NOT_OK
    if getattr(args, "ipv6_preferred", False):
        flags |= BEGIN_FLAG_IPV6_PREFERRED
    return flags


def _run_padding_loop(
    circuit: Circuit,
    connection: RelayConnection,
    drop_strategy: PaddingStrategy | None,
    vpadding_strategy: PaddingStrategy | None,
    stop_event: threading.Event,
) -> None:
    """
    Run padding loop in a background thread.

    Sends DROP and/or VPADDING cells according to the specified strategies.

    Args:
        circuit: Circuit for DROP cells (long-range padding)
        connection: Connection for VPADDING cells (link padding)
        drop_strategy: Strategy for DROP cells (or None)
        vpadding_strategy: Strategy for VPADDING cells (or None)
        stop_event: Event to signal when to stop
    """
    drop_count = 0
    vpadding_count = 0
    drop_target = drop_strategy.count if drop_strategy else 0
    vpadding_target = vpadding_strategy.count if vpadding_strategy else 0
    drop_interval = (drop_strategy.interval_ms / 1000.0) if drop_strategy else 0
    vpadding_interval = (vpadding_strategy.interval_ms / 1000.0) if vpadding_strategy else 0

    while not stop_event.is_set():
        # Check if we're done
        drop_done = drop_count >= drop_target
        vpadding_done = vpadding_count >= vpadding_target
        if drop_done and vpadding_done:
            break

        # Send DROP cell if needed
        if not drop_done:
            try:
                circuit.send_drop()
                drop_count += 1
                output.debug(f"Sent DROP cell {drop_count}/{drop_target}")
                if drop_interval > 0:
                    time.sleep(drop_interval)
            except Exception as e:  # pylint: disable=broad-exception-caught
                output.debug(f"Error sending DROP cell: {e}")
                break

        # Send VPADDING cell if needed
        if not vpadding_done:
            try:
                connection.send_vpadding()
                vpadding_count += 1
                output.debug(f"Sent VPADDING cell {vpadding_count}/{vpadding_target}")
                if vpadding_interval > 0:
                    time.sleep(vpadding_interval)
            except Exception as e:  # pylint: disable=broad-exception-caught
                output.debug(f"Error sending VPADDING cell: {e}")
                break

    output.debug(f"Padding loop finished: DROP={drop_count}, VPADDING={vpadding_count}")


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


def cmd_serve(args: argparse.Namespace) -> int:
    """Start the API server."""
    try:
        import uvicorn
    except ImportError:
        print("Error: API dependencies not installed.", file=sys.stderr)
        print("Install with: pip install torscope[api]", file=sys.stderr)
        return 1

    host = args.host
    port = args.port
    reload = args.reload
    geoip_db = getattr(args, "geoip_db", None)

    # Initialize GeoIP if path provided
    if geoip_db:
        from torscope.api.geoip import init_geoip

        geoip = init_geoip(geoip_db)
        if geoip.available:
            print(f"GeoIP database: {geoip_db}")
        else:
            print(f"Warning: GeoIP database not found at {geoip_db}", file=sys.stderr)

    print(f"Starting Torscope API server on http://{host}:{port}")
    print(f"API docs: http://{host}:{port}/docs")
    print("Press Ctrl+C to stop")
    print()

    uvicorn.run(
        "torscope.api.app:app",
        host=host,
        port=port,
        reload=reload,
    )
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
            guard = find_router(consensus, args.guard.strip())
            if guard is None:
                print(f"Guard router not found: {args.guard}", file=sys.stderr)
                return 1

        if args.middle and num_hops >= 3:
            middle = find_router(consensus, args.middle.strip())
            if middle is None:
                print(f"Middle router not found: {args.middle}", file=sys.stderr)
                return 1

        if exit_spec and num_hops >= 2:
            exit_router = find_router(consensus, exit_spec.strip())
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


def cmd_circuit(args: argparse.Namespace) -> int:
    """Build a Tor circuit (1-3 hops)."""
    try:
        output.explain("Building a Tor circuit through multiple relays")

        num_hops = args.hops
        output.verbose(f"Circuit will have {num_hops} hop(s)")

        # Check for bridge mode
        bridge = None
        if hasattr(args, "bridge") and args.bridge:
            try:
                bridge = parse_bridge_line(args.bridge)
                output.verbose(f"Using bridge: {bridge.address} ({bridge.short_fingerprint})")
                if bridge.transport:
                    transport_name = bridge.transport.lower()
                    supported_transports = ["webtunnel", "obfs4"]
                    if transport_name not in supported_transports:
                        print(
                            f"Error: Pluggable transport '{bridge.transport}' not yet supported. "
                            f"Supported: {', '.join(supported_transports)}",
                            file=sys.stderr,
                        )
                        return 1
                    output.verbose(f"Using transport: {bridge.transport}")
                if num_hops < 2:
                    print("Error: Bridge requires at least 2 hops", file=sys.stderr)
                    return 1
                if args.guard:
                    print("Error: Cannot specify both --bridge and --guard", file=sys.stderr)
                    return 1
            except BridgeParseError as e:
                print(f"Error parsing bridge: {e}", file=sys.stderr)
                return 1

        # Get consensus (needed for middle/exit selection)
        consensus = get_consensus()

        # Resolve pre-specified routers
        exit_spec = vars(args).get("exit")  # 'exit' is a builtin name
        guard = None
        middle = None
        exit_router = None

        if not bridge and args.guard:
            guard = find_router(consensus, args.guard.strip())
            if guard is None:
                print(f"Guard router not found: {args.guard}", file=sys.stderr)
                return 1

        if args.middle and num_hops >= 3:
            middle = find_router(consensus, args.middle.strip())
            if middle is None:
                print(f"Middle router not found: {args.middle}", file=sys.stderr)
                return 1

        if exit_spec and num_hops >= 2:
            exit_router = find_router(consensus, exit_spec.strip())
            if exit_router is None:
                print(f"Exit router not found: {exit_spec}", file=sys.stderr)
                return 1

        # Path selection
        output.explain("Selecting path through the network (bandwidth-weighted)")
        selector = PathSelector(consensus=consensus)

        if bridge:
            # Bridge mode: select middle/exit only
            try:
                path = selector.select_path_for_bridge(
                    num_hops=num_hops,
                    target_port=args.port,
                    bridge_ip=bridge.ip,
                    bridge_fingerprint=bridge.fingerprint,
                    exit_router=exit_router,
                )
            except ValueError as e:
                print(f"Path selection failed: {e}", file=sys.stderr)
                return 1
        else:
            # Normal mode: select guard/middle/exit
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
        if routers:
            output.verbose(f"Selected path: {' → '.join(r.nickname for r in routers)}")

        # Fetch ntor keys for all routers (not bridge - we'll use CREATE_FAST)
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

        # Display path info
        print(f"\nBuilding {num_hops}-hop circuit:")
        hop_num = 1
        if bridge:
            print(f"  [{hop_num}] Bridge: {bridge.address} ({bridge.short_fingerprint}...)")
            hop_num += 1
        for role, r in zip(roles, routers, strict=True):
            print(f"  [{hop_num}] {role}: {r.nickname} ({r.ip}:{r.orport})")
            hop_num += 1

        # Connect and build circuit
        if bridge:
            # Bridge mode: connect to bridge first
            output.explain("Establishing TLS connection to bridge relay")
            print(f"\nConnecting to bridge {bridge.address}...")
            conn = RelayConnection(host=bridge.ip, port=bridge.port, timeout=get_timeout())
        else:
            # Normal mode: connect to first router
            first_router = routers[0]
            output.explain("Establishing TLS connection to guard relay")
            print(f"\nConnecting to {first_router.nickname}...")
            conn = RelayConnection(
                host=first_router.ip, port=first_router.orport, timeout=get_timeout()
            )

        try:
            conn.connect()
            print("  TLS connection established")
            if bridge:
                output.verbose(f"TLS connected to bridge {bridge.ip}:{bridge.port}")
            else:
                output.verbose(f"TLS connected to {routers[0].ip}:{routers[0].orport}")

            output.explain("Performing link protocol handshake")
            if not conn.handshake():
                print("  Link handshake failed", file=sys.stderr)
                return 1
            print(f"  Link protocol: v{conn.link_protocol}")
            output.verbose(f"Link protocol version: {conn.link_protocol}")

            # Create circuit
            circuit = Circuit.create(conn)
            print(f"  Circuit ID: {circuit.circ_id:#010x}")
            output.debug(f"Circuit ID: {circuit.circ_id:#010x}")

            # Build first hop
            if bridge:
                # Bridge mode: use CREATE_FAST for bridge (no ntor key needed)
                output.explain("Creating circuit to bridge using CREATE_FAST")
                print("\n  Hop 1: Creating circuit to bridge...")
                output.verbose("CREATE_FAST → bridge")
                if not circuit.create_fast(bridge.fingerprint):
                    print("    CREATE_FAST failed", file=sys.stderr)
                    return 1
                print("    CREATE_FAST/CREATED_FAST successful")
                output.verbose("CREATED_FAST ← bridge")

                # Extend to remaining hops
                for i, (router, ntor_key) in enumerate(zip(routers, ntor_keys, strict=True)):
                    role = "middle" if i == 0 and len(routers) > 1 else "exit"
                    output.explain(f"Extending circuit to {role} relay")
                    print(f"\n  Hop {i+2}: Extending to {router.nickname}...")
                    output.verbose(f"RELAY_EXTEND2 → {router.nickname}")
                    output.debug(f"ntor-onion-key: {ntor_key.hex()}")
                    if not circuit.extend_to(
                        router.fingerprint, ntor_key, ip=router.ip, port=router.orport
                    ):
                        print("    EXTEND2 failed", file=sys.stderr)
                        return 1
                    print("    RELAY_EXTEND2/EXTENDED2 successful")
                    output.verbose(f"EXTENDED2 ← {router.nickname}")
            else:
                # Normal mode: use CREATE2/EXTEND2
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
                        role = "middle" if i == 1 and num_hops == 3 else "exit"
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

            # Show all hops
            print("\n  Hops:")
            for i, hop in enumerate(circuit.hops):
                if hop.keys:
                    kf = hop.keys.key_forward.hex()[:8]
                    print(f"    [{i+1}] {hop.fingerprint[:16]}... Kf={kf}...")
                else:
                    # CREATE_FAST doesn't use CircuitKeys, just print fingerprint
                    print(f"    [{i+1}] {hop.fingerprint[:16]}... (CREATE_FAST)")

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

        # Read client authorization key (from file or direct)
        client_privkey: bytes | None = None
        if getattr(args, "auth_key_file", None):
            try:
                client_privkey = read_client_auth_file(args.auth_key_file)
                output.verbose(f"Client authorization key loaded from {args.auth_key_file}")
                output.debug(f"Client auth key: {client_privkey.hex()[:16]}...")
            except FileNotFoundError:
                print(f"Auth key file not found: {args.auth_key_file}", file=sys.stderr)
                return 1
            except ValueError as e:
                print(f"Invalid auth key file: {e}", file=sys.stderr)
                return 1
        elif getattr(args, "auth_key", None):
            try:
                client_privkey = parse_client_auth_key(args.auth_key)
                output.verbose("Client authorization key provided")
                output.debug(f"Client auth key: {client_privkey.hex()[:16]}...")
            except ValueError as e:
                print(f"Invalid auth key: {e}", file=sys.stderr)
                return 1

        # Display parsed address info
        print(f"Onion Address: {onion.address}")
        print(f"  Version: {onion.version}")
        print(f"  Public key: {onion.public_key.hex()}")
        print(f"  Checksum: {onion.checksum.hex()}")

        # Time period info
        output.explain("Computing time period for descriptor lookup")
        current_period = get_current_time_period()
        period_info = get_time_period_info()

        # Use specified period or default to current
        if getattr(args, "time_period", None) is not None:
            time_period = args.time_period
            period_offset = time_period - current_period
            output.verbose(f"Using time period: {time_period} (offset: {period_offset:+d})")
            print(f"\nTime Period: {time_period} (offset: {period_offset:+d} from current)")
        else:
            time_period = current_period
            output.verbose(f"Time period: {time_period}")
            print(f"\nTime Period: {time_period}")

        output.debug(f"Remaining in current period: {period_info['remaining_minutes']:.1f} minutes")
        print(f"  Current period: {current_period}")
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
            hsdir = find_router(consensus, args.hsdir.strip())
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

        # Fetch descriptor from HSDirs
        output.explain("Fetching hidden service descriptor from HSDir")
        descriptor_text = None
        hsdir_used = None

        if getattr(args, "all_hsdirs", False):
            # Query all HSDirs and pick highest revision
            print("\nQuerying all HSDirs for latest revision...")
            result = fetch_hs_descriptor_latest(
                consensus=consensus,
                hsdirs=hsdirs,
                blinded_key=blinded_key,
                timeout=get_timeout(),
                verbose=True,
            )
            if result:
                descriptor_text, hsdir_used = result
                print(f"\nUsing descriptor from {hsdir_used.nickname}")
        else:
            # Standard: try HSDirs in order until one succeeds
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
            descriptor = parse_hs_descriptor(
                descriptor_text, blinded_key, subcredential, client_privkey=client_privkey
            )
        except ValueError as e:
            print(f"\nFailed to parse descriptor: {e}", file=sys.stderr)
            return 1

        output.verbose(f"Descriptor parsed: version {descriptor.outer.version}")
        output.debug(f"Revision counter: {descriptor.outer.revision_counter}")

        # Display descriptor info
        print_descriptor_info(descriptor)

        if descriptor.decrypted:
            print_introduction_points(descriptor.introduction_points)
        else:
            print_decryption_error(descriptor.decryption_error, file=sys.stdout)

        return 0

    # pylint: disable-next=broad-exception-caught
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        traceback.print_exc()
        return 1


def cmd_open_stream(args: argparse.Namespace) -> int:  # noqa: PLR0915
    """Connect to a destination through Tor (clearnet or .onion)."""
    try:
        output.explain("Connecting to destination through Tor network")

        # Parse address:port
        try:
            target_addr, target_port = parse_address_port(args.destination)
        except ValueError as e:
            print(f"Invalid destination format: {e}", file=sys.stderr)
            return 1

        output.verbose(f"Target: {target_addr}:{target_port}")

        # Detect if this is an onion address
        is_onion = target_addr.endswith(".onion")

        if is_onion:
            output.explain("Detected .onion address, using hidden service protocol")
            return _open_stream_onion(args, target_addr, target_port)
        output.explain("Connecting to clearnet destination through exit relay")
        return _open_stream_clearnet(args, target_addr, target_port)

    # pylint: disable-next=broad-exception-caught
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        traceback.print_exc()
        return 1


def _open_stream_clearnet(args: argparse.Namespace, target_addr: str, target_port: int) -> int:
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
        guard = find_router(consensus, args.guard.strip())
        if guard is None:
            print(f"Guard router not found: {args.guard}", file=sys.stderr)
            return 1

    if args.middle and num_hops >= 3:
        middle = find_router(consensus, args.middle.strip())
        if middle is None:
            print(f"Middle router not found: {args.middle}", file=sys.stderr)
            return 1

    if exit_spec and num_hops >= 2:
        exit_router = find_router(consensus, exit_spec.strip())
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

        # Open stream with BEGIN flags
        begin_flags = get_begin_flags(args)
        flags_str = f" (flags=0x{begin_flags:02x})" if begin_flags else ""
        print(f"\n  Opening stream to {target_addr}:{target_port}{flags_str}...")
        stream_id = circuit.begin_stream(target_addr, target_port, flags=begin_flags)

        if stream_id is None:
            print("    Stream rejected by exit router", file=sys.stderr)
            circuit.destroy()
            return 1

        print(f"    Stream opened (stream_id={stream_id})")

        # Send and receive data (pass connection for VPADDING support)
        return _send_and_receive(args, circuit, stream_id, target_addr, connection=conn)

    except ConnectionError as e:
        print(f"  Connection error: {e}", file=sys.stderr)
        return 1
    finally:
        conn.close()


def _open_stream_onion(args: argparse.Namespace, target_addr: str, target_port: int) -> int:
    """Connect to an onion service through Tor."""
    # Parse the onion address
    try:
        onion = OnionAddress.parse(target_addr)
    except ValueError as e:
        print(f"Invalid onion address: {e}", file=sys.stderr)
        return 1

    # Read client authorization key (from file or direct)
    client_privkey: bytes | None = None
    if getattr(args, "auth_key_file", None):
        try:
            client_privkey = read_client_auth_file(args.auth_key_file)
            print(f"  Client auth key loaded from {args.auth_key_file}", file=sys.stderr)
        except FileNotFoundError:
            print(f"Auth key file not found: {args.auth_key_file}", file=sys.stderr)
            return 1
        except ValueError as e:
            print(f"Invalid auth key file: {e}", file=sys.stderr)
            return 1
    elif getattr(args, "auth_key", None):
        try:
            client_privkey = parse_client_auth_key(args.auth_key)
            print("  Client authorization key provided", file=sys.stderr)
        except ValueError as e:
            print(f"Invalid auth key: {e}", file=sys.stderr)
            return 1

    print(f"Connecting to {target_addr}:{target_port}", file=sys.stderr)
    print(f"  Public key: {onion.public_key.hex()[:32]}...", file=sys.stderr)

    # Get consensus
    consensus = get_consensus()

    # Time period info
    current_period = get_current_time_period()
    period_info = get_time_period_info()

    # Use specified period or default to current
    if getattr(args, "time_period", None) is not None:
        time_period = args.time_period
        period_offset = time_period - current_period
        print(f"\nTime Period: {time_period} (offset: {period_offset:+d})", file=sys.stderr)
    else:
        time_period = current_period

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

    # Print time period info (only if not already printed for specified period)
    if getattr(args, "time_period", None) is None:
        print(f"\nTime Period: {time_period}", file=sys.stderr)
    remaining = period_info["remaining_minutes"]
    print(f"  Current: {current_period}, Remaining: {remaining:.1f} min", file=sys.stderr)
    print(f"\nBlinded Key: {blinded_key.hex()[:32]}...", file=sys.stderr)

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
        hsdir = find_router(consensus, hsdir_arg.strip())
        if hsdir is None:
            print(f"HSDir not found: {hsdir_arg}", file=sys.stderr)
            return 1
        hsdirs = [hsdir]
    else:
        hsdirs = hsdir_ring.get_responsible_hsdirs(blinded_key)
        output.verbose(f"Found {len(hsdirs)} responsible HSDirs")
        print(f"Responsible HSDirs ({len(hsdirs)}):", file=sys.stderr)
        for i, hsdir in enumerate(hsdirs):
            output.debug(f"HSDir {i+1}: {hsdir.nickname} ({hsdir.fingerprint[:16]}...)")
            print(f"  [{i+1}] {hsdir.nickname} ({hsdir.ip}:{hsdir.orport})", file=sys.stderr)

    # Fetch descriptor
    descriptor_text = None
    hsdir_used = None

    if getattr(args, "all_hsdirs", False):
        # Query all HSDirs and pick highest revision
        print("\nQuerying all HSDirs for latest revision...", file=sys.stderr)
        result = fetch_hs_descriptor_latest(
            consensus=consensus,
            hsdirs=hsdirs,
            blinded_key=blinded_key,
            timeout=get_timeout(),
            verbose=True,
        )
        if result:
            descriptor_text, hsdir_used = result
            print(f"\nUsing descriptor from {hsdir_used.nickname}", file=sys.stderr)
    else:
        # Standard: try HSDirs in order until one succeeds
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
                    print(f"  Failed: {hsdir.nickname}, trying next...", file=sys.stderr)
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
        descriptor = parse_hs_descriptor(
            descriptor_text, blinded_key, subcredential, client_privkey=client_privkey
        )
    except ValueError as e:
        print(f"\nFailed to parse descriptor: {e}", file=sys.stderr)
        return 1

    # Display descriptor info
    print_descriptor_info(descriptor, file=sys.stderr)

    if not descriptor.decrypted or not descriptor.introduction_points:
        error = descriptor.decryption_error or "no introduction points"
        print_decryption_error(error)
        return 1

    print_introduction_points(descriptor.introduction_points, file=sys.stderr)

    # Perform rendezvous
    try:
        rend_result = rendezvous_connect(
            consensus=consensus,
            onion_address=onion,
            introduction_points=descriptor.introduction_points,
            subcredential=subcredential,
            timeout=get_timeout(),
            verbose=output.is_verbose() or output.is_debug(),
            pow_params=descriptor.pow_params,
            blinded_key=blinded_key,
        )

        # Open stream with BEGIN flags
        begin_flags = get_begin_flags(args)
        flags_str = f" (flags=0x{begin_flags:02x})" if begin_flags else ""
        print(f"\nConnected! Opening stream to port {target_port}{flags_str}...", file=sys.stderr)
        stream_id = rend_result.circuit.begin_stream(target_addr, target_port, flags=begin_flags)
        if stream_id is None:
            print("Failed to open stream", file=sys.stderr)
            rend_result.circuit.destroy()
            rend_result.connection.close()
            return 1

        print(f"Stream opened (id={stream_id})", file=sys.stderr)

        # Send and receive data (pass connection for VPADDING support)
        # Note: _send_and_receive destroys the circuit
        exit_code = _send_and_receive(
            args, rend_result.circuit, stream_id, target_addr, connection=rend_result.connection
        )

        rend_result.connection.close()
        return exit_code

    except RendezvousError as e:
        print(f"\nRendezvous failed: {e}", file=sys.stderr)
        return 1


def _send_and_receive(
    args: argparse.Namespace,
    circuit: Circuit,
    stream_id: int,
    target_addr: str,
    connection: RelayConnection | None = None,
) -> int:
    """Send data and receive response on a stream.

    Args:
        args: CLI arguments
        circuit: The circuit to use
        stream_id: Stream ID
        target_addr: Target address
        connection: Connection for VPADDING (if padding requested)
    """
    http_get_path: str | None = getattr(args, "http_get", None)
    request_file: str | None = getattr(args, "file", None)

    # Parse padding strategies
    drop_strategy = None
    vpadding_strategy = None
    stop_event = None
    padding_thread = None

    if getattr(args, "with_drop", None):
        try:
            drop_strategy = PaddingStrategy.parse(args.with_drop)
        except ValueError as e:
            print(f"  Invalid --with-drop: {e}", file=sys.stderr)
            circuit.destroy()
            return 1

    if getattr(args, "with_vpadding", None):
        if connection is None:
            print("  Error: VPADDING requires connection reference", file=sys.stderr)
            circuit.destroy()
            return 1
        try:
            vpadding_strategy = PaddingStrategy.parse(args.with_vpadding)
        except ValueError as e:
            print(f"  Invalid --with-vpadding: {e}", file=sys.stderr)
            circuit.destroy()
            return 1

    # Start padding thread if needed
    if drop_strategy or vpadding_strategy:
        if drop_strategy:
            print(f"  DROP padding: {drop_strategy.count} cells", end="")
            if drop_strategy.interval_ms > 0:
                print(f" ({drop_strategy.interval_ms}ms interval)")
            else:
                print()
        if vpadding_strategy:
            print(f"  VPADDING padding: {vpadding_strategy.count} cells", end="")
            if vpadding_strategy.interval_ms > 0:
                print(f" ({vpadding_strategy.interval_ms}ms interval)")
            else:
                print()

        stop_event = threading.Event()
        padding_thread = threading.Thread(
            target=_run_padding_loop,
            args=(circuit, connection, drop_strategy, vpadding_strategy, stop_event),
            daemon=True,
        )
        padding_thread.start()

    if request_file or http_get_path:
        if http_get_path:
            request_bytes = (
                f"GET {http_get_path} HTTP/1.1\r\n"
                f"Host: {target_addr}\r\n"
                f"User-Agent: torscope/{__version__}\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
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

            # Split headers and body
            raw_text = response_data.decode("utf-8", errors="replace")
            if "\r\n\r\n" in raw_text:
                headers_part, body_part = raw_text.split("\r\n\r\n", 1)
            elif "\n\n" in raw_text:
                headers_part, body_part = raw_text.split("\n\n", 1)
            else:
                headers_part, body_part = raw_text, ""

            # Check Content-Type header
            is_text = False
            for line in headers_part.split("\n"):
                if line.lower().startswith("content-type:"):
                    content_type = line.split(":", 1)[1].strip().lower()
                    is_text = content_type.startswith("text/")
                    break

            # Print headers
            headers_clean = headers_part.rstrip().replace("\r\n", "\n").replace("\r", "\n")
            for line in headers_clean.split("\n"):
                print(f"  {line}")

            # Print body or binary indicator
            if body_part:
                print()  # Blank line after headers
                if is_text:
                    body_clean = body_part.rstrip().replace("\r\n", "\n").replace("\r", "\n")
                    for line in body_clean.split("\n"):
                        print(f"  {line}")
                else:
                    print(f"  <binary data, {len(body_part)} bytes>")

            print("  " + "-" * 50)
        else:
            print("  No response data received")

    # Stop padding thread if running
    if padding_thread is not None and stop_event is not None:
        stop_event.set()
        padding_thread.join(timeout=1.0)
        if padding_thread.is_alive():
            output.debug("Padding thread still running, continuing...")
        print("  Padding complete")

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
        description="Tor Network Exploration Tool",
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
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        metavar="SECS",
        help=f"Network timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="", title="commands")

    # version command
    subparsers.add_parser("version", help="Display the torscope version")

    # serve command (API server)
    serve_parser = subparsers.add_parser("serve", help="Start the API server")
    serve_parser.add_argument(
        "--host",
        default="127.0.0.1",
        metavar="HOST",
        help="Host to bind to (default: 127.0.0.1)",
    )
    serve_parser.add_argument(
        "--port",
        type=int,
        default=8000,
        metavar="PORT",
        help="Port to bind to (default: 8000)",
    )
    serve_parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for development",
    )
    serve_parser.add_argument(
        "--geoip-db",
        metavar="PATH",
        help="Path to GeoLite2-City.mmdb (default: ./GeoLite2-City.mmdb)",
    )

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
        "--auth-key-file", metavar="FILE", help="Client auth key file for private HS"
    )
    hs_parser.add_argument("--auth-key", metavar="KEY", help="Client auth key (for testing)")
    hs_parser.add_argument("--hsdir", metavar="FINGERPRINT", help="Manually specify HSDir to use")
    hs_parser.add_argument(
        "--all-hsdirs",
        action="store_true",
        help="Query all HSDirs and use descriptor with highest revision",
    )
    hs_parser.add_argument(
        "--time-period",
        type=int,
        default=None,
        metavar="NUM",
        help="Absolute time period number (default: current)",
    )

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
    circuit_parser.add_argument(
        "--bridge",
        metavar="'IP:PORT FP'",
        help="Bridge relay to use as first hop (format: 'IP:PORT FINGERPRINT')",
    )

    # open-stream command
    stream_parser = subparsers.add_parser(
        "open-stream", help="Open a stream to a destination through Tor (clearnet or .onion)"
    )
    stream_parser.add_argument(
        "destination",
        metavar="ADDR:PORT",
        help="Destination address:port (use [ipv6]:port for IPv6)",
    )
    stream_parser.add_argument(
        "--file", metavar="FILE", help="File containing request to send (use - for stdin)"
    )
    stream_parser.add_argument(
        "--http-get",
        nargs="?",
        const="/",
        metavar="PATH",
        help="Send HTTP GET request (default path: /)",
    )
    stream_parser.add_argument(
        "--hops", type=int, choices=[1, 2, 3], default=3, help="Number of hops (default: 3)"
    )
    stream_parser.add_argument("--guard", metavar="ROUTER", help="Guard router (clearnet only)")
    stream_parser.add_argument("--middle", metavar="ROUTER", help="Middle router (clearnet only)")
    stream_parser.add_argument("--exit", metavar="ROUTER", help="Exit router (clearnet only)")
    stream_parser.add_argument("--hsdir", metavar="FINGERPRINT", help="HSDir to use (onion only)")
    stream_parser.add_argument(
        "--auth-key-file", metavar="FILE", help="Client auth key file (onion only)"
    )
    stream_parser.add_argument(
        "--auth-key", metavar="KEY", help="Client auth key (onion only, for testing)"
    )
    stream_parser.add_argument(
        "--bridge",
        metavar="'IP:PORT FP'",
        help="Bridge relay to use as first hop (format: 'IP:PORT FINGERPRINT')",
    )
    stream_parser.add_argument(
        "--all-hsdirs",
        action="store_true",
        help="Query all HSDirs and use descriptor with highest revision (onion only)",
    )
    stream_parser.add_argument(
        "--time-period",
        type=int,
        default=None,
        metavar="NUM",
        help="Absolute time period number (onion only, default: current)",
    )
    stream_parser.add_argument(
        "--with-drop",
        metavar="STRATEGY",
        help="Send DROP cells (long-range padding). Format: count:N[,INTERVAL_MS]",
    )
    stream_parser.add_argument(
        "--with-vpadding",
        metavar="STRATEGY",
        help="Send VPADDING cells (link padding). Format: count:N[,INTERVAL_MS]",
    )
    # BEGIN flags for IPv6 preferences (tor-spec section 6.2)
    stream_parser.add_argument(
        "--ipv6-ok",
        action="store_true",
        help="Allow exit to resolve/connect to IPv6 addresses",
    )
    stream_parser.add_argument(
        "--ipv4-not-ok",
        action="store_true",
        help="Don't allow exit to resolve/connect to IPv4 addresses",
    )
    stream_parser.add_argument(
        "--ipv6-preferred",
        action="store_true",
        help="Prefer IPv6 over IPv4 when both are available",
    )

    # resolve command
    resolve_parser = subparsers.add_parser(
        "resolve", help="Resolve hostname through Tor network (DNS)"
    )
    resolve_parser.add_argument("hostname", metavar="HOSTNAME", help="Hostname to resolve")
    resolve_parser.add_argument(
        "--bridge",
        metavar="'IP:PORT FP'",
        help="Bridge relay to use as first hop (format: 'IP:PORT FINGERPRINT')",
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

    # Set global timeout if provided
    global _timeout  # noqa: PLW0603
    if args.timeout is not None:
        _timeout = args.timeout

    if args.command is None:
        parser.print_help()
        return 0

    # Dispatch to command handler
    commands: dict[str, Callable[[argparse.Namespace], int]] = {
        "version": cmd_version,
        "serve": cmd_serve,
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
        "open-stream": cmd_open_stream,
    }

    try:
        return commands[args.command](args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
