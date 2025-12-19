"""
CLI interface for torscope.

Provides command-line tools for exploring the Tor network.
"""

import argparse
import base64
import random
import sys
import traceback
from collections.abc import Callable

from torscope import __version__
from torscope.cache import load_consensus, save_consensus
from torscope.directory.authority import get_authorities
from torscope.directory.client import DirectoryClient
from torscope.directory.consensus import ConsensusParser
from torscope.directory.descriptor import ServerDescriptorParser
from torscope.directory.extra_info import ExtraInfoParser
from torscope.directory.fallback import get_fallbacks
from torscope.directory.models import ConsensusDocument, RouterStatusEntry
from torscope.onion.circuit import Circuit
from torscope.onion.connection import RelayConnection


def get_consensus(no_cache: bool = False) -> ConsensusDocument:
    """
    Get consensus from cache or fetch from network.

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
            print("Using cached consensus", file=sys.stderr)
            return cached

    # Fetch from network
    client = DirectoryClient()
    print("Fetching consensus...", file=sys.stderr)
    content, used_authority = client.fetch_consensus(None, "microdesc")
    consensus = ConsensusParser.parse(content, used_authority.nickname)
    print(
        f"Fetched {consensus.total_relays:,} relays from {used_authority.nickname}", file=sys.stderr
    )

    # Save to cache
    save_consensus(content, used_authority.nickname)

    return consensus


def cmd_version(args: argparse.Namespace) -> int:  # pylint: disable=unused-argument
    """Display the torscope version."""
    print(__version__)
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


def cmd_relays(args: argparse.Namespace) -> int:
    """List relays from network consensus."""
    try:
        consensus = get_consensus()

        # Filter relays
        relays = consensus.routers
        if args.flags:
            filter_flags = [f.strip() for f in args.flags.split(",")]
            relays = [r for r in relays if all(r.has_flag(flag) for flag in filter_flags)]

        # Display header
        print(f"\nRelays ({len(relays):,} total):\n")
        print(f"{'Nickname':<20} {'Fingerprint':<11} {'Flags'}")
        print("-" * 70)

        # Display relays
        for relay in relays:
            nickname = relay.nickname[:17] + "..." if len(relay.nickname) > 20 else relay.nickname
            fp = relay.short_fingerprint
            flags = ",".join(relay.flags)
            print(f"{nickname:<20} {fp:<11} {flags}")

        return 0

    # pylint: disable-next=broad-exception-caught
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_relay(args: argparse.Namespace) -> int:
    """Show details for a specific relay."""
    try:
        consensus = get_consensus()

        # Find relay by fingerprint or nickname
        query = args.query.upper()
        relay = None

        for r in consensus.routers:
            # Match by fingerprint (full or partial)
            if r.fingerprint.startswith(query):
                relay = r
                break
            # Match by nickname (case-insensitive)
            if r.nickname.upper() == query:
                relay = r
                break

        if relay is None:
            print(f"Relay not found: {args.query}", file=sys.stderr)
            return 1

        # Display consensus info
        print(f"\nRelay: {relay.nickname}")
        print("=" * 70)
        print(f"  Fingerprint:  {relay.fingerprint}")
        print(f"  Address:      {relay.ip}:{relay.orport}")
        if relay.dirport:
            print(f"  DirPort:      {relay.dirport}")
        if relay.ipv6_addresses:
            for addr in relay.ipv6_addresses:
                print(f"  IPv6:         {addr}")
        print(f"  Published:    {relay.published} UTC")
        print(f"  Flags:        {', '.join(relay.flags)}")
        if relay.version:
            print(f"  Version:      {relay.version}")
        if relay.bandwidth:
            bw_mbps = relay.bandwidth / 1_000_000
            print(f"  Bandwidth:    {bw_mbps:.2f} MB/s")

        # Fetch full descriptor for additional details
        client = DirectoryClient()
        print("\nFetching full descriptor...", file=sys.stderr)
        content, _ = client.fetch_server_descriptors([relay.fingerprint])
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
    """Show extra-info statistics for a relay."""
    try:
        consensus = get_consensus()

        # Find relay by fingerprint or nickname
        query = args.query.upper()
        relay = None

        for r in consensus.routers:
            if r.fingerprint.startswith(query):
                relay = r
                break
            if r.nickname.upper() == query:
                relay = r
                break

        if relay is None:
            print(f"Relay not found: {args.query}", file=sys.stderr)
            return 1

        # Fetch extra-info
        client = DirectoryClient()
        print(f"Fetching extra-info for {relay.nickname}...", file=sys.stderr)
        extra_content, _ = client.fetch_extra_info([relay.fingerprint])
        extra_infos = ExtraInfoParser.parse(extra_content)

        if not extra_infos:
            print(f"No extra-info available for {relay.nickname}", file=sys.stderr)
            return 1

        extra = extra_infos[0]

        # Display header
        print(f"\nExtra-Info: {relay.nickname}")
        print("=" * 70)
        print(f"  Fingerprint:  {relay.fingerprint}")
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


def _find_relay(consensus: ConsensusDocument, query: str) -> RouterStatusEntry | None:
    """Find relay by fingerprint or nickname."""
    query_upper = query.upper()
    for r in consensus.routers:
        if r.fingerprint.startswith(query_upper):
            return r
        if r.nickname.upper() == query_upper:
            return r
    return None


def _select_random_relay(
    consensus: ConsensusDocument,
    role: str,
    exclude: list[str] | None = None,
) -> RouterStatusEntry | None:
    """
    Select a random relay appropriate for a circuit role.

    Args:
        consensus: The consensus document
        role: One of "guard", "middle", "exit"
        exclude: List of fingerprints to exclude (avoid same relay twice)

    Returns:
        A random relay suitable for the role, or None if none found
    """
    exclude_set = set(exclude) if exclude else set()

    if role == "guard":
        # Guards need Guard, Stable, and Fast flags
        candidates = [
            r
            for r in consensus.routers
            if r.has_flag("Guard")
            and r.has_flag("Stable")
            and r.has_flag("Fast")
            and r.fingerprint not in exclude_set
        ]
    elif role == "exit":
        # Exits need Exit, Stable, and Fast flags
        candidates = [
            r
            for r in consensus.routers
            if r.has_flag("Exit")
            and r.has_flag("Stable")
            and r.has_flag("Fast")
            and r.fingerprint not in exclude_set
        ]
    else:  # middle
        # Middle relays need Stable and Fast flags
        candidates = [
            r
            for r in consensus.routers
            if r.has_flag("Stable") and r.has_flag("Fast") and r.fingerprint not in exclude_set
        ]

    if not candidates:
        return None

    return random.choice(candidates)


def _get_ntor_key(client: DirectoryClient, fingerprint: str) -> bytes | None:
    """Fetch and decode ntor-onion-key for a relay."""
    content, _ = client.fetch_server_descriptors([fingerprint])
    descriptors = ServerDescriptorParser.parse(content)
    if not descriptors or not descriptors[0].ntor_onion_key:
        return None

    key_b64 = descriptors[0].ntor_onion_key
    padding = 4 - len(key_b64) % 4
    if padding != 4:
        key_b64 += "=" * padding
    return base64.b64decode(key_b64)


def cmd_circuit(args: argparse.Namespace) -> int:  # pylint: disable=too-many-return-statements
    """Build a circuit (1-3 hops), optionally open a stream and send data."""
    try:
        consensus = get_consensus()
        client = DirectoryClient()

        num_hops = args.hops

        # Build relay specs based on number of hops
        exit_spec = vars(args)["exit"]  # 'exit' is a builtin name
        all_specs = [
            ("guard", args.guard),
            ("middle", args.middle),
            ("exit", exit_spec),
        ]
        relay_specs = all_specs[:num_hops]

        # Resolve relays (None means random selection)
        relays = []
        used_fingerprints: list[str] = []

        for role, query in relay_specs:
            if query is None:
                # Random selection based on role
                relay = _select_random_relay(consensus, role, used_fingerprints)
                if relay is None:
                    print(f"No suitable {role} relay found", file=sys.stderr)
                    return 1
            else:
                relay = _find_relay(consensus, query.strip())
                if relay is None:
                    print(f"Relay not found: {query}", file=sys.stderr)
                    return 1
            relays.append(relay)
            used_fingerprints.append(relay.fingerprint)

        # Check if stream requested
        has_stream = args.target is not None and args.port is not None

        # Warn if exit doesn't have Exit flag (only for 3-hop with stream)
        if has_stream and num_hops == 3 and "Exit" not in relays[2].flags:
            print(f"Warning: {relays[2].nickname} does not have Exit flag", file=sys.stderr)

        print(f"\nBuilding {num_hops}-hop circuit:")
        roles = ["Guard", "Middle", "Exit"]
        for i, r in enumerate(relays):
            print(f"  [{i+1}] {roles[i]}: {r.nickname} ({r.ip}:{r.orport})")

        # Fetch descriptors for all relays
        print("\nFetching relay descriptors...", file=sys.stderr)
        ntor_keys = []
        for relay in relays:
            ntor_key = _get_ntor_key(client, relay.fingerprint)
            if ntor_key is None:
                print(f"No ntor-onion-key for {relay.nickname}", file=sys.stderr)
                return 1
            ntor_keys.append(ntor_key)

        # Connect to first relay
        first_relay = relays[0]
        print(f"\nConnecting to {first_relay.nickname}...")
        conn = RelayConnection(host=first_relay.ip, port=first_relay.orport, timeout=args.timeout)

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

            for i, (relay, ntor_key) in enumerate(zip(relays, ntor_keys, strict=True)):
                if i == 0:
                    # First hop - use CREATE2
                    print(f"\n  Hop {i+1}: Creating circuit to {relay.nickname}...")
                    if not circuit.extend_to(relay.fingerprint, ntor_key):
                        print("    CREATE2 failed", file=sys.stderr)
                        return 1
                    print("    CREATE2/CREATED2 successful")
                else:
                    # Subsequent hops - use RELAY_EXTEND2
                    print(f"\n  Hop {i+1}: Extending to {relay.nickname}...")
                    if not circuit.extend_to(
                        relay.fingerprint, ntor_key, ip=relay.ip, port=relay.orport
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
                    print("    Stream rejected by exit relay", file=sys.stderr)
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

    # authorities command
    subparsers.add_parser("authorities", help="List all directory authorities")

    # fallbacks command
    subparsers.add_parser("fallbacks", help="List fallback directories")

    # relays command
    relays_parser = subparsers.add_parser("relays", help="List relays from network consensus")
    relays_parser.add_argument("--flags", metavar="FLAGS", help="Filter by flags (comma-separated)")

    # relay command
    relay_parser = subparsers.add_parser("relay", help="Show details for a specific relay")
    relay_parser.add_argument(
        "query", metavar="nickname|fingerprint", help="Relay nickname or fingerprint (partial ok)"
    )

    # extra-info command
    extra_info_parser = subparsers.add_parser(
        "extra-info", help="Show extra-info statistics for a relay"
    )
    extra_info_parser.add_argument(
        "query", metavar="nickname|fingerprint", help="Relay nickname or fingerprint"
    )

    # circuit command
    circuit_parser = subparsers.add_parser(
        "circuit", help="Build a Tor circuit (1-3 hops), optionally open stream"
    )
    circuit_parser.add_argument(
        "--hops", type=int, choices=[1, 2, 3], default=3, help="Number of hops (default: 3)"
    )
    circuit_parser.add_argument("--guard", metavar="RELAY", help="Guard relay (default: random)")
    circuit_parser.add_argument("--middle", metavar="RELAY", help="Middle relay (default: random)")
    circuit_parser.add_argument("--exit", metavar="RELAY", help="Exit relay (default: random)")
    circuit_parser.add_argument("--target", metavar="HOST", help="Target hostname to connect to")
    circuit_parser.add_argument("--port", type=int, metavar="PORT", help="Target port")
    circuit_parser.add_argument(
        "--data", metavar="DATA", help="ASCII data to send (use \\r\\n for line breaks)"
    )
    circuit_parser.add_argument(
        "--timeout", type=float, default=30.0, help="Connection timeout (default: 30s)"
    )
    circuit_parser.add_argument("--debug", action="store_true", help="Enable debug output")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    # Dispatch to command handler
    commands: dict[str, Callable[[argparse.Namespace], int]] = {
        "version": cmd_version,
        "authorities": cmd_authorities,
        "fallbacks": cmd_fallbacks,
        "relays": cmd_relays,
        "relay": cmd_relay,
        "extra-info": cmd_extra_info,
        "circuit": cmd_circuit,
    }

    try:
        return commands[args.command](args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
