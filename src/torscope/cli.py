"""
CLI interface for torscope.

Provides command-line tools for exploring the Tor network.
"""

import argparse
import sys
from typing import Callable, Optional

from torscope import __version__
from torscope.cache import load_consensus, save_consensus
from torscope.directory.authority import get_authorities, get_authority_by_nickname
from torscope.directory.client import DirectoryClient
from torscope.directory.consensus import ConsensusParser
from torscope.directory.descriptor import ServerDescriptorParser
from torscope.directory.microdescriptor import MicrodescriptorParser
from torscope.directory.models import ConsensusDocument


def get_consensus(
    authority_name: Optional[str] = None,
    no_cache: bool = False,
) -> ConsensusDocument:
    """
    Get consensus from cache or fetch from network.

    Args:
        authority_name: Specific authority to fetch from (None for random)
        no_cache: If True, bypass cache and always fetch

    Returns:
        ConsensusDocument

    Raises:
        Exception: If fetch fails
    """
    # Try cache first (unless disabled or specific authority requested)
    if not no_cache and authority_name is None:
        cached = load_consensus()
        if cached is not None:
            print("Using cached consensus", file=sys.stderr)
            return cached

    # Fetch from network
    client = DirectoryClient()
    authority = None
    if authority_name:
        authority = get_authority_by_nickname(authority_name)
        if authority is None:
            raise ValueError(f"Unknown authority '{authority_name}'")

    source = authority.nickname if authority else "random authority"
    print(f"Fetching consensus from {source}...", file=sys.stderr)
    content, used_authority = client.fetch_consensus(authority, "microdesc")
    consensus = ConsensusParser.parse(content, used_authority.nickname)
    print(f"Fetched {consensus.total_relays:,} relays", file=sys.stderr)

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


def cmd_fetch_consensus(args: argparse.Namespace) -> int:
    """Fetch network consensus document."""
    client = DirectoryClient()

    # Get authority if specified
    authority = None
    if args.authority:
        authority = get_authority_by_nickname(args.authority)
        if authority is None:
            print(f"Error: Unknown authority '{args.authority}'", file=sys.stderr)
            return 1

    try:
        source = authority.nickname if authority else "random authority"
        print(f"Fetching {args.type} consensus from {source}...")
        content, used_authority = client.fetch_consensus(authority, args.type)
        print(f"Downloaded {len(content):,} bytes from {used_authority.nickname}")

        # Parse consensus
        print("Parsing consensus...")
        consensus = ConsensusParser.parse(content, used_authority.nickname)

        # Save to cache (only microdesc type)
        if args.type == "microdesc":
            save_consensus(content, used_authority.nickname)
            print("Cached to .torscope/")

        # Display summary
        print("\nConsensus Information:")
        print(f"  Valid After:  {consensus.valid_after} UTC")
        print(f"  Fresh Until:  {consensus.fresh_until} UTC")
        print(f"  Valid Until:  {consensus.valid_until} UTC")
        print(f"  Total Relays: {consensus.total_relays:,}")
        print(f"  Signatures:   {len(consensus.signatures)}/9 authorities")

        if consensus.known_flags:
            print(f"  Flags: {', '.join(consensus.known_flags)}")

        if consensus.params:
            print(f"  Network Parameters: {len(consensus.params)} parameters set")

        return 0

    # pylint: disable-next=broad-exception-caught
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_list_relays(args: argparse.Namespace) -> int:
    """List relays from network consensus."""
    try:
        consensus = get_consensus(args.authority, args.no_cache)

        # Filter relays
        relays = consensus.routers
        if args.flags:
            filter_flags = [f.strip() for f in args.flags.split(",")]
            relays = [r for r in relays if all(r.has_flag(flag) for flag in filter_flags)]

        total = len(relays)
        relays = relays[: args.limit]

        # Display header
        print(f"\nRelays (showing {len(relays)} of {total:,}):\n")
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
        consensus = get_consensus(None, args.no_cache)

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

        # Display relay details
        print(f"\nRelay: {relay.nickname}")
        print("=" * 60)
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
        if relay.measured:
            measured_mbps = relay.measured / 1_000_000
            print(f"  Measured:     {measured_mbps:.2f} MB/s")
        if relay.exit_policy:
            print(f"  Exit Policy:  {relay.exit_policy}")
        if relay.microdesc_hash:
            print(f"  Microdesc:    {relay.microdesc_hash}")

        return 0

    # pylint: disable-next=broad-exception-caught
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_fetch_microdescriptors(args: argparse.Namespace) -> int:
    """Fetch microdescriptors for relays."""
    try:
        consensus = get_consensus(args.authority, args.no_cache)

        # Filter relays
        relays = consensus.routers
        if args.flags:
            filter_flags = [f.strip() for f in args.flags.split(",")]
            relays = [r for r in relays if all(r.has_flag(flag) for flag in filter_flags)]

        # Get relays with microdescriptor hashes
        relays = [r for r in relays if r.microdesc_hash][: args.limit]

        if not relays:
            print("No relays with microdescriptor hashes found.", file=sys.stderr)
            return 1

        # Collect hashes
        hashes = [r.microdesc_hash for r in relays if r.microdesc_hash]

        client = DirectoryClient()
        print(f"Fetching {len(hashes)} microdescriptors...", file=sys.stderr)
        md_content, md_authority = client.fetch_microdescriptors(hashes)
        print(f"Downloaded {len(md_content):,} bytes from {md_authority.nickname}", file=sys.stderr)

        # Parse microdescriptors
        microdescriptors = MicrodescriptorParser.parse(md_content)
        print(f"Parsed {len(microdescriptors)} microdescriptors\n", file=sys.stderr)

        # Display summary
        print(f"{'#':<4} {'ntor-key':<20} {'Exit Policy':<20} {'Family':<10}")
        print("-" * 60)

        for idx, md in enumerate(microdescriptors[:20], 1):
            ntor_key = md.onion_key_ntor[:17] + "..." if md.onion_key_ntor else "none"
            policy = md.exit_policy_v4[:17] + "..." if md.exit_policy_v4 else "none"
            family = str(len(md.family_members)) if md.family_members else "0"
            print(f"{idx:<4} {ntor_key:<20} {policy:<20} {family:<10}")

        if len(microdescriptors) > 20:
            print(f"\n... and {len(microdescriptors) - 20} more")

        return 0

    # pylint: disable-next=broad-exception-caught
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_fetch_descriptor(args: argparse.Namespace) -> int:
    """Fetch full server descriptor for a relay."""
    try:
        consensus = get_consensus(None, args.no_cache)

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

        # Fetch the server descriptor
        client = DirectoryClient()
        print(f"Fetching descriptor for {relay.nickname}...", file=sys.stderr)
        content, used_authority = client.fetch_server_descriptors([relay.fingerprint])
        print(f"Downloaded {len(content):,} bytes from {used_authority.nickname}", file=sys.stderr)

        # Parse the descriptor
        descriptors = ServerDescriptorParser.parse(content)
        if not descriptors:
            print("Failed to parse descriptor", file=sys.stderr)
            return 1

        desc = descriptors[0]

        # Display descriptor details
        print(f"\nServer Descriptor: {desc.nickname}")
        print("=" * 70)
        print(f"  Fingerprint:    {desc.fingerprint}")
        print(f"  Address:        {desc.ip}:{desc.orport}")
        if desc.dirport:
            print(f"  DirPort:        {desc.dirport}")
        for addr in desc.ipv6_addresses:
            print(f"  IPv6:           {addr}")
        print(f"  Published:      {desc.published} UTC")

        if desc.platform:
            print(f"  Platform:       {desc.platform}")
        if desc.tor_version:
            print(f"  Tor Version:    {desc.tor_version}")

        print("\n  Bandwidth:")
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
            print(f"\n  Flags:          {', '.join(flags)}")

        if desc.ntor_onion_key:
            print(f"\n  ntor-onion-key: {desc.ntor_onion_key[:40]}...")

        return 0

    # pylint: disable-next=broad-exception-caught
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
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

    # fetch-consensus command
    fetch_consensus = subparsers.add_parser(
        "fetch-consensus", help="Fetch network consensus document"
    )
    fetch_consensus.add_argument(
        "--type",
        choices=["microdesc", "full"],
        default="microdesc",
        help="Consensus type (default: microdesc)",
    )
    fetch_consensus.add_argument(
        "--authority", metavar="NAME", help="Specific authority to fetch from"
    )

    # relays command
    list_relays = subparsers.add_parser("relays", help="List relays from network consensus")
    list_relays.add_argument(
        "--limit", type=int, default=50, help="Maximum relays to display (default: 50)"
    )
    list_relays.add_argument("--flags", metavar="FLAGS", help="Filter by flags (comma-separated)")
    list_relays.add_argument("--authority", metavar="NAME", help="Specific authority to fetch from")
    list_relays.add_argument("--no-cache", action="store_true", help="Bypass cache, fetch fresh")

    # fetch-microdescriptors command
    fetch_mds = subparsers.add_parser(
        "fetch-microdescriptors", help="Fetch microdescriptors for relays"
    )
    fetch_mds.add_argument(
        "--limit", type=int, default=10, help="Maximum microdescriptors to fetch (default: 10)"
    )
    fetch_mds.add_argument(
        "--flags", metavar="FLAGS", help="Filter relays by flags (comma-separated)"
    )
    fetch_mds.add_argument("--authority", metavar="NAME", help="Specific authority to fetch from")
    fetch_mds.add_argument("--no-cache", action="store_true", help="Bypass cache, fetch fresh")

    # relay command
    relay_parser = subparsers.add_parser("relay", help="Show details for a specific relay")
    relay_parser.add_argument("query", metavar="nickname|fingerprint", help="Relay nickname or fingerprint (partial ok)")
    relay_parser.add_argument("--no-cache", action="store_true", help="Bypass cache, fetch fresh")

    # fetch-descriptor command
    fetch_desc = subparsers.add_parser(
        "fetch-descriptor", help="Fetch full server descriptor for a relay"
    )
    fetch_desc.add_argument("query", metavar="nickname|fingerprint", help="Relay nickname or fingerprint (partial ok)")
    fetch_desc.add_argument("--no-cache", action="store_true", help="Bypass cache, fetch fresh")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    # Dispatch to command handler
    commands = {
        "version": cmd_version,
        "authorities": cmd_authorities,
        "fetch-consensus": cmd_fetch_consensus,
        "relays": cmd_list_relays,
        "relay": cmd_relay,
        "fetch-microdescriptors": cmd_fetch_microdescriptors,
        "fetch-descriptor": cmd_fetch_descriptor,
    }

    try:
        return commands[args.command](args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
