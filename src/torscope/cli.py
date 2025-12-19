"""
CLI interface for torscope.

Provides command-line tools for exploring the Tor network.
"""

import argparse
import sys
from collections.abc import Callable

from torscope import __version__
from torscope.cache import load_consensus, save_consensus
from torscope.directory.authority import get_authorities
from torscope.directory.client import DirectoryClient
from torscope.directory.consensus import ConsensusParser
from torscope.directory.descriptor import ServerDescriptorParser
from torscope.directory.models import ConsensusDocument


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
    print(f"Fetched {consensus.total_relays:,} relays from {used_authority.nickname}",
          file=sys.stderr)

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


def cmd_relays(args: argparse.Namespace) -> int:
    """List relays from network consensus."""
    try:
        consensus = get_consensus(args.no_cache)

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
        consensus = get_consensus(args.no_cache)

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

    # relays command
    relays_parser = subparsers.add_parser("relays", help="List relays from network consensus")
    relays_parser.add_argument(
        "--limit", type=int, default=50, help="Maximum relays to display (default: 50)"
    )
    relays_parser.add_argument("--flags", metavar="FLAGS", help="Filter by flags (comma-separated)")
    relays_parser.add_argument("--no-cache", action="store_true", help="Bypass cache, fetch fresh")

    # relay command
    relay_parser = subparsers.add_parser("relay", help="Show details for a specific relay")
    relay_parser.add_argument(
        "query", metavar="nickname|fingerprint", help="Relay nickname or fingerprint (partial ok)"
    )
    relay_parser.add_argument("--no-cache", action="store_true", help="Bypass cache, fetch fresh")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    # Dispatch to command handler
    commands: dict[str, Callable[[argparse.Namespace], int]] = {
        "version": cmd_version,
        "authorities": cmd_authorities,
        "relays": cmd_relays,
        "relay": cmd_relay,
    }

    try:
        return commands[args.command](args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
