"""
CLI interface for torscope.

Provides command-line tools for exploring the Tor network.
"""

import argparse
import sys
from typing import Optional

from torscope import __version__
from torscope.cache import load_consensus, save_consensus
from torscope.directory.authority import DIRECTORY_AUTHORITIES, get_authority_by_nickname
from torscope.directory.client import DirectoryClient
from torscope.directory.consensus import ConsensusParser
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
    for i, auth in enumerate(DIRECTORY_AUTHORITIES, 1):
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
        print(f"{'Nickname':<20} {'Fingerprint':<10} {'Address':<22} {'Bandwidth':<12} {'Flags'}")
        print("-" * 100)

        # Display relays
        for relay in relays:
            nickname = relay.nickname[:19]
            fp = relay.short_fingerprint
            address = f"{relay.ip}:{relay.orport}"
            bw = f"{relay.bandwidth / 1_000_000:.1f} MB/s" if relay.bandwidth else "unknown"
            flags = ",".join(relay.flags[:5])
            if len(relay.flags) > 5:
                flags += "..."
            print(f"{nickname:<20} {fp:<10} {address:<22} {bw:<12} {flags}")

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


def main() -> int:
    """Main entry point for the torscope CLI."""
    parser = argparse.ArgumentParser(
        prog="torscope",
        description="Tor Network Information Tool",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

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

    # list-relays command
    list_relays = subparsers.add_parser("list-relays", help="List relays from network consensus")
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

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    # Dispatch to command handler
    commands = {
        "version": cmd_version,
        "authorities": cmd_authorities,
        "fetch-consensus": cmd_fetch_consensus,
        "list-relays": cmd_list_relays,
        "fetch-microdescriptors": cmd_fetch_microdescriptors,
    }

    try:
        return commands[args.command](args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
