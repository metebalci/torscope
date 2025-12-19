"""
CLI interface for torscope.

Provides a REPL (Read-Eval-Print Loop) for exploring the Tor network.
"""

import argparse
import cmd
import sys
from typing import Optional

from torscope import __version__
from torscope.directory.authority import DIRECTORY_AUTHORITIES, get_authority_by_nickname
from torscope.directory.client import DirectoryClient
from torscope.directory.consensus import ConsensusParser
from torscope.directory.models import ConsensusDocument


class TorscopeREPL(cmd.Cmd):
    """Interactive REPL for torscope commands."""

    intro = (
        f"torscope v{__version__} - Tor Network Information Tool\n"
        "Type 'help' for available commands or 'exit' to quit.\n"
    )
    prompt = "torscope> "

    def __init__(self) -> None:
        """Initialize the REPL."""
        super().__init__()
        self.client = DirectoryClient()
        self.cached_consensus: Optional[ConsensusDocument] = None

    # pylint: disable-next=unused-argument
    def do_version(self, arg: str) -> None:
        """Display the torscope version.

        Usage: version
        """
        print(__version__)

    # pylint: disable-next=unused-argument
    def do_authorities(self, arg: str) -> None:
        """List all directory authorities.

        Usage: authorities
        """
        print("Directory Authorities:\n")
        for i, auth in enumerate(DIRECTORY_AUTHORITIES, 1):
            print(f"  [{i}] {auth.nickname}")
            print(f"      Address: {auth.address}")
            print(f"      Identity: {auth.v3ident}")
            if auth.ipv6_address:
                print(f"      IPv6: {auth.ipv6_address}")
            print()

    def do_fetch_consensus(self, arg: str) -> None:
        """Fetch network consensus document.

        Usage: fetch-consensus [--type microdesc|full] [--authority <name>]
        """
        # pylint: disable-next=import-outside-toplevel
        import shlex

        try:
            args = shlex.split(arg)
        except ValueError:
            args = arg.split()

        # Parse arguments
        consensus_type = "microdesc"
        authority = None

        i = 0
        while i < len(args):
            if args[i] == "--type" and i + 1 < len(args):
                consensus_type = args[i + 1]
                i += 2
            elif args[i] == "--authority" and i + 1 < len(args):
                auth_name = args[i + 1]
                authority = get_authority_by_nickname(auth_name)
                if authority is None:
                    print(f"Error: Unknown authority '{auth_name}'")
                    return
                i += 2
            else:
                i += 1

        try:
            # Fetch consensus
            source = authority.nickname if authority else "random authority"
            print(f"Fetching {consensus_type} consensus from {source}...")
            content, used_authority = self.client.fetch_consensus(authority, consensus_type)
            print(f"✓ Downloaded {len(content):,} bytes")

            # Parse consensus
            print("Parsing consensus...")
            consensus = ConsensusParser.parse(content, used_authority.nickname)
            self.cached_consensus = consensus

            # Display summary
            print("✓ Parsed successfully\n")
            print("Consensus Information:")
            print(f"  Valid After:  {consensus.valid_after} UTC")
            print(f"  Fresh Until:  {consensus.fresh_until} UTC")
            print(f"  Valid Until:  {consensus.valid_until} UTC")
            print(f"  Total Relays: {consensus.total_relays:,}")
            print(f"  Signatures:   {len(consensus.signatures)}/9 authorities")

            if consensus.known_flags:
                print(f"  Flags: {', '.join(consensus.known_flags)}")

            if consensus.params:
                print(f"  Network Parameters: {len(consensus.params)} parameters set")

            print("\nConsensus cached in memory. Use 'list_relays' to view relays.")

        # pylint: disable-next=broad-exception-caught
        except Exception as e:
            print(f"Error fetching consensus: {e}")
            # pylint: disable-next=import-outside-toplevel
            import traceback

            traceback.print_exc()

    def do_list_relays(self, arg: str) -> None:
        """List relays from cached consensus.

        Usage: list-relays [--limit <n>] [--flags <flag1,flag2>]
        """
        if self.cached_consensus is None:
            print("Error: No consensus cached. Run 'fetch-consensus' first.")
            return

        # pylint: disable-next=import-outside-toplevel
        import shlex

        try:
            args = shlex.split(arg)
        except ValueError:
            args = arg.split()

        # Parse arguments
        limit = 50
        filter_flags: list[str] = []

        i = 0
        while i < len(args):
            if args[i] == "--limit" and i + 1 < len(args):
                limit = int(args[i + 1])
                i += 2
            elif args[i] == "--flags" and i + 1 < len(args):
                filter_flags = [f.strip() for f in args[i + 1].split(",")]
                i += 2
            else:
                i += 1

        # Filter relays
        relays = self.cached_consensus.routers
        if filter_flags:
            relays = [r for r in relays if all(r.has_flag(flag) for flag in filter_flags)]

        total = len(relays)
        relays = relays[:limit]

        # Display header
        print(f"\nRelays (showing {len(relays)} of {total:,}):\n")
        print(f"{'Nickname':<20} {'Fingerprint':<10} {'Address':<22} {'Bandwidth':<12} {'Flags'}")
        print("-" * 100)

        # Display relays
        for relay in relays:
            nickname = relay.nickname[:19]
            fp = relay.short_fingerprint
            address = f"{relay.ip}:{relay.orport}"
            bandwidth = f"{relay.bandwidth / 1_000_000:.1f} MB/s" if relay.bandwidth else "unknown"
            flags = ",".join(relay.flags[:5])  # Show first 5 flags
            if len(relay.flags) > 5:
                flags += "..."

            print(f"{nickname:<20} {fp:<10} {address:<22} {bandwidth:<12} {flags}")

    # pylint: disable-next=unused-argument
    def do_exit(self, arg: str) -> bool:
        """Exit the REPL.

        Usage: exit
        """
        print("Goodbye!")
        return True

    def do_quit(self, arg: str) -> bool:
        """Exit the REPL (alias for exit).

        Usage: quit
        """
        return self.do_exit(arg)

    # pylint: disable-next=invalid-name
    def do_EOF(self, arg: str) -> bool:
        """Exit on Ctrl+D."""
        print()  # Print newline for clean exit
        return self.do_exit(arg)

    def emptyline(self) -> bool:
        """Do nothing on empty line (override default repeat behavior)."""
        return False

    def default(self, line: str) -> None:
        """Handle unknown commands."""
        print(f"Unknown command: {line}")
        print("Type 'help' for available commands.")


def main() -> int:
    """Main entry point for the torscope CLI."""
    parser = argparse.ArgumentParser(
        prog="torscope",
        description="torscope - Tor Network Information Tool",
    )
    parser.add_argument(
        "-c",
        "--command",
        metavar="COMMAND",
        help="Execute a single command and exit (e.g., 'torscope -c version')",
    )

    args = parser.parse_args()

    try:
        repl = TorscopeREPL()

        if args.command:
            # Execute single command and exit
            repl.onecmd(args.command)
            return 0

        # Start interactive REPL
        repl.cmdloop()
        return 0
    except KeyboardInterrupt:
        print("\nInterrupted. Goodbye!")
        return 130
    # pylint: disable-next=broad-exception-caught
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
