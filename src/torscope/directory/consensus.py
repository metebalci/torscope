"""
Consensus document parsing.

This module provides functionality to parse Tor network consensus documents.
"""

from datetime import UTC, datetime

from torscope.directory.models import (
    AuthorityEntry,
    ConsensusDocument,
    DirectorySignature,
    RouterStatusEntry,
)


class ConsensusParser:
    """Parser for Tor consensus documents."""

    @staticmethod
    def parse(content: bytes, fetched_from: str = "") -> ConsensusDocument:
        """
        Parse a consensus document.

        Args:
            content: Raw consensus document bytes
            fetched_from: Nickname of authority it was fetched from

        Returns:
            Parsed ConsensusDocument

        Raises:
            ValueError: If parsing fails
        """
        text = content.decode("utf-8", errors="replace")
        lines = text.split("\n")

        consensus = ConsensusDocument(
            version=3,
            vote_status="consensus",
            consensus_method=1,
            valid_after=datetime.now(UTC),
            fresh_until=datetime.now(UTC),
            valid_until=datetime.now(UTC),
            voting_delay=(0, 0),
            raw_document=text,
            fetched_from=fetched_from,
            fetched_at=datetime.now(UTC),
        )

        current_router: RouterStatusEntry | None = None
        i = 0

        while i < len(lines):
            line = lines[i].strip()

            if not line or line.startswith("#"):
                i += 1
                continue

            parts = line.split()
            if not parts:
                i += 1
                continue

            keyword = parts[0]

            # Preamble fields
            if keyword == "network-status-version":
                consensus.version = int(parts[1])

            elif keyword == "vote-status":
                consensus.vote_status = parts[1]

            elif keyword == "consensus-method":
                consensus.consensus_method = int(parts[1])

            elif keyword == "valid-after":
                consensus.valid_after = ConsensusParser._parse_datetime(" ".join(parts[1:3]))

            elif keyword == "fresh-until":
                consensus.fresh_until = ConsensusParser._parse_datetime(" ".join(parts[1:3]))

            elif keyword == "valid-until":
                consensus.valid_until = ConsensusParser._parse_datetime(" ".join(parts[1:3]))

            elif keyword == "voting-delay":
                consensus.voting_delay = (int(parts[1]), int(parts[2]))

            elif keyword == "client-versions":
                consensus.client_versions = parts[1].split(",")

            elif keyword == "server-versions":
                consensus.server_versions = parts[1].split(",")

            elif keyword == "known-flags":
                consensus.known_flags = parts[1:]

            elif keyword == "params":
                # Parse network parameters (key=value pairs)
                for param in parts[1:]:
                    if "=" in param:
                        key, value = param.split("=", 1)
                        consensus.params[key] = int(value)

            elif keyword == "shared-rand-current-value":
                # shared-rand-current-value NumReveals Value
                if len(parts) >= 3:
                    consensus.shared_rand_current = (int(parts[1]), parts[2])

            elif keyword == "shared-rand-previous-value":
                # shared-rand-previous-value NumReveals Value
                if len(parts) >= 3:
                    consensus.shared_rand_previous = (int(parts[1]), parts[2])

            # Authority section
            elif keyword == "dir-source":
                # dir-source nickname identity hostname IP dirport orport
                if len(parts) >= 7:
                    auth = AuthorityEntry(
                        nickname=parts[1],
                        identity=parts[2],
                        hostname=parts[3],
                        ip=parts[4],
                        dirport=int(parts[5]),
                        orport=int(parts[6]),
                    )
                    consensus.authorities.append(auth)

            # Router status entry
            elif keyword == "r":
                # Full consensus: r nickname identity digest date time IP ORPort DirPort (9 parts)
                # Microdesc consensus: r nickname identity date time IP ORPort DirPort (8 parts)
                if len(parts) >= 8:
                    if current_router is not None:
                        consensus.routers.append(current_router)

                    if len(parts) >= 9:
                        # Full consensus format (with digest)
                        current_router = RouterStatusEntry(
                            nickname=parts[1],
                            identity=parts[2],
                            digest=parts[3],
                            published=ConsensusParser._parse_datetime(" ".join(parts[4:6])),
                            ip=parts[6],
                            orport=int(parts[7]),
                            dirport=int(parts[8]),
                        )
                    else:
                        # Microdesc consensus format (no digest)
                        current_router = RouterStatusEntry(
                            nickname=parts[1],
                            identity=parts[2],
                            digest=parts[2],  # Use identity as digest placeholder
                            published=ConsensusParser._parse_datetime(" ".join(parts[3:5])),
                            ip=parts[5],
                            orport=int(parts[6]),
                            dirport=int(parts[7]),
                        )

            # Additional router fields (only valid if we have a current router)
            elif current_router is not None:
                if keyword == "a":
                    # IPv6 address
                    current_router.ipv6_addresses.append(parts[1])

                elif keyword == "s":
                    # Status flags
                    current_router.flags = parts[1:]

                elif keyword == "v":
                    # Version
                    current_router.version = " ".join(parts[1:])

                elif keyword == "pr":
                    # Protocols
                    current_router.protocols = ConsensusParser._parse_protocols(" ".join(parts[1:]))

                elif keyword == "w":
                    # Bandwidth weights
                    for param in parts[1:]:
                        if "=" in param:
                            key, value = param.split("=", 1)
                            if key == "Bandwidth":
                                current_router.bandwidth = int(value)
                            elif key == "Measured":
                                current_router.measured = int(value)
                            elif key == "Unmeasured" and value == "1":
                                current_router.unmeasured = True

                elif keyword == "p":
                    # Exit policy
                    current_router.exit_policy = " ".join(parts[1:])

                elif keyword == "m":
                    # Microdescriptor hash
                    if len(parts) >= 2:
                        current_router.microdesc_hash = parts[1]

                elif keyword == "id":
                    # Identity keys (id ed25519 <base64>)
                    if len(parts) >= 3 and parts[1] == "ed25519":
                        current_router.ed25519_identity = parts[2]

            # Footer (these must be checked even when current_router is set)
            if keyword == "bandwidth-weights":
                # Append last router before footer section
                if current_router is not None:
                    consensus.routers.append(current_router)
                    current_router = None
                for param in parts[1:]:
                    if "=" in param:
                        key, value = param.split("=", 1)
                        consensus.bandwidth_weights[key] = int(value)

            if keyword == "directory-signature":
                # directory-signature [algorithm] identity signing-key-digest
                if len(parts) >= 3:
                    if len(parts) == 3:
                        # No algorithm specified, default to sha1
                        sig = DirectorySignature(
                            algorithm="sha1",
                            identity=parts[1],
                            signing_key_digest=parts[2],
                            signature="",
                        )
                    else:
                        sig = DirectorySignature(
                            algorithm=parts[1],
                            identity=parts[2],
                            signing_key_digest=parts[3],
                            signature="",
                        )

                    # Read signature lines
                    i += 1
                    sig_lines = []
                    while i < len(lines):
                        sig_line = lines[i].strip()
                        if sig_line.startswith("-----END"):
                            sig_lines.append(sig_line)
                            break
                        sig_lines.append(sig_line)
                        i += 1

                    sig.signature = "\n".join(sig_lines)
                    consensus.signatures.append(sig)

            i += 1

        # Append last router if exists
        if current_router is not None:
            consensus.routers.append(current_router)

        return consensus

    @staticmethod
    def _parse_datetime(date_str: str) -> datetime:
        """Parse datetime from consensus format (YYYY-MM-DD HH:MM:SS)."""
        try:
            return datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return datetime.now(UTC)

    @staticmethod
    def _parse_protocols(proto_str: str) -> dict[str, list[int]]:
        """
        Parse protocol versions string.

        Format: "Link=1-5 Cons=1-2"
        Returns: {"Link": [1,2,3,4,5], "Cons": [1,2]}
        """
        result: dict[str, list[int]] = {}

        for item in proto_str.split():
            if "=" not in item:
                continue

            proto, versions = item.split("=", 1)
            version_list: list[int] = []

            for version_range in versions.split(","):
                if "-" in version_range:
                    start, end = version_range.split("-", 1)
                    version_list.extend(range(int(start), int(end) + 1))
                else:
                    version_list.append(int(version_range))

            result[proto] = version_list

        return result
