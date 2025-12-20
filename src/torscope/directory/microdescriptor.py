"""
Microdescriptor parser.

This module provides parsing functionality for Tor microdescriptor documents.
Microdescriptors are compact relay descriptors containing only essential
information for path selection.
"""

import base64
import hashlib
from datetime import UTC, datetime

from torscope.directory.models import Microdescriptor


class MicrodescriptorParser:
    """Parser for Tor microdescriptor documents."""

    @staticmethod
    def parse(content: bytes | str) -> list[Microdescriptor]:
        """
        Parse microdescriptor document(s) into Microdescriptor objects.

        A single fetch may return multiple microdescriptors concatenated together.
        Each microdescriptor starts with "onion-key" line.

        Args:
            content: Raw microdescriptor content (bytes or string)

        Returns:
            List of parsed Microdescriptor objects
        """
        if isinstance(content, bytes):
            text = content.decode("utf-8", errors="replace")
        else:
            text = content

        microdescriptors: list[Microdescriptor] = []
        current_lines: list[str] = []
        in_pem_block = False

        for line in text.split("\n"):
            # Track PEM block boundaries
            if line.startswith("-----BEGIN"):
                in_pem_block = True
            elif line.startswith("-----END"):
                in_pem_block = False
                current_lines.append(line)
                continue

            # New microdescriptor starts with "onion-key"
            if line.startswith("onion-key") and not in_pem_block:
                # Parse previous microdescriptor if exists
                if current_lines:
                    md = MicrodescriptorParser._parse_single(current_lines)
                    if md:
                        microdescriptors.append(md)
                current_lines = [line]
            elif current_lines:  # Only add lines if we've started a microdescriptor
                current_lines.append(line)

        # Parse last microdescriptor
        if current_lines:
            md = MicrodescriptorParser._parse_single(current_lines)
            if md:
                microdescriptors.append(md)

        return microdescriptors

    @staticmethod
    def _parse_single(lines: list[str]) -> Microdescriptor | None:
        """
        Parse a single microdescriptor from lines.

        Args:
            lines: Lines comprising a single microdescriptor

        Returns:
            Microdescriptor object or None if parsing fails
        """
        # Reconstruct raw descriptor for hashing
        raw_descriptor = "\n".join(lines)
        if not raw_descriptor.endswith("\n"):
            raw_descriptor += "\n"

        # Compute SHA256 digest (base64-encoded without padding, to match consensus format)
        digest_bytes = hashlib.sha256(raw_descriptor.encode("utf-8")).digest()
        digest = base64.b64encode(digest_bytes).decode("ascii").rstrip("=")

        # Initialize fields
        onion_key_rsa: str | None = None
        onion_key_ntor: str | None = None
        ed25519_identity: str | None = None
        rsa1024_identity: str | None = None
        ipv6_addresses: list[str] = []
        exit_policy_v4: str | None = None
        exit_policy_v6: str | None = None
        family_members: list[str] = []
        family_ids: list[str] = []

        i = 0
        while i < len(lines):
            line = lines[i]

            if line.startswith("onion-key"):
                # Parse PEM block
                pem_lines = [line]
                i += 1
                while i < len(lines) and not lines[i].startswith("-----END"):
                    pem_lines.append(lines[i])
                    i += 1
                if i < len(lines):
                    pem_lines.append(lines[i])
                onion_key_rsa = "\n".join(pem_lines)

            elif line.startswith("ntor-onion-key "):
                # Base64-encoded curve25519 key
                onion_key_ntor = line[len("ntor-onion-key ") :].strip()

            elif line.startswith("a "):
                # IPv6 or additional OR address
                addr = line[2:].strip()
                if addr:
                    ipv6_addresses.append(addr)

            elif line.startswith("family "):
                # Family members (space-separated)
                members = line[len("family ") :].strip().split()
                family_members.extend(members)

            elif line.startswith("family-ids "):
                # Family identifiers (space-separated)
                ids = line[len("family-ids ") :].strip().split()
                family_ids.extend(ids)

            elif line.startswith("p "):
                # Exit policy summary (accept/reject portlist)
                exit_policy_v4 = line[2:].strip()

            elif line.startswith("p6 "):
                # IPv6 exit policy summary
                exit_policy_v6 = line[3:].strip()

            elif line.startswith("id "):
                # Identity key hash
                parts = line.split()
                if len(parts) >= 3:
                    key_type = parts[1]
                    key_value = parts[2]
                    if key_type == "ed25519":
                        ed25519_identity = key_value
                    elif key_type == "rsa1024":
                        rsa1024_identity = key_value

            i += 1

        return Microdescriptor(
            digest=digest,
            onion_key_rsa=onion_key_rsa,
            onion_key_ntor=onion_key_ntor,
            ed25519_identity=ed25519_identity,
            rsa1024_identity=rsa1024_identity,
            ipv6_addresses=ipv6_addresses,
            exit_policy_v4=exit_policy_v4,
            exit_policy_v6=exit_policy_v6,
            family_members=family_members,
            family_ids=family_ids,
            raw_descriptor=raw_descriptor,
            fetched_at=datetime.now(UTC),
        )
