"""
Server descriptor parsing.

This module provides functionality to parse Tor server descriptors.
"""

# pylint: disable=duplicate-code

import re
from datetime import UTC, datetime

from torscope.directory.models import ServerDescriptor


class ServerDescriptorParser:
    """Parser for Tor server descriptors."""

    @staticmethod
    def parse(content: bytes) -> list[ServerDescriptor]:
        """
        Parse server descriptors from raw bytes.

        Args:
            content: Raw descriptor bytes (may contain multiple descriptors)

        Returns:
            List of parsed ServerDescriptor objects
        """
        text = content.decode("utf-8", errors="replace")
        return ServerDescriptorParser.parse_text(text)

    @staticmethod
    def parse_text(text: str) -> list[ServerDescriptor]:
        """
        Parse server descriptors from text.

        Args:
            text: Descriptor text (may contain multiple descriptors)

        Returns:
            List of parsed ServerDescriptor objects
        """
        descriptors = []

        # Split into individual descriptors
        # Each starts with "@type server-descriptor" or "router "
        raw_descriptors = re.split(r"(?=^router\s)", text, flags=re.MULTILINE)

        for raw in raw_descriptors:
            raw = raw.strip()
            if not raw or not raw.startswith("router "):
                continue

            try:
                descriptor = ServerDescriptorParser._parse_single(raw)
                if descriptor:
                    descriptors.append(descriptor)
            # pylint: disable-next=broad-exception-caught
            except Exception:
                continue

        return descriptors

    @staticmethod
    def _parse_single(text: str) -> ServerDescriptor | None:
        """Parse a single server descriptor."""
        lines = text.split("\n")
        i = 0

        # Parse router line (required)
        # router <nickname> <ip> <orport> <socksport> <dirport>
        if not lines[0].startswith("router "):
            return None

        parts = lines[0].split()
        if len(parts) < 6:
            return None

        nickname = parts[1]
        ip = parts[2]
        orport = int(parts[3])
        # socksport = int(parts[4])  # deprecated, always 0
        dirport = int(parts[5])

        # Initialize with defaults
        fingerprint = ""
        published = datetime.now(UTC)
        platform: str | None = None
        tor_version: str | None = None
        bandwidth_avg = 0
        bandwidth_burst = 0
        bandwidth_observed = 0
        uptime: int | None = None
        contact: str | None = None
        exit_policy: list[str] = []
        onion_key: str | None = None
        signing_key: str | None = None
        ntor_onion_key: str | None = None
        family: list[str] = []
        ipv6_addresses: list[str] = []
        hibernating = False
        allow_single_hop_exits = False
        caches_extra_info = False
        tunnelled_dir_server = False
        protocols: dict[str, list[int]] | None = None

        i = 1
        while i < len(lines):
            line = lines[i].strip()

            if line.startswith("fingerprint "):
                # fingerprint <fp> (with spaces)
                fp_parts = line[12:].split()
                fingerprint = "".join(fp_parts).upper()

            elif line.startswith("published "):
                # published YYYY-MM-DD HH:MM:SS
                try:
                    dt_str = line[10:].strip()
                    published = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
                    published = published.replace(tzinfo=UTC)
                except ValueError:
                    pass

            elif line.startswith("platform "):
                platform = line[9:]
                # Extract Tor version if present
                if "Tor " in platform:
                    match = re.search(r"Tor (\S+)", platform)
                    if match:
                        tor_version = match.group(1)

            elif line.startswith("bandwidth "):
                # bandwidth <avg> <burst> <observed>
                bw_parts = line[10:].split()
                if len(bw_parts) >= 3:
                    bandwidth_avg = int(bw_parts[0])
                    bandwidth_burst = int(bw_parts[1])
                    bandwidth_observed = int(bw_parts[2])

            elif line.startswith("uptime "):
                try:
                    uptime = int(line[7:])
                except ValueError:
                    pass

            elif line.startswith("contact "):
                contact = line[8:]

            elif line.startswith("family "):
                family = line[7:].split()

            elif line.startswith("or-address "):
                # or-address [ipv6]:port or ip:port
                addr = line[11:]
                if "[" in addr:  # IPv6
                    ipv6_addresses.append(addr)

            elif line in ("accept", "reject") or line.startswith(("accept ", "reject ")):
                exit_policy.append(line)

            elif line.startswith("onion-key"):
                # Multi-line RSA key
                key_lines = ["-----BEGIN RSA PUBLIC KEY-----"]
                i += 1
                while i < len(lines) and not lines[i].startswith("-----END"):
                    key_lines.append(lines[i].strip())
                    i += 1
                if i < len(lines):
                    key_lines.append("-----END RSA PUBLIC KEY-----")
                onion_key = "\n".join(key_lines)

            elif line.startswith("signing-key"):
                # Multi-line RSA key
                key_lines = ["-----BEGIN RSA PUBLIC KEY-----"]
                i += 1
                while i < len(lines) and not lines[i].startswith("-----END"):
                    key_lines.append(lines[i].strip())
                    i += 1
                if i < len(lines):
                    key_lines.append("-----END RSA PUBLIC KEY-----")
                signing_key = "\n".join(key_lines)

            elif line.startswith("ntor-onion-key "):
                ntor_onion_key = line[15:]

            elif line == "hibernating 1":
                hibernating = True

            elif line == "allow-single-hop-exits":
                allow_single_hop_exits = True

            elif line == "caches-extra-info":
                caches_extra_info = True

            elif line == "tunnelled-dir-server":
                tunnelled_dir_server = True

            elif line.startswith("proto "):
                protocols = ServerDescriptorParser._parse_protocols(line[6:])

            i += 1

        return ServerDescriptor(
            nickname=nickname,
            fingerprint=fingerprint,
            published=published,
            ip=ip,
            orport=orport,
            dirport=dirport,
            ipv6_addresses=ipv6_addresses,
            platform=platform,
            tor_version=tor_version,
            bandwidth_avg=bandwidth_avg,
            bandwidth_burst=bandwidth_burst,
            bandwidth_observed=bandwidth_observed,
            uptime=uptime,
            contact=contact,
            exit_policy=exit_policy,
            onion_key=onion_key,
            signing_key=signing_key,
            ntor_onion_key=ntor_onion_key,
            family=family,
            hibernating=hibernating,
            allow_single_hop_exits=allow_single_hop_exits,
            caches_extra_info=caches_extra_info,
            tunnelled_dir_server=tunnelled_dir_server,
            protocols=protocols,
            raw_descriptor=text,
        )

    @staticmethod
    def _parse_protocols(proto_str: str) -> dict[str, list[int]]:
        """Parse protocol version string like 'Cons=1-2 Desc=1-2 ...'"""
        protocols: dict[str, list[int]] = {}

        for item in proto_str.split():
            if "=" not in item:
                continue
            name, versions = item.split("=", 1)
            version_list: list[int] = []

            for part in versions.split(","):
                if "-" in part:
                    start, end = part.split("-", 1)
                    version_list.extend(range(int(start), int(end) + 1))
                else:
                    version_list.append(int(part))

            protocols[name] = version_list

        return protocols
