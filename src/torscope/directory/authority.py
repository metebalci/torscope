"""
Directory authority information.

This module provides information about Tor directory authorities,
parsed from auth_dirs.inc at runtime with hardcoded fallback.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Local auth_dirs.inc file (downloaded via `make update-authorities`)
AUTH_DIRS_FILE = Path(__file__).parent / "auth_dirs.inc"


@dataclass
class DirectoryAuthority:
    """Directory authority information."""

    nickname: str
    ip: str
    dirport: int
    orport: int
    v3ident: str  # hex fingerprint
    ipv6_address: Optional[str] = None

    @property
    def http_url(self) -> str:
        """Get base HTTP URL for directory requests."""
        return f"http://{self.ip}:{self.dirport}"

    @property
    def address(self) -> str:
        """Get formatted address string."""
        return f"{self.ip}:{self.dirport}"


# Hardcoded fallback list (used if fetch fails)
_FALLBACK_AUTHORITIES = [
    DirectoryAuthority(
        nickname="moria1",
        ip="128.31.0.39",
        dirport=9231,
        orport=9201,
        v3ident="F533C81CEF0BC0267857C99B2F471ADF249FA232",
    ),
    DirectoryAuthority(
        nickname="tor26",
        ip="217.196.147.77",
        dirport=80,
        orport=443,
        v3ident="2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C",
        ipv6_address="[2a02:16a8:662:2203::1]:443",
    ),
    DirectoryAuthority(
        nickname="dizum",
        ip="45.66.35.11",
        dirport=80,
        orport=443,
        v3ident="E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58",
    ),
    DirectoryAuthority(
        nickname="gabelmoo",
        ip="131.188.40.189",
        dirport=80,
        orport=443,
        v3ident="ED03BB616EB2F60BEC80151114BB25CEF515B226",
        ipv6_address="[2001:638:a000:4140::ffff:189]:443",
    ),
    DirectoryAuthority(
        nickname="dannenberg",
        ip="193.23.244.244",
        dirport=80,
        orport=443,
        v3ident="0232AF901C31A04EE9848595AF9BB7620D4C5B2E",
        ipv6_address="[2001:678:558:1000::244]:443",
    ),
    DirectoryAuthority(
        nickname="maatuska",
        ip="171.25.193.9",
        dirport=443,
        orport=80,
        v3ident="49015F787433103580E3B66A1707A00E60F2D15B",
        ipv6_address="[2001:67c:289c::9]:80",
    ),
    DirectoryAuthority(
        nickname="longclaw",
        ip="199.58.81.140",
        dirport=80,
        orport=443,
        v3ident="23D15D965BC35114467363C165C4F724B64B4F66",
    ),
    DirectoryAuthority(
        nickname="bastet",
        ip="204.13.164.118",
        dirport=80,
        orport=443,
        v3ident="27102BC123E7AF1D4741AE047E160C91ADC76B21",
        ipv6_address="[2620:13:4000:6000::1000:118]:443",
    ),
    DirectoryAuthority(
        nickname="faravahar",
        ip="216.218.219.41",
        dirport=80,
        orport=443,
        v3ident="70849B868D606BAECFB6128C5E3D782029AA394F",
    ),
]

# Cached authorities (populated on first access)
_cached_authorities: Optional[list[DirectoryAuthority]] = None


def _parse_auth_dirs(content: str) -> list[DirectoryAuthority]:
    """Parse authority information from auth_dirs.inc content."""
    authorities = []

    # Join continuation lines
    lines = []
    current = ""
    for line in content.split("\n"):
        line = line.strip()
        if not line or line.startswith("//") or line.startswith("/*"):
            continue
        current += line
        if line.endswith(","):
            lines.append(current)
            current = ""

    for line in lines:
        # Skip bridge authorities
        if "bridge" in line.lower():
            continue

        # Extract nickname
        nick_match = re.search(r'"(\w+)\s+orport=', line)
        if not nick_match:
            continue
        nickname = nick_match.group(1)

        # Extract orport
        orport_match = re.search(r"orport=(\d+)", line)
        orport = int(orport_match.group(1)) if orport_match else 0

        # Extract v3ident
        v3ident_match = re.search(r"v3ident=([A-F0-9]+)", line)
        if not v3ident_match:
            continue
        v3ident = v3ident_match.group(1)

        # Extract IPv4 address and dirport
        ipv4_match = re.search(r'"?\s*(\d+\.\d+\.\d+\.\d+):(\d+)', line)
        if not ipv4_match:
            continue
        ip = ipv4_match.group(1)
        dirport = int(ipv4_match.group(2))

        # Extract IPv6 address if present
        ipv6_match = re.search(r"\[([0-9a-fA-F:]+)\]:(\d+)", line)
        ipv6 = f"[{ipv6_match.group(1)}]:{ipv6_match.group(2)}" if ipv6_match else None

        authorities.append(
            DirectoryAuthority(
                nickname=nickname,
                ip=ip,
                dirport=dirport,
                orport=orport,
                v3ident=v3ident,
                ipv6_address=ipv6,
            )
        )

    return authorities


def _load_authorities_from_file() -> list[DirectoryAuthority]:
    """Load authorities from local auth_dirs.inc file."""
    try:
        if not AUTH_DIRS_FILE.exists():
            return []
        content = AUTH_DIRS_FILE.read_text()
        return _parse_auth_dirs(content)
    # pylint: disable-next=broad-exception-caught
    except Exception:
        return []


def get_authorities() -> list[DirectoryAuthority]:
    """Get list of directory authorities (from file or fallback)."""
    global _cached_authorities  # pylint: disable=global-statement

    if _cached_authorities is not None:
        return _cached_authorities

    # Try loading from local auth_dirs.inc file
    authorities = _load_authorities_from_file()

    # Use fallback if file missing or parse failed
    if not authorities:
        authorities = _FALLBACK_AUTHORITIES

    _cached_authorities = authorities
    return authorities


def get_authority_by_nickname(nickname: str) -> Optional[DirectoryAuthority]:
    """Get directory authority by nickname (case-insensitive)."""
    for auth in get_authorities():
        if auth.nickname.lower() == nickname.lower():
            return auth
    return None


def get_random_authority() -> DirectoryAuthority:
    """Get a random directory authority."""
    # pylint: disable-next=import-outside-toplevel
    import random

    return random.choice(get_authorities())


def get_shuffled_authorities() -> list[DirectoryAuthority]:
    """Get all directory authorities in random order."""
    # pylint: disable-next=import-outside-toplevel
    import random

    authorities = list(get_authorities())
    random.shuffle(authorities)
    return authorities
