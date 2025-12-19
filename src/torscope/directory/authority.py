"""
Directory authority information.

This module contains hardcoded information about Tor directory authorities.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class DirectoryAuthority:
    """Hardcoded directory authority information."""

    nickname: str
    ip: str
    dirport: int
    orport: int
    v3ident: str  # hex fingerprint

    # Optional
    bridge_authority: bool = False
    ipv6_address: Optional[str] = None

    @property
    def http_url(self) -> str:
        """Get base HTTP URL for directory requests."""
        return f"http://{self.ip}:{self.dirport}"

    @property
    def address(self) -> str:
        """Get formatted address string."""
        return f"{self.ip}:{self.dirport}"


# Hardcoded list of Tor directory authorities
# Source: https://spec.torproject.org/dir-list-spec.html
# Updated: December 2025
DIRECTORY_AUTHORITIES = [
    DirectoryAuthority(
        nickname="moria1",
        ip="128.31.0.34",
        dirport=9131,
        orport=9101,
        v3ident="D586D18309DED4CD6D57C18FDB97EFA96D330566",
    ),
    DirectoryAuthority(
        nickname="tor26",
        ip="86.59.21.38",
        dirport=80,
        orport=443,
        v3ident="14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4",
    ),
    DirectoryAuthority(
        nickname="dizum",
        ip="194.109.206.212",
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
    ),
    DirectoryAuthority(
        nickname="maatuska",
        ip="171.25.193.9",
        dirport=443,
        orport=80,
        v3ident="BD6A829255CB08E66FBE7D3748363586E46B3810",
        ipv6_address="[2001:67c:289c::9]:443",
    ),
    DirectoryAuthority(
        nickname="Faravahar",
        ip="154.35.175.225",
        dirport=80,
        orport=443,
        v3ident="CFCE4C0F26D94E3B3F1F834C0FBD37E9A4B47957",
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
    ),
]


def get_authority_by_nickname(nickname: str) -> Optional[DirectoryAuthority]:
    """Get directory authority by nickname (case-insensitive)."""
    for auth in DIRECTORY_AUTHORITIES:
        if auth.nickname.lower() == nickname.lower():
            return auth
    return None


def get_random_authority() -> DirectoryAuthority:
    """Get a random directory authority."""
    # pylint: disable-next=import-outside-toplevel
    import random

    return random.choice(DIRECTORY_AUTHORITIES)
