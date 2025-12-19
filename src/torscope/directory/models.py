"""
Data models for directory documents.

This module contains dataclasses for representing consensus documents,
relay descriptors, and related data structures.
"""

import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class RouterStatusEntry:
    """Represents a single router entry in consensus (r line + associated lines)."""

    nickname: str
    identity: str  # base64-encoded fingerprint
    digest: str  # base64-encoded descriptor digest
    published: datetime
    ip: str
    orport: int
    dirport: int

    # Optional fields
    ipv6_addresses: list[str] = field(default_factory=list)  # a lines
    flags: list[str] = field(default_factory=list)  # s line
    version: Optional[str] = None  # v line
    protocols: Optional[dict[str, list[int]]] = None  # pr line
    bandwidth: Optional[int] = None  # w line (Bandwidth=)
    measured: Optional[int] = None  # w line (Measured=)
    unmeasured: bool = False  # w line (Unmeasured=1)
    exit_policy: Optional[str] = None  # p line
    microdesc_hash: Optional[str] = None  # m line (base64)

    @property
    def fingerprint(self) -> str:
        """Get hex-encoded fingerprint."""
        # Decode base64 and convert to hex
        try:
            decoded = base64.b64decode(self.identity + "=")
            return decoded.hex().upper()
        # pylint: disable-next=broad-exception-caught
        except Exception:
            return self.identity

    @property
    def short_fingerprint(self) -> str:
        """Get shortened fingerprint (first 8 hex chars)."""
        fp = self.fingerprint
        return fp[:8] if len(fp) >= 8 else fp

    def has_flag(self, flag: str) -> bool:
        """Check if relay has specific flag."""
        return flag in self.flags

    @property
    def is_exit(self) -> bool:
        """Check if relay is an exit relay."""
        return self.has_flag("Exit")

    @property
    def is_guard(self) -> bool:
        """Check if relay is a guard relay."""
        return self.has_flag("Guard")

    @property
    def is_stable(self) -> bool:
        """Check if relay is stable."""
        return self.has_flag("Stable")

    @property
    def is_fast(self) -> bool:
        """Check if relay is fast."""
        return self.has_flag("Fast")


@dataclass
class AuthorityEntry:
    """Represents a directory authority in consensus."""

    nickname: str
    identity: str  # hex fingerprint
    hostname: str
    ip: str
    dirport: int
    orport: int
    contact: Optional[str] = None
    vote_digest: Optional[str] = None  # SHA1 in hex


@dataclass
class DirectorySignature:
    """Represents a directory signature."""

    algorithm: str  # "sha256" or "sha1"
    identity: str  # hex fingerprint
    signing_key_digest: str  # hex
    signature: str  # base64
    verified: Optional[bool] = None  # Verification result


@dataclass
class ConsensusDocument:
    """Represents a parsed network consensus document."""

    # Preamble
    version: int  # network-status-version
    vote_status: str  # "consensus"
    consensus_method: int  # Method number
    valid_after: datetime
    fresh_until: datetime
    valid_until: datetime
    voting_delay: tuple[int, int]  # vote seconds, dist seconds
    client_versions: list[str] = field(default_factory=list)
    server_versions: list[str] = field(default_factory=list)
    known_flags: list[str] = field(default_factory=list)
    params: dict[str, int] = field(default_factory=dict)  # Network parameters
    shared_rand_current: Optional[tuple[int, str]] = None
    shared_rand_previous: Optional[tuple[int, str]] = None

    # Authorities
    authorities: list[AuthorityEntry] = field(default_factory=list)

    # Routers
    routers: list[RouterStatusEntry] = field(default_factory=list)

    # Footer
    bandwidth_weights: dict[str, int] = field(default_factory=dict)

    # Signatures
    signatures: list[DirectorySignature] = field(default_factory=list)

    # Metadata
    raw_document: str = ""  # Original text
    fetched_from: str = ""  # Authority nickname
    fetched_at: Optional[datetime] = None

    @property
    def is_valid(self) -> bool:
        """Check if consensus is currently valid."""
        now = datetime.now(timezone.utc)
        return self.valid_after <= now <= self.valid_until

    @property
    def is_fresh(self) -> bool:
        """Check if consensus is fresh."""
        now = datetime.now(timezone.utc)
        return self.valid_after <= now <= self.fresh_until

    @property
    def total_relays(self) -> int:
        """Get total number of relays in consensus."""
        return len(self.routers)

    @property
    def verified_signatures(self) -> int:
        """Get count of verified signatures."""
        return sum(1 for sig in self.signatures if sig.verified is True)

    def get_relays_by_flag(self, flag: str) -> list[RouterStatusEntry]:
        """Get all relays with a specific flag."""
        return [r for r in self.routers if r.has_flag(flag)]


@dataclass
class Microdescriptor:
    """Represents a parsed microdescriptor."""

    # Identifying hash (SHA256 of descriptor content)
    digest: str  # base64-encoded

    # Keys
    onion_key_rsa: Optional[str] = None  # PEM format (TAP, legacy)
    onion_key_ntor: Optional[str] = None  # base64-encoded curve25519
    ed25519_identity: Optional[str] = None  # base64

    # Network
    ipv6_addresses: list[str] = field(default_factory=list)

    # Exit policy
    exit_policy_v4: Optional[str] = None  # "accept" or "reject" + portlist
    exit_policy_v6: Optional[str] = None

    # Protocols
    protocols: Optional[dict[str, list[int]]] = None

    # Family
    family_members: list[str] = field(default_factory=list)
    family_ids: list[str] = field(default_factory=list)

    # Metadata
    raw_descriptor: str = ""
    fetched_at: Optional[datetime] = None

    @property
    def is_exit(self) -> bool:
        """Check if this relay allows exits."""
        return self.exit_policy_v4 is not None and self.exit_policy_v4.startswith("accept")
