"""
Data models for directory documents.

This module contains dataclasses for representing consensus documents,
relay descriptors, and related data structures.
"""

# pylint: disable=duplicate-code

import base64
from dataclasses import dataclass, field
from datetime import UTC, datetime


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
    version: str | None = None  # v line
    protocols: dict[str, list[int]] | None = None  # pr line
    bandwidth: int | None = None  # w line (Bandwidth=)
    measured: int | None = None  # w line (Measured=)
    unmeasured: bool = False  # w line (Unmeasured=1)
    exit_policy: str | None = None  # p line
    microdesc_hash: str | None = None  # m line (base64)
    ed25519_identity: str | None = None  # id ed25519 (base64)

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

    def allows_port(self, port: int) -> bool:
        """
        Check if this relay's exit policy allows a specific port.

        Uses the exit policy summary from the consensus "p" line.

        Args:
            port: Port number to check

        Returns:
            True if the port is allowed, False otherwise
        """
        # Import here to avoid circular imports
        # pylint: disable-next=import-outside-toplevel
        from torscope.directory.exit_policy import check_exit_policy

        return check_exit_policy(self.exit_policy, port)


@dataclass
class AuthorityEntry:
    """Represents a directory authority in consensus."""

    nickname: str
    identity: str  # hex fingerprint
    hostname: str
    ip: str
    dirport: int
    orport: int
    contact: str | None = None
    vote_digest: str | None = None  # SHA1 in hex


@dataclass
class DirectorySignature:
    """Represents a directory signature."""

    algorithm: str  # "sha256" or "sha1"
    identity: str  # hex fingerprint
    signing_key_digest: str  # hex
    signature: str  # base64
    verified: bool | None = None  # Verification result


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
    shared_rand_current: tuple[int, str] | None = None
    shared_rand_previous: tuple[int, str] | None = None

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
    fetched_at: datetime | None = None

    @property
    def is_valid(self) -> bool:
        """Check if consensus is currently valid."""
        now = datetime.now(UTC)
        # Ensure valid_after and valid_until are timezone-aware (they're UTC)
        valid_after = (
            self.valid_after.replace(tzinfo=UTC)
            if self.valid_after.tzinfo is None
            else self.valid_after
        )
        valid_until = (
            self.valid_until.replace(tzinfo=UTC)
            if self.valid_until.tzinfo is None
            else self.valid_until
        )
        return valid_after <= now <= valid_until

    @property
    def is_fresh(self) -> bool:
        """Check if consensus is fresh."""
        now = datetime.now(UTC)
        # Ensure datetimes are timezone-aware (they're UTC)
        valid_after = (
            self.valid_after.replace(tzinfo=UTC)
            if self.valid_after.tzinfo is None
            else self.valid_after
        )
        fresh_until = (
            self.fresh_until.replace(tzinfo=UTC)
            if self.fresh_until.tzinfo is None
            else self.fresh_until
        )
        return valid_after <= now <= fresh_until

    @property
    def total_routers(self) -> int:
        """Get total number of routers in consensus."""
        return len(self.routers)

    @property
    def verified_signatures(self) -> int:
        """Get count of verified signatures."""
        return sum(1 for sig in self.signatures if sig.verified is True)

    def get_routers_by_flag(self, flag: str) -> list[RouterStatusEntry]:
        """Get all routers with a specific flag."""
        return [r for r in self.routers if r.has_flag(flag)]

    def verify_signatures(self, certificates: list["KeyCertificate"]) -> int:
        """
        Verify consensus signatures against authority key certificates.

        Args:
            certificates: List of authority key certificates

        Returns:
            Number of successfully verified signatures
        """
        # pylint: disable-next=import-outside-toplevel
        from torscope.crypto import extract_signed_portion, verify_consensus_signature

        # Build a map of signing key fingerprint -> certificate
        cert_map: dict[str, KeyCertificate] = {}
        for key_cert in certificates:
            try:
                signing_fp = key_cert.signing_key_fingerprint
                cert_map[signing_fp] = key_cert
            # pylint: disable-next=broad-exception-caught
            except Exception:
                continue

        verified_count = 0

        for sig in self.signatures:
            # Find the certificate for this signature
            signing_key_digest = sig.signing_key_digest.upper()
            matching_cert = cert_map.get(signing_key_digest)

            if matching_cert is None:
                sig.verified = False
                continue

            # Extract the signed portion for this signature
            signed_data = extract_signed_portion(
                self.raw_document,
                sig.identity,
                sig.algorithm,
            )

            if signed_data is None:
                sig.verified = False
                continue

            # Verify the signature
            is_valid = verify_consensus_signature(
                matching_cert.signing_key,
                sig.signature,
                signed_data,
                sig.algorithm,
            )

            sig.verified = is_valid
            if is_valid:
                verified_count += 1

        return verified_count


@dataclass
class Microdescriptor:
    """Represents a parsed microdescriptor."""

    # Identifying hash (SHA256 of descriptor content)
    digest: str  # base64-encoded

    # Keys
    onion_key_rsa: str | None = None  # PEM format (TAP, legacy)
    onion_key_ntor: str | None = None  # base64-encoded curve25519
    ed25519_identity: str | None = None  # base64 (id ed25519)
    rsa1024_identity: str | None = None  # base64 (id rsa1024)

    # Network
    ipv6_addresses: list[str] = field(default_factory=list)

    # Exit policy
    exit_policy_v4: str | None = None  # "accept" or "reject" + portlist
    exit_policy_v6: str | None = None

    # Family
    family_members: list[str] = field(default_factory=list)
    family_ids: list[str] = field(default_factory=list)

    # Metadata
    raw_descriptor: str = ""
    fetched_at: datetime | None = None

    @property
    def is_exit(self) -> bool:
        """Check if this relay allows exits."""
        return self.exit_policy_v4 is not None and self.exit_policy_v4.startswith("accept")


@dataclass
class ServerDescriptor:
    """Represents a full server descriptor."""

    # Required fields
    nickname: str
    fingerprint: str  # hex-encoded identity fingerprint
    published: datetime
    ip: str
    orport: int

    # Optional addressing
    dirport: int = 0
    ipv6_addresses: list[str] = field(default_factory=list)

    # Platform/version info
    platform: str | None = None
    tor_version: str | None = None

    # Bandwidth
    bandwidth_avg: int = 0  # bytes/sec
    bandwidth_burst: int = 0
    bandwidth_observed: int = 0

    # Uptime
    uptime: int | None = None  # seconds

    # Contact
    contact: str | None = None

    # Exit policy
    exit_policy: list[str] = field(default_factory=list)

    # Keys
    onion_key: str | None = None  # RSA public key (PEM)
    signing_key: str | None = None  # RSA public key (PEM)
    ntor_onion_key: str | None = None  # curve25519 (base64)

    # Family
    family: list[str] = field(default_factory=list)

    # Flags/features
    hibernating: bool = False
    allow_single_hop_exits: bool = False
    caches_extra_info: bool = False
    tunnelled_dir_server: bool = False

    # Protocols
    protocols: dict[str, list[int]] | None = None

    # Raw descriptor
    raw_descriptor: str = ""

    @property
    def bandwidth_mbps(self) -> float:
        """Get observed bandwidth in MB/s."""
        return self.bandwidth_observed / 1_000_000

    @property
    def uptime_days(self) -> float | None:
        """Get uptime in days."""
        if self.uptime is None:
            return None
        return self.uptime / 86400


@dataclass
class BandwidthHistory:
    """Represents bandwidth history data from extra-info descriptors."""

    timestamp: datetime  # End of most recent interval
    interval_seconds: int  # Interval length
    values: list[int] = field(default_factory=list)  # Bytes per interval, oldest to newest

    @property
    def total_bytes(self) -> int:
        """Get total bytes across all intervals."""
        return sum(self.values)

    @property
    def average_bytes_per_second(self) -> float:
        """Get average bytes per second."""
        if not self.values or self.interval_seconds == 0:
            return 0.0
        return self.total_bytes / (len(self.values) * self.interval_seconds)


@dataclass
class ExtraInfoDescriptor:
    """Represents an extra-info descriptor with relay statistics."""

    # Identity
    nickname: str
    fingerprint: str  # hex-encoded
    published: datetime

    # Bandwidth history
    write_history: BandwidthHistory | None = None
    read_history: BandwidthHistory | None = None
    dirreq_write_history: BandwidthHistory | None = None
    dirreq_read_history: BandwidthHistory | None = None

    # GeoIP database digests
    geoip_db_digest: str | None = None
    geoip6_db_digest: str | None = None

    # Directory request statistics
    dirreq_stats_end: datetime | None = None
    dirreq_v3_ips: dict[str, int] = field(default_factory=dict)  # country -> count
    dirreq_v3_reqs: dict[str, int] = field(default_factory=dict)
    dirreq_v3_resp: dict[str, int] = field(default_factory=dict)  # status -> count

    # Entry statistics (for guards)
    entry_stats_end: datetime | None = None
    entry_ips: dict[str, int] = field(default_factory=dict)  # country -> count

    # Exit statistics
    exit_stats_end: datetime | None = None
    exit_kibibytes_written: dict[str, int] = field(default_factory=dict)  # port -> KiB
    exit_kibibytes_read: dict[str, int] = field(default_factory=dict)
    exit_streams_opened: dict[str, int] = field(default_factory=dict)  # port -> count

    # Cell statistics
    cell_stats_end: datetime | None = None
    cell_processed_cells: list[float] = field(default_factory=list)  # deciles
    cell_queued_cells: list[float] = field(default_factory=list)
    cell_time_in_queue: list[int] = field(default_factory=list)  # milliseconds

    # Hidden service statistics
    hidserv_stats_end: datetime | None = None
    hidserv_rend_relayed_cells: int | None = None
    hidserv_dir_onions_seen: int | None = None

    # Raw descriptor
    raw_descriptor: str = ""

    @property
    def total_written_bytes(self) -> int:
        """Get total bytes written from history."""
        return self.write_history.total_bytes if self.write_history else 0

    @property
    def total_read_bytes(self) -> int:
        """Get total bytes read from history."""
        return self.read_history.total_bytes if self.read_history else 0

    @property
    def is_exit(self) -> bool:
        """Check if this relay has exit statistics."""
        return bool(self.exit_kibibytes_written or self.exit_streams_opened)

    @property
    def is_guard(self) -> bool:
        """Check if this relay has entry/guard statistics."""
        return bool(self.entry_ips)

    @property
    def is_directory(self) -> bool:
        """Check if this relay serves directory requests."""
        return bool(self.dirreq_v3_ips or self.dirreq_v3_reqs)


@dataclass
class KeyCertificate:
    """Represents an authority key certificate.

    Authority key certificates bind a long-term identity key to a
    medium-term signing key used for signing consensus documents.
    """

    # Protocol version (must be 3)
    version: int

    # Authority fingerprint (SHA1 of identity key, uppercase hex)
    fingerprint: str

    # Validity period
    published: datetime
    expires: datetime

    # RSA public keys (PEM format including headers)
    identity_key: str  # Long-term authority identity key
    signing_key: str  # Medium-term signing key

    # Optional fields
    address: str | None = None  # IP:port of directory service
    dir_key_crosscert: str | None = None  # Cross-certification signature
    dir_key_certification: str | None = None  # Final signature by identity key

    # Raw certificate
    raw_certificate: str = ""

    @property
    def signing_key_fingerprint(self) -> str:
        """Get SHA1 fingerprint of signing key (uppercase hex)."""
        # pylint: disable-next=import-outside-toplevel
        from torscope.crypto import compute_rsa_key_fingerprint

        return compute_rsa_key_fingerprint(self.signing_key)
