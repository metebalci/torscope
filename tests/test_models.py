"""Tests for directory models."""

import base64
from datetime import UTC, datetime, timedelta

from torscope.directory.models import (
    AuthorityEntry,
    ConsensusDocument,
    DirectorySignature,
    Microdescriptor,
    RouterStatusEntry,
)


class TestRouterStatusEntry:
    """Tests for RouterStatusEntry model."""

    def test_basic_router_creation(self):
        """Test creating a basic router entry."""
        router = RouterStatusEntry(
            nickname="TestRelay",
            identity="AAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            digest="BBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            published=datetime(2024, 1, 15, 10, 0, 0),
            ip="192.0.2.1",
            orport=9001,
            dirport=9030,
        )
        assert router.nickname == "TestRelay"
        assert router.ip == "192.0.2.1"
        assert router.orport == 9001
        assert router.dirport == 9030

    def test_fingerprint_property(self):
        """Test fingerprint property converts base64 to hex."""
        # Create a base64-encoded identity (20 bytes for SHA-1)
        identity_bytes = b"12345678901234567890"
        identity_b64 = base64.b64encode(identity_bytes).decode("utf-8").rstrip("=")

        router = RouterStatusEntry(
            nickname="TestRelay",
            identity=identity_b64,
            digest="BBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            published=datetime(2024, 1, 15, 10, 0, 0),
            ip="192.0.2.1",
            orport=9001,
            dirport=9030,
        )

        expected_hex = identity_bytes.hex().upper()
        assert router.fingerprint == expected_hex

    def test_short_fingerprint_property(self):
        """Test short_fingerprint returns first 8 characters."""
        identity_bytes = b"12345678901234567890"
        identity_b64 = base64.b64encode(identity_bytes).decode("utf-8").rstrip("=")

        router = RouterStatusEntry(
            nickname="TestRelay",
            identity=identity_b64,
            digest="BBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            published=datetime(2024, 1, 15, 10, 0, 0),
            ip="192.0.2.1",
            orport=9001,
            dirport=9030,
        )

        expected_short = identity_bytes.hex().upper()[:8]
        assert router.short_fingerprint == expected_short

    def test_has_flag_method(self):
        """Test has_flag method."""
        router = RouterStatusEntry(
            nickname="TestRelay",
            identity="AAAA",
            digest="BBBB",
            published=datetime(2024, 1, 15, 10, 0, 0),
            ip="192.0.2.1",
            orport=9001,
            dirport=9030,
            flags=["Exit", "Fast", "Running", "Stable", "Valid"],
        )

        assert router.has_flag("Exit") is True
        assert router.has_flag("Fast") is True
        assert router.has_flag("Guard") is False
        assert router.has_flag("NonExistent") is False

    def test_is_exit_property(self):
        """Test is_exit property."""
        exit_router = RouterStatusEntry(
            nickname="ExitRelay",
            identity="AAAA",
            digest="BBBB",
            published=datetime(2024, 1, 15, 10, 0, 0),
            ip="192.0.2.1",
            orport=9001,
            dirport=9030,
            flags=["Exit", "Fast", "Running"],
        )
        assert exit_router.is_exit is True

        non_exit_router = RouterStatusEntry(
            nickname="GuardRelay",
            identity="AAAA",
            digest="BBBB",
            published=datetime(2024, 1, 15, 10, 0, 0),
            ip="192.0.2.1",
            orport=9001,
            dirport=9030,
            flags=["Guard", "Fast", "Running"],
        )
        assert non_exit_router.is_exit is False

    def test_is_guard_property(self):
        """Test is_guard property."""
        guard_router = RouterStatusEntry(
            nickname="GuardRelay",
            identity="AAAA",
            digest="BBBB",
            published=datetime(2024, 1, 15, 10, 0, 0),
            ip="192.0.2.1",
            orport=9001,
            dirport=9030,
            flags=["Guard", "Fast", "Running"],
        )
        assert guard_router.is_guard is True

        non_guard_router = RouterStatusEntry(
            nickname="ExitRelay",
            identity="AAAA",
            digest="BBBB",
            published=datetime(2024, 1, 15, 10, 0, 0),
            ip="192.0.2.1",
            orport=9001,
            dirport=9030,
            flags=["Exit", "Fast", "Running"],
        )
        assert non_guard_router.is_guard is False

    def test_is_stable_property(self):
        """Test is_stable property."""
        stable_router = RouterStatusEntry(
            nickname="StableRelay",
            identity="AAAA",
            digest="BBBB",
            published=datetime(2024, 1, 15, 10, 0, 0),
            ip="192.0.2.1",
            orport=9001,
            dirport=9030,
            flags=["Stable", "Fast", "Running"],
        )
        assert stable_router.is_stable is True

    def test_is_fast_property(self):
        """Test is_fast property."""
        fast_router = RouterStatusEntry(
            nickname="FastRelay",
            identity="AAAA",
            digest="BBBB",
            published=datetime(2024, 1, 15, 10, 0, 0),
            ip="192.0.2.1",
            orport=9001,
            dirport=9030,
            flags=["Fast", "Running"],
        )
        assert fast_router.is_fast is True

    def test_optional_fields_default_values(self):
        """Test optional fields have correct default values."""
        router = RouterStatusEntry(
            nickname="TestRelay",
            identity="AAAA",
            digest="BBBB",
            published=datetime(2024, 1, 15, 10, 0, 0),
            ip="192.0.2.1",
            orport=9001,
            dirport=9030,
        )

        assert router.ipv6_addresses == []
        assert router.flags == []
        assert router.version is None
        assert router.protocols is None
        assert router.bandwidth is None
        assert router.measured is None
        assert router.unmeasured is False
        assert router.exit_policy is None
        assert router.microdesc_hash is None

    def test_router_with_all_fields(self):
        """Test router entry with all optional fields populated."""
        router = RouterStatusEntry(
            nickname="CompleteRelay",
            identity="AAAA",
            digest="BBBB",
            published=datetime(2024, 1, 15, 10, 0, 0),
            ip="192.0.2.1",
            orport=9001,
            dirport=9030,
            ipv6_addresses=["[2001:db8::1]:9001"],
            flags=["Exit", "Fast", "Guard", "Running", "Stable", "Valid"],
            version="Tor 0.4.8.1",
            protocols={"Link": [1, 2, 3, 4, 5], "Cons": [1, 2]},
            bandwidth=10000,
            measured=9500,
            unmeasured=False,
            exit_policy="accept 80,443",
            microdesc_hash="sha256=dGVzdA==",
        )

        assert router.nickname == "CompleteRelay"
        assert router.ipv6_addresses == ["[2001:db8::1]:9001"]
        assert len(router.flags) == 6
        assert router.version == "Tor 0.4.8.1"
        assert router.protocols == {"Link": [1, 2, 3, 4, 5], "Cons": [1, 2]}
        assert router.bandwidth == 10000
        assert router.measured == 9500
        assert router.unmeasured is False
        assert router.exit_policy == "accept 80,443"
        assert router.microdesc_hash == "sha256=dGVzdA=="


class TestAuthorityEntry:
    """Tests for AuthorityEntry model."""

    def test_basic_authority_creation(self):
        """Test creating an authority entry."""
        auth = AuthorityEntry(
            nickname="moria1",
            identity="D586D18309DED4CD6D57C18FDB97EFA96D330566",
            hostname="128.31.0.34",
            ip="128.31.0.34",
            dirport=9131,
            orport=9101,
        )

        assert auth.nickname == "moria1"
        assert auth.identity == "D586D18309DED4CD6D57C18FDB97EFA96D330566"
        assert auth.hostname == "128.31.0.34"
        assert auth.ip == "128.31.0.34"
        assert auth.dirport == 9131
        assert auth.orport == 9101

    def test_optional_fields(self):
        """Test optional fields default to None."""
        auth = AuthorityEntry(
            nickname="test",
            identity="ABC123",
            hostname="example.com",
            ip="192.0.2.1",
            dirport=9131,
            orport=9101,
        )

        assert auth.contact is None
        assert auth.vote_digest is None

    def test_authority_with_optional_fields(self):
        """Test authority with optional fields populated."""
        auth = AuthorityEntry(
            nickname="test",
            identity="ABC123",
            hostname="example.com",
            ip="192.0.2.1",
            dirport=9131,
            orport=9101,
            contact="authority@example.com",
            vote_digest="0123456789ABCDEF0123456789ABCDEF01234567",
        )

        assert auth.contact == "authority@example.com"
        assert auth.vote_digest == "0123456789ABCDEF0123456789ABCDEF01234567"


class TestDirectorySignature:
    """Tests for DirectorySignature model."""

    def test_basic_signature_creation(self):
        """Test creating a directory signature."""
        sig = DirectorySignature(
            algorithm="sha256",
            identity="D586D18309DED4CD6D57C18FDB97EFA96D330566",
            signing_key_digest="0123456789ABCDEF",
            signature="dGVzdHNpZ25hdHVyZQ==",
        )

        assert sig.algorithm == "sha256"
        assert sig.identity == "D586D18309DED4CD6D57C18FDB97EFA96D330566"
        assert sig.signing_key_digest == "0123456789ABCDEF"
        assert sig.signature == "dGVzdHNpZ25hdHVyZQ=="

    def test_verified_defaults_to_none(self):
        """Test verified field defaults to None."""
        sig = DirectorySignature(
            algorithm="sha256",
            identity="ABC123",
            signing_key_digest="DEF456",
            signature="test",
        )

        assert sig.verified is None

    def test_signature_with_verification_result(self):
        """Test signature with verification result."""
        sig_verified = DirectorySignature(
            algorithm="sha256",
            identity="ABC123",
            signing_key_digest="DEF456",
            signature="test",
            verified=True,
        )
        assert sig_verified.verified is True

        sig_failed = DirectorySignature(
            algorithm="sha1",
            identity="ABC123",
            signing_key_digest="DEF456",
            signature="test",
            verified=False,
        )
        assert sig_failed.verified is False


class TestConsensusDocument:
    """Tests for ConsensusDocument model."""

    def test_basic_consensus_creation(self):
        """Test creating a basic consensus document."""
        now = datetime.now(UTC)
        consensus = ConsensusDocument(
            version=3,
            vote_status="consensus",
            consensus_method=28,
            valid_after=now,
            fresh_until=now + timedelta(hours=1),
            valid_until=now + timedelta(hours=3),
            voting_delay=(300, 300),
        )

        assert consensus.version == 3
        assert consensus.vote_status == "consensus"
        assert consensus.consensus_method == 28
        assert consensus.voting_delay == (300, 300)

    def test_is_valid_property(self):
        """Test is_valid property checks current time."""
        now = datetime.now(UTC)

        # Valid consensus
        valid_consensus = ConsensusDocument(
            version=3,
            vote_status="consensus",
            consensus_method=28,
            valid_after=now - timedelta(minutes=30),
            fresh_until=now + timedelta(minutes=30),
            valid_until=now + timedelta(hours=2),
            voting_delay=(300, 300),
        )
        assert valid_consensus.is_valid is True

        # Expired consensus
        expired_consensus = ConsensusDocument(
            version=3,
            vote_status="consensus",
            consensus_method=28,
            valid_after=now - timedelta(hours=5),
            fresh_until=now - timedelta(hours=4),
            valid_until=now - timedelta(hours=3),
            voting_delay=(300, 300),
        )
        assert expired_consensus.is_valid is False

        # Future consensus
        future_consensus = ConsensusDocument(
            version=3,
            vote_status="consensus",
            consensus_method=28,
            valid_after=now + timedelta(hours=1),
            fresh_until=now + timedelta(hours=2),
            valid_until=now + timedelta(hours=3),
            voting_delay=(300, 300),
        )
        assert future_consensus.is_valid is False

    def test_is_fresh_property(self):
        """Test is_fresh property checks freshness time."""
        now = datetime.now(UTC)

        # Fresh consensus
        fresh_consensus = ConsensusDocument(
            version=3,
            vote_status="consensus",
            consensus_method=28,
            valid_after=now - timedelta(minutes=30),
            fresh_until=now + timedelta(minutes=30),
            valid_until=now + timedelta(hours=2),
            voting_delay=(300, 300),
        )
        assert fresh_consensus.is_fresh is True

        # Stale but valid consensus
        stale_consensus = ConsensusDocument(
            version=3,
            vote_status="consensus",
            consensus_method=28,
            valid_after=now - timedelta(hours=2),
            fresh_until=now - timedelta(hours=1),
            valid_until=now + timedelta(hours=1),
            voting_delay=(300, 300),
        )
        assert stale_consensus.is_fresh is False

    def test_total_routers_property(self):
        """Test total_routers property."""
        consensus = ConsensusDocument(
            version=3,
            vote_status="consensus",
            consensus_method=28,
            valid_after=datetime.now(UTC),
            fresh_until=datetime.now(UTC),
            valid_until=datetime.now(UTC),
            voting_delay=(300, 300),
        )

        assert consensus.total_routers == 0

        # Add some routers
        for i in range(5):
            router = RouterStatusEntry(
                nickname=f"Router{i}",
                identity=f"ID{i}",
                digest=f"DIGEST{i}",
                published=datetime.now(UTC),
                ip="192.0.2.1",
                orport=9001,
                dirport=9030,
            )
            consensus.routers.append(router)

        assert consensus.total_routers == 5

    def test_verified_signatures_property(self):
        """Test verified_signatures property counts verified signatures."""
        consensus = ConsensusDocument(
            version=3,
            vote_status="consensus",
            consensus_method=28,
            valid_after=datetime.now(UTC),
            fresh_until=datetime.now(UTC),
            valid_until=datetime.now(UTC),
            voting_delay=(300, 300),
        )

        assert consensus.verified_signatures == 0

        # Add signatures with different verification states
        consensus.signatures.append(
            DirectorySignature(
                algorithm="sha256",
                identity="ID1",
                signing_key_digest="KEY1",
                signature="SIG1",
                verified=True,
            )
        )
        consensus.signatures.append(
            DirectorySignature(
                algorithm="sha256",
                identity="ID2",
                signing_key_digest="KEY2",
                signature="SIG2",
                verified=False,
            )
        )
        consensus.signatures.append(
            DirectorySignature(
                algorithm="sha256",
                identity="ID3",
                signing_key_digest="KEY3",
                signature="SIG3",
                verified=True,
            )
        )
        consensus.signatures.append(
            DirectorySignature(
                algorithm="sha256",
                identity="ID4",
                signing_key_digest="KEY4",
                signature="SIG4",
                verified=None,
            )
        )

        assert consensus.verified_signatures == 2

    def test_get_routers_by_flag(self):
        """Test get_routers_by_flag method."""
        consensus = ConsensusDocument(
            version=3,
            vote_status="consensus",
            consensus_method=28,
            valid_after=datetime.now(UTC),
            fresh_until=datetime.now(UTC),
            valid_until=datetime.now(UTC),
            voting_delay=(300, 300),
        )

        # Add routers with different flags
        consensus.routers.append(
            RouterStatusEntry(
                nickname="ExitRouter",
                identity="ID1",
                digest="D1",
                published=datetime.now(UTC),
                ip="192.0.2.1",
                orport=9001,
                dirport=9030,
                flags=["Exit", "Fast", "Running", "Valid"],
            )
        )
        consensus.routers.append(
            RouterStatusEntry(
                nickname="GuardRouter",
                identity="ID2",
                digest="D2",
                published=datetime.now(UTC),
                ip="192.0.2.2",
                orport=9001,
                dirport=9030,
                flags=["Guard", "Fast", "Running", "Stable", "Valid"],
            )
        )
        consensus.routers.append(
            RouterStatusEntry(
                nickname="ExitGuardRouter",
                identity="ID3",
                digest="D3",
                published=datetime.now(UTC),
                ip="192.0.2.3",
                orport=9001,
                dirport=9030,
                flags=["Exit", "Guard", "Fast", "Running", "Stable", "Valid"],
            )
        )

        exit_routers = consensus.get_routers_by_flag("Exit")
        assert len(exit_routers) == 2
        assert all(r.has_flag("Exit") for r in exit_routers)

        guard_routers = consensus.get_routers_by_flag("Guard")
        assert len(guard_routers) == 2
        assert all(r.has_flag("Guard") for r in guard_routers)

        stable_routers = consensus.get_routers_by_flag("Stable")
        assert len(stable_routers) == 2


class TestMicrodescriptor:
    """Tests for Microdescriptor model."""

    def test_basic_microdescriptor_creation(self):
        """Test creating a basic microdescriptor."""
        md = Microdescriptor(digest="dGVzdGRpZ2VzdA==")
        assert md.digest == "dGVzdGRpZ2VzdA=="

    def test_is_exit_property_with_accept_policy(self):
        """Test is_exit property returns True for accept policies."""
        md = Microdescriptor(digest="dGVzdA==", exit_policy_v4="accept 80,443,8080-8090")
        assert md.is_exit is True

    def test_is_exit_property_with_reject_policy(self):
        """Test is_exit property returns False for reject policies."""
        md = Microdescriptor(digest="dGVzdA==", exit_policy_v4="reject 1-65535")
        assert md.is_exit is False

    def test_is_exit_property_with_no_policy(self):
        """Test is_exit property returns False with no exit policy."""
        md = Microdescriptor(digest="dGVzdA==")
        assert md.is_exit is False

    def test_optional_fields_defaults(self):
        """Test optional fields have correct defaults."""
        md = Microdescriptor(digest="dGVzdA==")

        assert md.onion_key_rsa is None
        assert md.onion_key_ntor is None
        assert md.ed25519_identity is None
        assert md.rsa1024_identity is None
        assert md.ipv6_addresses == []
        assert md.exit_policy_v4 is None
        assert md.exit_policy_v6 is None
        assert md.family_members == []
        assert md.family_ids == []
        assert md.raw_descriptor == ""
        assert md.fetched_at is None
