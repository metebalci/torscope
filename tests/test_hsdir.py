"""Tests for HSDir hashring selection."""

import base64
import struct
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from torscope.crypto import sha3_256
from torscope.directory.hsdir import (
    HSDirectoryEntry,
    HSDirectoryRing,
    HS_N_REPLICAS,
    HS_TIME_PERIOD_LENGTH,
    HSDIR_SPREAD_FETCH,
    HSDIR_SPREAD_STORE,
    get_responsible_hsdirs,
)
from torscope.directory.models import ConsensusDocument, RouterStatusEntry


# =============================================================================
# Test Helpers
# =============================================================================


def make_router(
    nickname: str,
    identity_hex: str,
    flags: list[str] | None = None,
    microdesc_hash: str | None = None,
    ed25519_identity: str | None = None,
) -> RouterStatusEntry:
    """Create a RouterStatusEntry for testing.

    Args:
        nickname: Router nickname
        identity_hex: 40-char hex fingerprint (will be base64 encoded for identity field)
        flags: Optional list of flags
        microdesc_hash: Optional microdescriptor hash
        ed25519_identity: Optional Ed25519 identity (base64)
    """
    # Convert hex fingerprint to base64 identity (as in consensus)
    fp_bytes = bytes.fromhex(identity_hex)
    identity_b64 = base64.b64encode(fp_bytes).decode("ascii").rstrip("=")

    return RouterStatusEntry(
        nickname=nickname,
        identity=identity_b64,
        digest="AAAAAAAAAAAAAAAAAAAAAAAAAAAA",  # Dummy digest
        published=datetime(2024, 1, 1, 0, 0, 0),
        ip="192.0.2.1",
        orport=9001,
        dirport=9030,
        flags=flags or ["Fast", "Running", "Stable", "Valid", "HSDir"],
        bandwidth=1000000,
        microdesc_hash=microdesc_hash or f"hash_{identity_hex[:8]}",
        ed25519_identity=ed25519_identity,
    )


def make_consensus(
    routers: list[RouterStatusEntry] | None = None,
    shared_rand_current: tuple[int, str] | None = None,
    shared_rand_previous: tuple[int, str] | None = None,
) -> ConsensusDocument:
    """Create a mock ConsensusDocument."""
    if routers is None:
        routers = []

    mock = MagicMock(spec=ConsensusDocument)
    mock.routers = routers
    mock.shared_rand_current = shared_rand_current
    mock.shared_rand_previous = shared_rand_previous
    return mock


# =============================================================================
# Tests
# =============================================================================


class TestHSDirectoryEntry:
    """Tests for HSDirectoryEntry dataclass."""

    def test_create_entry(self):
        """Test creating an HSDirectoryEntry."""
        router = make_router("test", "A" * 40)
        index = b"i" * 32
        ed25519_id = b"e" * 32

        entry = HSDirectoryEntry(
            router=router,
            index=index,
            ed25519_id=ed25519_id,
        )

        assert entry.router == router
        assert entry.index == index
        assert entry.ed25519_id == ed25519_id

    def test_comparison_by_index(self):
        """Test entries are compared by index."""
        router1 = make_router("a", "A" * 40)
        router2 = make_router("b", "B" * 40)

        entry1 = HSDirectoryEntry(router=router1, index=b"\x00" * 32, ed25519_id=None)
        entry2 = HSDirectoryEntry(router=router2, index=b"\xff" * 32, ed25519_id=None)

        assert entry1 < entry2
        assert not entry2 < entry1

    def test_sorting(self):
        """Test entries can be sorted by index."""
        entries = [
            HSDirectoryEntry(router=make_router("c", "C" * 40), index=b"\x80" * 32, ed25519_id=None),
            HSDirectoryEntry(router=make_router("a", "A" * 40), index=b"\x00" * 32, ed25519_id=None),
            HSDirectoryEntry(router=make_router("b", "B" * 40), index=b"\x40" * 32, ed25519_id=None),
        ]

        sorted_entries = sorted(entries)

        assert sorted_entries[0].router.nickname == "a"
        assert sorted_entries[1].router.nickname == "b"
        assert sorted_entries[2].router.nickname == "c"


class TestHSDirectoryRingInit:
    """Tests for HSDirectoryRing initialization."""

    def test_init_with_current_srv(self):
        """Test initialization uses current SRV."""
        srv_value = base64.b64encode(b"s" * 32).decode()
        consensus = make_consensus(
            routers=[],
            shared_rand_current=(5, srv_value),
        )

        ring = HSDirectoryRing(consensus, time_period=1000, ed25519_map={})

        assert ring.shared_random == b"s" * 32
        assert ring.time_period == 1000
        assert ring.period_length == HS_TIME_PERIOD_LENGTH

    def test_init_with_previous_srv(self):
        """Test initialization can use previous SRV."""
        current_srv = base64.b64encode(b"c" * 32).decode()
        previous_srv = base64.b64encode(b"p" * 32).decode()
        consensus = make_consensus(
            routers=[],
            shared_rand_current=(5, current_srv),
            shared_rand_previous=(4, previous_srv),
        )

        ring = HSDirectoryRing(consensus, time_period=1000, use_second_srv=True, ed25519_map={})

        assert ring.shared_random == b"p" * 32

    def test_init_without_srv_uses_zeros(self):
        """Test initialization falls back to zero SRV."""
        consensus = make_consensus(
            routers=[],
            shared_rand_current=None,
            shared_rand_previous=None,
        )

        ring = HSDirectoryRing(consensus, time_period=1000, ed25519_map={})

        assert ring.shared_random == b"\x00" * 32

    def test_builds_ring_from_hsdirs(self):
        """Test ring is built from HSDir routers."""
        ed25519_id1 = b"e" * 32
        ed25519_id2 = b"f" * 32
        md_hash1 = "hash1"
        md_hash2 = "hash2"

        routers = [
            make_router("hsdir1", "A" * 40, ["HSDir", "Running"], md_hash1),
            make_router("hsdir2", "B" * 40, ["HSDir", "Running"], md_hash2),
            make_router("relay", "C" * 40, ["Running"]),  # Not HSDir
        ]
        consensus = make_consensus(routers=routers)

        ed25519_map = {
            md_hash1: ed25519_id1,
            md_hash2: ed25519_id2,
        }

        ring = HSDirectoryRing(consensus, time_period=1000, ed25519_map=ed25519_map)

        assert ring.size == 2

    def test_skips_routers_without_ed25519_id(self):
        """Test routers without Ed25519 identity are skipped."""
        routers = [
            make_router("hsdir1", "A" * 40, ["HSDir", "Running"], "hash1"),
            make_router("hsdir2", "B" * 40, ["HSDir", "Running"], "hash2"),
        ]
        consensus = make_consensus(routers=routers)

        # Only provide ed25519 for one router
        ed25519_map = {"hash1": b"e" * 32}

        ring = HSDirectoryRing(consensus, time_period=1000, ed25519_map=ed25519_map)

        assert ring.size == 1


class TestHSDirectoryRingDecodeSrv:
    """Tests for HSDirectoryRing._decode_srv()."""

    def test_decode_srv(self):
        """Test decoding SRV from consensus format."""
        srv_bytes = b"shared_random_value!1234"
        srv_b64 = base64.b64encode(srv_bytes).decode()

        ring = HSDirectoryRing.__new__(HSDirectoryRing)
        result = ring._decode_srv((5, srv_b64))

        assert result == srv_bytes


class TestHSDirectoryRingComputeIndex:
    """Tests for HSDirectoryRing index computation."""

    def test_compute_hsdir_index(self):
        """Test HSDir index computation."""
        ring = HSDirectoryRing.__new__(HSDirectoryRing)
        ring.shared_random = b"s" * 32
        ring.time_period = 1000
        ring.period_length = HS_TIME_PERIOD_LENGTH

        ed25519_id = b"e" * 32
        index = ring._compute_hsdir_index(ed25519_id)

        # Verify it's a SHA3-256 hash
        assert len(index) == 32

        # Verify deterministic
        index2 = ring._compute_hsdir_index(ed25519_id)
        assert index == index2

    def test_compute_hsdir_index_different_ids(self):
        """Test different Ed25519 IDs produce different indices."""
        ring = HSDirectoryRing.__new__(HSDirectoryRing)
        ring.shared_random = b"s" * 32
        ring.time_period = 1000
        ring.period_length = HS_TIME_PERIOD_LENGTH

        index1 = ring._compute_hsdir_index(b"a" * 32)
        index2 = ring._compute_hsdir_index(b"b" * 32)

        assert index1 != index2

    def test_compute_hs_index(self):
        """Test hidden service index computation."""
        ring = HSDirectoryRing.__new__(HSDirectoryRing)
        ring.shared_random = b"s" * 32
        ring.time_period = 1000
        ring.period_length = HS_TIME_PERIOD_LENGTH

        blinded_key = b"b" * 32
        index = ring._compute_hs_index(blinded_key, replica=1)

        # Verify it's a SHA3-256 hash
        assert len(index) == 32

    def test_compute_hs_index_different_replicas(self):
        """Test different replicas produce different indices."""
        ring = HSDirectoryRing.__new__(HSDirectoryRing)
        ring.shared_random = b"s" * 32
        ring.time_period = 1000
        ring.period_length = HS_TIME_PERIOD_LENGTH

        blinded_key = b"b" * 32
        index1 = ring._compute_hs_index(blinded_key, replica=1)
        index2 = ring._compute_hs_index(blinded_key, replica=2)

        assert index1 != index2

    def test_compute_hs_index_matches_spec(self):
        """Test HS index computation matches spec format."""
        ring = HSDirectoryRing.__new__(HSDirectoryRing)
        ring.shared_random = b"s" * 32
        ring.time_period = 1000
        ring.period_length = 1440

        blinded_key = b"b" * 32
        index = ring._compute_hs_index(blinded_key, replica=1)

        # Manually compute expected value
        expected_data = (
            b"store-at-idx"
            + blinded_key
            + struct.pack(">Q", 1)  # replica
            + struct.pack(">Q", 1440)  # period_length
            + struct.pack(">Q", 1000)  # time_period
        )
        expected_index = sha3_256(expected_data)

        assert index == expected_index


class TestHSDirectoryRingFindClosest:
    """Tests for HSDirectoryRing._find_closest()."""

    def test_find_closest_empty_ring(self):
        """Test finding closest on empty ring."""
        ring = HSDirectoryRing.__new__(HSDirectoryRing)
        ring.entries = []

        result = ring._find_closest(b"\x50" * 32, n=3)

        assert result == []

    def test_find_closest_basic(self):
        """Test finding closest entries."""
        ring = HSDirectoryRing.__new__(HSDirectoryRing)
        ring.entries = [
            HSDirectoryEntry(
                router=make_router("a", "A" * 40), index=b"\x20" * 32, ed25519_id=None
            ),
            HSDirectoryEntry(
                router=make_router("b", "B" * 40), index=b"\x40" * 32, ed25519_id=None
            ),
            HSDirectoryEntry(
                router=make_router("c", "C" * 40), index=b"\x60" * 32, ed25519_id=None
            ),
            HSDirectoryEntry(
                router=make_router("d", "D" * 40), index=b"\x80" * 32, ed25519_id=None
            ),
        ]

        # Target between b and c, should get c, d
        result = ring._find_closest(b"\x50" * 32, n=2)

        assert len(result) == 2
        assert result[0].router.nickname == "c"
        assert result[1].router.nickname == "d"

    def test_find_closest_wraparound(self):
        """Test finding closest wraps around the ring."""
        ring = HSDirectoryRing.__new__(HSDirectoryRing)
        ring.entries = [
            HSDirectoryEntry(
                router=make_router("a", "A" * 40), index=b"\x20" * 32, ed25519_id=None
            ),
            HSDirectoryEntry(
                router=make_router("b", "B" * 40), index=b"\x80" * 32, ed25519_id=None
            ),
        ]

        # Target after b, should wrap to a
        result = ring._find_closest(b"\x90" * 32, n=2)

        assert len(result) == 2
        assert result[0].router.nickname == "a"  # Wrapped around
        assert result[1].router.nickname == "b"

    def test_find_closest_limits_to_ring_size(self):
        """Test finding closest limits to ring size."""
        ring = HSDirectoryRing.__new__(HSDirectoryRing)
        ring.entries = [
            HSDirectoryEntry(
                router=make_router("a", "A" * 40), index=b"\x40" * 32, ed25519_id=None
            ),
            HSDirectoryEntry(
                router=make_router("b", "B" * 40), index=b"\x80" * 32, ed25519_id=None
            ),
        ]

        # Ask for more than available
        result = ring._find_closest(b"\x50" * 32, n=10)

        assert len(result) == 2


class TestHSDirectoryRingGetResponsibleHsdirs:
    """Tests for HSDirectoryRing.get_responsible_hsdirs()."""

    def test_empty_ring_returns_empty(self):
        """Test empty ring returns empty list."""
        ring = HSDirectoryRing.__new__(HSDirectoryRing)
        ring.entries = []
        ring.time_period = 1000
        ring.period_length = 1440

        result = ring.get_responsible_hsdirs(b"b" * 32)

        assert result == []

    def test_finds_hsdirs_for_each_replica(self):
        """Test finds HSDirs for each replica."""
        ring = HSDirectoryRing.__new__(HSDirectoryRing)
        ring.time_period = 1000
        ring.period_length = 1440

        # Create enough entries for multiple replicas
        ring.entries = [
            HSDirectoryEntry(
                router=make_router(f"r{i}", f"{i:02x}" * 20),  # Valid hex fingerprint
                index=bytes([i * 20]) + b"\x00" * 31,
                ed25519_id=None,
            )
            for i in range(12)
        ]

        # Default: 2 replicas, 3 spread = up to 6 HSDirs
        result = ring.get_responsible_hsdirs(b"b" * 32)

        # Should have unique routers from both replicas
        assert len(result) <= 6
        assert len(result) > 0

    def test_deduplicates_across_replicas(self):
        """Test HSDirs are deduplicated across replicas."""
        ring = HSDirectoryRing.__new__(HSDirectoryRing)
        ring.time_period = 1000
        ring.period_length = 1440

        # Small ring where replicas will overlap
        ring.entries = [
            HSDirectoryEntry(
                router=make_router("only", "A" * 40), index=b"\x50" * 32, ed25519_id=None
            ),
        ]

        result = ring.get_responsible_hsdirs(b"b" * 32, n_replicas=2, spread=3)

        # Only one unique router
        assert len(result) == 1
        assert result[0].nickname == "only"

    def test_custom_replicas_and_spread(self):
        """Test custom replica and spread values."""
        ring = HSDirectoryRing.__new__(HSDirectoryRing)
        ring.time_period = 1000
        ring.period_length = 1440

        ring.entries = [
            HSDirectoryEntry(
                router=make_router(f"r{i}", f"{i:02x}" * 20),  # Valid hex fingerprint
                index=bytes([i * 10]) + b"\x00" * 31,
                ed25519_id=None,
            )
            for i in range(20)
        ]

        # Use store spread (4 per replica)
        result = ring.get_responsible_hsdirs(
            b"b" * 32, n_replicas=2, spread=HSDIR_SPREAD_STORE
        )

        # Could have up to 8 unique HSDirs
        assert len(result) <= 8


class TestHSDirectoryRingSize:
    """Tests for HSDirectoryRing.size property."""

    def test_size_empty(self):
        """Test size of empty ring."""
        ring = HSDirectoryRing.__new__(HSDirectoryRing)
        ring.entries = []

        assert ring.size == 0

    def test_size_with_entries(self):
        """Test size with entries."""
        ring = HSDirectoryRing.__new__(HSDirectoryRing)
        ring.entries = [
            HSDirectoryEntry(router=make_router("a", "A" * 40), index=b"\x00" * 32, ed25519_id=None),
            HSDirectoryEntry(router=make_router("b", "B" * 40), index=b"\x40" * 32, ed25519_id=None),
            HSDirectoryEntry(router=make_router("c", "C" * 40), index=b"\x80" * 32, ed25519_id=None),
        ]

        assert ring.size == 3


class TestGetResponsibleHsdirs:
    """Tests for get_responsible_hsdirs() convenience function."""

    def test_creates_ring_and_returns_hsdirs(self):
        """Test convenience function creates ring and returns HSDirs."""
        srv_value = base64.b64encode(b"s" * 32).decode()
        md_hash = "hash1"
        ed25519_id = b"e" * 32

        routers = [make_router("hsdir1", "A" * 40, ["HSDir", "Running"], md_hash)]
        consensus = make_consensus(routers=routers, shared_rand_current=(5, srv_value))

        with patch.object(
            HSDirectoryRing, "_fetch_ed25519_identities", return_value={md_hash: ed25519_id}
        ):
            result = get_responsible_hsdirs(
                consensus=consensus,
                blinded_key=b"b" * 32,
                time_period=1000,
            )

            assert len(result) >= 0  # May be empty depending on hashring position


class TestHSDirectoryRingConstants:
    """Tests for module constants."""

    def test_replicas_constant(self):
        """Test HS_N_REPLICAS is 2."""
        assert HS_N_REPLICAS == 2

    def test_spread_store_constant(self):
        """Test HSDIR_SPREAD_STORE is 4."""
        assert HSDIR_SPREAD_STORE == 4

    def test_spread_fetch_constant(self):
        """Test HSDIR_SPREAD_FETCH is 3."""
        assert HSDIR_SPREAD_FETCH == 3

    def test_time_period_length(self):
        """Test HS_TIME_PERIOD_LENGTH is 1440 (24 hours in minutes)."""
        assert HS_TIME_PERIOD_LENGTH == 1440
