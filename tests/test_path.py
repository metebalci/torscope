"""Tests for path selection."""

from datetime import UTC, datetime

import pytest

from torscope.directory.models import ConsensusDocument, RouterStatusEntry
from torscope.path import DEFAULT_WEIGHT_SCALE, PathSelectionResult, PathSelector


def make_router(
    nickname: str,
    fingerprint: str,
    ip: str = "192.168.1.1",
    bandwidth: int = 1000,
    flags: str = "Fast Stable Valid Running",
) -> RouterStatusEntry:
    """Create a test router."""
    return RouterStatusEntry(
        nickname=nickname,
        identity=fingerprint[:27],  # Base64-encoded identity
        digest="",
        published=datetime.now(UTC),
        ip=ip,
        orport=9001,
        dirport=0,
        flags=flags.split(),  # flags is a list
        bandwidth=bandwidth,
    )


def make_consensus(routers: list[RouterStatusEntry]) -> ConsensusDocument:
    """Create a test consensus with given routers."""
    return ConsensusDocument(
        version=3,
        vote_status="consensus",
        consensus_method=1,
        valid_after=datetime.now(UTC),
        fresh_until=datetime.now(UTC),
        valid_until=datetime.now(UTC),
        voting_delay=(300, 300),
        client_versions=[],
        server_versions=[],
        known_flags=["Authority", "Exit", "Fast", "Guard", "Running", "Stable", "Valid"],
        params={"bwweightscale": DEFAULT_WEIGHT_SCALE},
        authorities=[],
        routers=routers,
        signatures=[],
    )


class TestPathSelectionResult:
    """Tests for PathSelectionResult dataclass."""

    def test_1_hop_path(self):
        """Test 1-hop path has only guard."""
        guard = make_router("Guard1", "A" * 40)
        result = PathSelectionResult(guard=guard)

        assert result.hops == 1
        assert result.routers == [guard]
        assert result.roles == ["Guard"]
        assert len(result.fingerprints) == 1

    def test_2_hop_path(self):
        """Test 2-hop path has guard and exit."""
        guard = make_router("Guard1", "A" * 40)
        exit_router = make_router("Exit1", "B" * 40)
        result = PathSelectionResult(guard=guard, exit=exit_router)

        assert result.hops == 2
        assert result.routers == [guard, exit_router]
        assert result.roles == ["Guard", "Exit"]

    def test_3_hop_path(self):
        """Test 3-hop path has guard, middle, and exit."""
        guard = make_router("Guard1", "A" * 40)
        middle = make_router("Middle1", "B" * 40)
        exit_router = make_router("Exit1", "C" * 40)
        result = PathSelectionResult(guard=guard, middle=middle, exit=exit_router)

        assert result.hops == 3
        assert result.routers == [guard, middle, exit_router]
        assert result.roles == ["Guard", "Middle", "Exit"]


class TestPathSelector:
    """Tests for PathSelector class."""

    def test_select_1_hop_path(self):
        """Test selecting a 1-hop path."""
        router = make_router("Router1", "A" * 40, flags="Fast Stable Valid Running Guard")
        consensus = make_consensus([router])
        selector = PathSelector(consensus)

        path = selector.select_path(num_hops=1)

        assert path.hops == 1
        assert path.guard == router

    def test_select_2_hop_path(self):
        """Test selecting a 2-hop path."""
        # Use different /16 subnets (10.0 vs 10.1)
        guard = make_router(
            "Guard1", "A" * 40, ip="10.0.0.1", flags="Fast Stable Valid Running Guard"
        )
        exit_router = make_router(
            "Exit1", "B" * 40, ip="10.1.0.1", flags="Fast Stable Valid Running Exit"
        )
        consensus = make_consensus([guard, exit_router])
        selector = PathSelector(consensus)

        path = selector.select_path(num_hops=2)

        assert path.hops == 2
        assert path.guard is not None
        assert path.exit is not None

    def test_select_3_hop_path(self):
        """Test selecting a 3-hop path."""
        # Use different /16 subnets (10.0, 10.1, 10.2)
        guard = make_router(
            "Guard1", "A" * 40, ip="10.0.0.1", flags="Fast Stable Valid Running Guard"
        )
        middle = make_router("Middle1", "B" * 40, ip="10.1.0.1", flags="Fast Stable Valid Running")
        exit_router = make_router(
            "Exit1", "C" * 40, ip="10.2.0.1", flags="Fast Stable Valid Running Exit"
        )
        consensus = make_consensus([guard, middle, exit_router])
        selector = PathSelector(consensus)

        path = selector.select_path(num_hops=3)

        assert path.hops == 3
        assert path.middle is not None

    def test_invalid_num_hops(self):
        """Test that invalid num_hops raises ValueError."""
        router = make_router("Router1", "A" * 40)
        consensus = make_consensus([router])
        selector = PathSelector(consensus)

        with pytest.raises(ValueError, match="num_hops must be 1, 2, or 3"):
            selector.select_path(num_hops=0)

        with pytest.raises(ValueError, match="num_hops must be 1, 2, or 3"):
            selector.select_path(num_hops=4)

    def test_no_duplicate_routers(self):
        """Test that the same router doesn't appear twice."""
        # Use different /16 subnets for each router
        routers = [
            make_router(
                f"Router{i}",
                f"{chr(65+i)}" * 40,
                ip=f"10.{i}.0.1",
                flags="Fast Stable Valid Running Guard Exit",
            )
            for i in range(5)
        ]
        consensus = make_consensus(routers)
        selector = PathSelector(consensus)

        # Run multiple times to increase confidence
        for _ in range(10):
            path = selector.select_path(num_hops=3)
            fingerprints = path.fingerprints
            assert len(fingerprints) == len(set(fingerprints)), "Duplicate router in path"

    def test_subnet_exclusion(self):
        """Test that routers in the same /16 subnet are excluded."""
        # Two routers in same /16 subnet (10.0.x.x)
        guard = make_router(
            "Guard1", "A" * 40, ip="10.0.0.1", flags="Fast Stable Valid Running Guard"
        )
        same_subnet = make_router(
            "Exit1", "B" * 40, ip="10.0.1.1", flags="Fast Stable Valid Running Exit"
        )
        diff_subnet = make_router(
            "Exit2", "C" * 40, ip="10.1.0.1", flags="Fast Stable Valid Running Exit"
        )
        consensus = make_consensus([guard, same_subnet, diff_subnet])
        selector = PathSelector(consensus)

        # When guard is specified, exit should not be in same /16
        path = selector.select_path(num_hops=2, guard=guard)

        assert path.guard == guard
        assert path.exit == diff_subnet, "Exit should be from different /16 subnet"

    def test_prespecified_guard(self):
        """Test using a pre-specified guard router."""
        guard = make_router(
            "MyGuard", "A" * 40, ip="10.0.0.1", flags="Fast Stable Valid Running Guard"
        )
        exit_router = make_router(
            "Exit1", "B" * 40, ip="10.1.0.1", flags="Fast Stable Valid Running Exit"
        )
        consensus = make_consensus([guard, exit_router])
        selector = PathSelector(consensus)

        path = selector.select_path(num_hops=2, guard=guard)

        assert path.guard == guard

    def test_prespecified_exit(self):
        """Test using a pre-specified exit router."""
        guard = make_router(
            "Guard1", "A" * 40, ip="10.0.0.1", flags="Fast Stable Valid Running Guard"
        )
        exit_router = make_router(
            "MyExit", "B" * 40, ip="10.1.0.1", flags="Fast Stable Valid Running Exit"
        )
        consensus = make_consensus([guard, exit_router])
        selector = PathSelector(consensus)

        path = selector.select_path(num_hops=2, exit_router=exit_router)

        assert path.exit == exit_router


class TestBandwidthWeighting:
    """Tests for bandwidth-weighted selection."""

    def test_higher_bandwidth_selected_more_often(self):
        """Test that higher bandwidth routers are selected more frequently."""
        # Create routers with very different bandwidths
        low_bw = make_router(
            "LowBW", "A" * 40, ip="10.0.0.1", bandwidth=100, flags="Fast Stable Valid Running Guard"
        )
        high_bw = make_router(
            "HighBW",
            "B" * 40,
            ip="10.1.0.1",
            bandwidth=10000,
            flags="Fast Stable Valid Running Guard",
        )
        consensus = make_consensus([low_bw, high_bw])
        selector = PathSelector(consensus)

        # Select many times and count
        selections = {"LowBW": 0, "HighBW": 0}
        for _ in range(100):
            path = selector.select_path(num_hops=1)
            selections[path.guard.nickname] += 1

        # High bandwidth should be selected much more often
        # With 100:1 ratio, HighBW should be selected ~99% of the time
        assert (
            selections["HighBW"] > selections["LowBW"]
        ), f"Higher bandwidth router should be selected more often: {selections}"
