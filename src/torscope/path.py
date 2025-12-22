"""
Path selection for Tor circuits.

This module implements path selection according to the Tor path-spec:
https://spec.torproject.org/path-spec/path-selection-constraints.html

Key constraints:
- No router appears twice in the same path
- No two routers from the same family
- No two routers in the same /16 subnet (IPv4) or /32 (IPv6)
- Selection is weighted by bandwidth using consensus bandwidth weights
"""

import random
from dataclasses import dataclass, field
from typing import Literal

from torscope import output
from torscope.directory.models import ConsensusDocument, Microdescriptor, RouterStatusEntry

# Default weight scale (from bwweightscale consensus parameter)
DEFAULT_WEIGHT_SCALE = 10000

# Role types for path selection
Role = Literal["guard", "middle", "exit"]


@dataclass
class PathSelectionResult:
    """
    Result of path selection.

    Path structures:
    - 1-hop: guard only
    - 2-hop: guard + exit (no middle)
    - 3-hop: guard + middle + exit

    For bridge mode:
    - guard is None (bridge is used instead, handled separately)
    - 2-hop: exit only
    - 3-hop: middle + exit
    """

    guard: RouterStatusEntry | None = None  # None when using bridge
    middle: RouterStatusEntry | None = None  # None for 1-hop and 2-hop circuits
    exit: RouterStatusEntry | None = None  # None for 1-hop circuits

    @property
    def hops(self) -> int:
        """Number of hops in the path (not counting bridge)."""
        count = 0
        if self.guard is not None:
            count += 1
        if self.middle is not None:
            count += 1
        if self.exit is not None:
            count += 1
        return count

    @property
    def routers(self) -> list[RouterStatusEntry]:
        """List of routers in path order (guard, [middle], [exit])."""
        result: list[RouterStatusEntry] = []
        if self.guard is not None:
            result.append(self.guard)
        if self.middle is not None:
            result.append(self.middle)
        if self.exit is not None:
            result.append(self.exit)
        return result

    @property
    def roles(self) -> list[str]:
        """List of role names corresponding to routers."""
        result: list[str] = []
        if self.guard is not None:
            result.append("Guard")
        if self.middle is not None:
            result.append("Middle")
        if self.exit is not None:
            result.append("Exit")
        return result

    @property
    def fingerprints(self) -> list[str]:
        """List of fingerprints in path order."""
        return [r.fingerprint for r in self.routers]


@dataclass
class PathSelector:
    """
    Selects paths through the Tor network.

    Implements bandwidth-weighted selection with family and subnet exclusion.
    """

    consensus: ConsensusDocument
    microdescriptors: dict[str, Microdescriptor] = field(default_factory=dict)

    # Cached weight scale from consensus
    _weight_scale: int = field(default=DEFAULT_WEIGHT_SCALE, init=False)

    def __post_init__(self) -> None:
        """Initialize weight scale from consensus."""
        self._weight_scale = self.consensus.params.get("bwweightscale", DEFAULT_WEIGHT_SCALE)

    def select_path(
        self,
        num_hops: int = 3,
        target_port: int | None = None,
        guard: RouterStatusEntry | None = None,
        middle: RouterStatusEntry | None = None,
        exit_router: RouterStatusEntry | None = None,
    ) -> PathSelectionResult:
        """
        Select a path through the Tor network.

        Args:
            num_hops: Number of hops (1, 2, or 3)
            target_port: Target port for exit selection (filters by exit policy)
            guard: Pre-selected guard router (optional)
            middle: Pre-selected middle router (optional, for 3-hop)
            exit_router: Pre-selected exit router (optional, for 2+ hops)

        Returns:
            PathSelectionResult with selected routers

        Raises:
            ValueError: If no suitable routers found or invalid configuration
        """
        if num_hops < 1 or num_hops > 3:
            raise ValueError("num_hops must be 1, 2, or 3")

        output.debug(f"Selecting {num_hops}-hop path, target_port={target_port}")

        excluded_fps: set[str] = set()
        excluded_subnets: set[str] = set()
        excluded_families: set[str] = set()

        # Select or validate guard
        if guard is None:
            guard = self._select_router(
                "guard",
                excluded_fps=excluded_fps,
                excluded_subnets=excluded_subnets,
                excluded_families=excluded_families,
            )
            output.verbose(f"Selected guard: {guard.nickname}")
        else:
            output.verbose(f"Using specified guard: {guard.nickname}")
        self._add_exclusions(guard, excluded_fps, excluded_subnets, excluded_families)

        if num_hops == 1:
            return PathSelectionResult(guard=guard)

        # Select or validate exit (for 2+ hops)
        if exit_router is None:
            exit_router = self._select_router(
                "exit",
                excluded_fps=excluded_fps,
                excluded_subnets=excluded_subnets,
                excluded_families=excluded_families,
                target_port=target_port,
            )
            output.verbose(f"Selected exit: {exit_router.nickname}")
        else:
            output.verbose(f"Using specified exit: {exit_router.nickname}")
        self._add_exclusions(exit_router, excluded_fps, excluded_subnets, excluded_families)

        if num_hops == 2:
            return PathSelectionResult(guard=guard, exit=exit_router)

        # Select or validate middle (for 3-hop)
        if middle is None:
            middle = self._select_router(
                "middle",
                excluded_fps=excluded_fps,
                excluded_subnets=excluded_subnets,
                excluded_families=excluded_families,
            )
            output.verbose(f"Selected middle: {middle.nickname}")
        else:
            output.verbose(f"Using specified middle: {middle.nickname}")

        return PathSelectionResult(guard=guard, middle=middle, exit=exit_router)

    def select_path_for_bridge(
        self,
        num_hops: int = 3,
        target_port: int | None = None,
        bridge_ip: str | None = None,
        bridge_fingerprint: str | None = None,
        exit_router: RouterStatusEntry | None = None,
    ) -> PathSelectionResult:
        """
        Select path components for use with a bridge.

        When using a bridge, the bridge acts as the first hop.
        This method selects the remaining hops (middle and/or exit).

        Args:
            num_hops: Total number of hops including bridge (2 or 3)
            target_port: Target port for exit selection (filters by exit policy)
            bridge_ip: Bridge IP address (for subnet exclusion)
            bridge_fingerprint: Bridge fingerprint (for fingerprint exclusion)
            exit_router: Pre-selected exit router (optional)

        Returns:
            PathSelectionResult with guard=None and middle/exit selected

        Raises:
            ValueError: If no suitable routers found or invalid configuration
        """
        if num_hops < 2 or num_hops > 3:
            raise ValueError("num_hops must be 2 or 3 when using a bridge")

        output.debug(f"Selecting {num_hops - 1} hops after bridge, target_port={target_port}")

        excluded_fps: set[str] = set()
        excluded_subnets: set[str] = set()
        excluded_families: set[str] = set()

        # Exclude bridge from selection
        if bridge_fingerprint:
            excluded_fps.add(bridge_fingerprint.upper())
        if bridge_ip:
            excluded_subnets.add(self._get_ipv4_subnet(bridge_ip))

        # Select or validate exit
        if exit_router is None:
            exit_router = self._select_router(
                "exit",
                excluded_fps=excluded_fps,
                excluded_subnets=excluded_subnets,
                excluded_families=excluded_families,
                target_port=target_port,
            )
            output.verbose(f"Selected exit: {exit_router.nickname}")
        else:
            output.verbose(f"Using specified exit: {exit_router.nickname}")
        self._add_exclusions(exit_router, excluded_fps, excluded_subnets, excluded_families)

        if num_hops == 2:
            # Bridge + Exit (no middle)
            return PathSelectionResult(guard=None, exit=exit_router)

        # Select middle (for 3-hop)
        middle = self._select_router(
            "middle",
            excluded_fps=excluded_fps,
            excluded_subnets=excluded_subnets,
            excluded_families=excluded_families,
        )
        output.verbose(f"Selected middle: {middle.nickname}")

        return PathSelectionResult(guard=None, middle=middle, exit=exit_router)

    def _select_router(
        self,
        role: Role,
        excluded_fps: set[str],
        excluded_subnets: set[str],
        excluded_families: set[str],
        target_port: int | None = None,
    ) -> RouterStatusEntry:
        """
        Select a router for a specific role using bandwidth-weighted selection.

        Args:
            role: "guard", "middle", or "exit"
            excluded_fps: Fingerprints to exclude
            excluded_subnets: /16 subnets to exclude
            excluded_families: Family identifiers to exclude
            target_port: Target port for exit selection

        Returns:
            Selected router

        Raises:
            ValueError: If no suitable router found
        """
        candidates = self._get_candidates(
            role, excluded_fps, excluded_subnets, excluded_families, target_port
        )

        if not candidates:
            raise ValueError(f"No suitable {role} router found")

        output.debug(f"Found {len(candidates)} candidates for {role}")

        # Get bandwidth weights for this role
        weights = self._compute_weights(candidates, role)
        total_weight = sum(weights)
        output.debug(f"Total bandwidth weight: {total_weight:,.0f}")

        # Weighted random selection
        return self._weighted_choice(candidates, weights)

    def _get_candidates(
        self,
        role: Role,
        excluded_fps: set[str],
        excluded_subnets: set[str],
        excluded_families: set[str],
        target_port: int | None = None,
    ) -> list[RouterStatusEntry]:
        """Get candidate routers for a role, applying exclusions."""
        candidates = []

        for router in self.consensus.routers:
            # Skip excluded fingerprints
            if router.fingerprint in excluded_fps:
                continue

            # Skip same /16 subnet
            subnet = self._get_ipv4_subnet(router.ip)
            if subnet in excluded_subnets:
                continue

            # Skip same family
            router_families = self._get_router_families(router)
            if router_families & excluded_families:
                continue

            # Role-specific requirements
            if role == "guard":
                # Guards need Guard, Stable, and Fast flags
                required = router.has_flag("Guard") and router.has_flag("Stable")
                if not (required and router.has_flag("Fast")):
                    continue
            elif role == "exit":
                # Exits need Exit, Stable, and Fast flags
                required = router.has_flag("Exit") and router.has_flag("Stable")
                if not (required and router.has_flag("Fast")):
                    continue
                # Check exit policy if port specified and policy is available
                # If no exit_policy in consensus, trust the Exit flag (authorities verified it)
                if target_port is not None and router.exit_policy is not None:
                    if not router.allows_port(target_port):
                        continue
                # Skip BadExit
                if router.has_flag("BadExit"):
                    continue
            else:  # middle
                # Middle needs Stable and Fast flags
                if not (router.has_flag("Stable") and router.has_flag("Fast")):
                    continue

            candidates.append(router)

        return candidates

    def _compute_weights(self, candidates: list[RouterStatusEntry], role: Role) -> list[float]:
        """
        Compute bandwidth weights for candidates.

        Uses consensus bandwidth weights (Wgg, Wgd, etc.) to adjust
        router bandwidth based on role and flags.
        """
        weights = []
        bw_weights = self.consensus.bandwidth_weights

        for router in candidates:
            # Get base bandwidth (measured or advertised)
            bw = router.bandwidth or 0

            # Determine weight multiplier based on role and flags
            is_guard = router.has_flag("Guard")
            is_exit = router.has_flag("Exit")

            if role == "guard":
                if is_guard and is_exit:
                    weight_key = "Wgd"  # Guard+Exit in guard position
                elif is_guard:
                    weight_key = "Wgg"  # Guard-only in guard position
                else:
                    weight_key = "Wgm"  # Non-flagged in guard position
            elif role == "middle":
                if is_guard and is_exit:
                    weight_key = "Wmd"  # Guard+Exit in middle position
                elif is_guard:
                    weight_key = "Wmg"  # Guard in middle position
                elif is_exit:
                    weight_key = "Wme"  # Exit in middle position
                else:
                    weight_key = "Wmm"  # Non-flagged in middle position
            else:  # exit
                if is_guard and is_exit:
                    weight_key = "Wed"  # Guard+Exit in exit position
                elif is_exit:
                    weight_key = "Wee"  # Exit-only in exit position
                elif is_guard:
                    weight_key = "Weg"  # Guard in exit position (unusual)
                else:
                    weight_key = "Wem"  # Non-flagged in exit position

            # Get weight multiplier (default to scale if not found)
            multiplier = bw_weights.get(weight_key, self._weight_scale)

            # Compute weighted bandwidth
            weighted_bw = (bw * multiplier) / self._weight_scale
            weights.append(max(weighted_bw, 1.0))  # Minimum weight of 1

        return weights

    def _weighted_choice(
        self, candidates: list[RouterStatusEntry], weights: list[float]
    ) -> RouterStatusEntry:
        """Select a random router weighted by bandwidth."""
        total = sum(weights)
        if total == 0:
            return random.choice(candidates)

        r = random.uniform(0, total)
        cumulative = 0.0

        for router, weight in zip(candidates, weights, strict=True):
            cumulative += weight
            if r <= cumulative:
                return router

        return candidates[-1]  # Fallback

    def _get_ipv4_subnet(self, ip: str) -> str:
        """Get /16 subnet from IPv4 address."""
        parts = ip.split(".")
        if len(parts) >= 2:
            return f"{parts[0]}.{parts[1]}"
        return ip

    def _get_router_families(self, router: RouterStatusEntry) -> set[str]:
        """
        Get family identifiers for a router.

        Checks cached microdescriptors for family information.
        Returns fingerprint and any family members/IDs.
        """
        families: set[str] = {router.fingerprint}

        # Check microdescriptor for family info
        if router.microdesc_hash:
            md = self.microdescriptors.get(router.microdesc_hash)
            if md:
                # Add family members (fingerprints or nicknames)
                for member in md.family_members:
                    if member.startswith("$"):
                        # Fingerprint format: $FINGERPRINT or $FINGERPRINT~nickname
                        fp = member[1:].split("~")[0].split("=")[0].upper()
                        families.add(fp)
                    else:
                        # Nickname - add as-is (less reliable)
                        families.add(member)

                # Add family IDs
                for fid in md.family_ids:
                    families.add(fid)

        return families

    def _add_exclusions(
        self,
        router: RouterStatusEntry,
        excluded_fps: set[str],
        excluded_subnets: set[str],
        excluded_families: set[str],
    ) -> None:
        """Add a router's identifiers to exclusion sets."""
        excluded_fps.add(router.fingerprint)
        excluded_subnets.add(self._get_ipv4_subnet(router.ip))
        excluded_families.update(self._get_router_families(router))


def select_path(
    consensus: ConsensusDocument,
    num_hops: int = 3,
    target_port: int | None = None,
    microdescriptors: dict[str, Microdescriptor] | None = None,
) -> PathSelectionResult:
    """
    Convenience function to select a path.

    Args:
        consensus: Network consensus document
        num_hops: Number of hops (1, 2, or 3)
        target_port: Target port for exit selection
        microdescriptors: Optional dict of cached microdescriptors for family checking

    Returns:
        PathSelectionResult with selected routers
    """
    selector = PathSelector(
        consensus=consensus,
        microdescriptors=microdescriptors or {},
    )
    return selector.select_path(num_hops=num_hops, target_port=target_port)
