"""HSDir hashring selection for v3 hidden services.

This module implements the HSDir (Hidden Service Directory) selection
algorithm as specified in rend-spec-v3.txt.

The algorithm places both services and HSDirs on a hashring, and finds
the closest HSDirs to a service's blinded key for descriptor storage/lookup.
"""

from __future__ import annotations

import base64
import struct
from dataclasses import dataclass

from torscope.crypto import sha3_256
from torscope.directory.models import ConsensusDocument, RouterStatusEntry

# Number of replicas for descriptor distribution
HS_N_REPLICAS = 2

# Number of HSDirs to select per replica (spread)
HSDIR_SPREAD_STORE = 4  # For storing
HSDIR_SPREAD_FETCH = 3  # For fetching (we try fewer)

# Time period length in minutes (24 hours)
HS_TIME_PERIOD_LENGTH = 1440


@dataclass
class HSDirectoryEntry:
    """An HSDir with its computed index on the hashring."""

    router: RouterStatusEntry
    index: bytes  # 32-byte SHA3-256 hash (position on ring)
    ed25519_id: bytes | None  # 32-byte Ed25519 identity if available

    def __lt__(self, other: HSDirectoryEntry) -> bool:
        """Compare by index for sorting on the ring."""
        return self.index < other.index


class HSDirectoryRing:
    """Hashring of HSDir relays for hidden service directory lookup.

    The hashring is computed from the consensus and shared random value.
    Each HSDir's position on the ring is determined by:

        hsdir_index = SHA3-256("node-idx" | ed25519_id | shared_random |
                               INT_8(period_num) | INT_8(period_length))

    Services compute their position similarly (replica is 1-indexed: 1, 2):

        hs_index = SHA3-256("store-at-idx" | blinded_key |
                            INT_8(replica) | INT_8(period_length) |
                            INT_8(period_num))
    """

    def __init__(
        self,
        consensus: ConsensusDocument,
        time_period: int,
        use_second_srv: bool = False,
        ed25519_map: dict[str, bytes] | None = None,
    ):
        """Initialize the HSDir hashring.

        Args:
            consensus: Network consensus document
            time_period: Current time period number
            use_second_srv: If True, use shared_rand_previous instead of current
            ed25519_map: Pre-computed map of microdesc_hash -> Ed25519 identity (optional)
        """
        self.consensus = consensus
        self.time_period = time_period
        self.period_length = HS_TIME_PERIOD_LENGTH

        # Get shared random value from consensus
        if use_second_srv and consensus.shared_rand_previous:
            self.shared_random = self._decode_srv(consensus.shared_rand_previous)
        elif consensus.shared_rand_current:
            self.shared_random = self._decode_srv(consensus.shared_rand_current)
        else:
            # Fallback: use zero SRV (not ideal but allows testing)
            self.shared_random = b"\x00" * 32

        # Build the hashring
        self.entries: list[HSDirectoryEntry] = []
        self._build_ring(ed25519_map)

    def _decode_srv(self, srv: tuple[int, str]) -> bytes:
        """Decode shared random value from consensus format.

        Args:
            srv: Tuple of (num_reveals, base64_value)

        Returns:
            32-byte shared random value
        """
        _, value_b64 = srv
        return base64.b64decode(value_b64)

    def _build_ring(self, ed25519_map: dict[str, bytes] | None = None) -> None:
        """Build the HSDir hashring from consensus routers.

        Args:
            ed25519_map: Pre-computed map of microdesc_hash -> Ed25519 identity (optional).
                         If not provided, microdescriptors will be fetched.
        """
        # First, collect all HSDir routers and their microdesc hashes
        hsdir_routers: list[RouterStatusEntry] = []
        microdesc_hashes: list[str] = []

        for router in self.consensus.routers:
            if "HSDir" in router.flags and router.microdesc_hash:
                hsdir_routers.append(router)
                microdesc_hashes.append(router.microdesc_hash)

        # Use provided ed25519_map or fetch microdescriptors
        if ed25519_map is None:
            ed25519_map = self._fetch_ed25519_identities(microdesc_hashes)

        # Build the ring
        for router in hsdir_routers:
            # microdesc_hash is guaranteed non-None from the filter above
            md_hash = router.microdesc_hash
            if md_hash is None:
                continue
            ed25519_id = ed25519_map.get(md_hash)
            if ed25519_id is None:
                continue

            # Compute hsdir_index
            index = self._compute_hsdir_index(ed25519_id)

            entry = HSDirectoryEntry(
                router=router,
                index=index,
                ed25519_id=ed25519_id,
            )
            self.entries.append(entry)

        # Sort by index (position on ring)
        self.entries.sort()

    def _fetch_ed25519_identities(self, microdesc_hashes: list[str]) -> dict[str, bytes]:
        """Fetch Ed25519 identities from microdescriptors.

        Args:
            microdesc_hashes: List of microdescriptor hashes

        Returns:
            Dict mapping microdesc hash to 32-byte Ed25519 identity
        """
        # pylint: disable=import-outside-toplevel
        import time

        from torscope.cache import get_microdescriptor, save_microdescriptors
        from torscope.directory.authority import get_shuffled_authorities
        from torscope.directory.client import DirectoryClient
        from torscope.directory.microdescriptor import MicrodescriptorParser

        # pylint: enable=import-outside-toplevel

        result: dict[str, bytes] = {}

        # First check cache for already fetched microdescriptors
        missing_hashes: list[str] = []
        for h in microdesc_hashes:
            md = get_microdescriptor(h)
            if md and md.ed25519_identity:
                try:
                    b64 = md.ed25519_identity
                    padding = 4 - len(b64) % 4
                    if padding != 4:
                        b64 += "=" * padding
                    result[h] = base64.b64decode(b64)
                except (ValueError, AttributeError):
                    missing_hashes.append(h)
            else:
                missing_hashes.append(h)

        if not missing_hashes:
            return result

        # Fetch missing microdescriptors in larger batches for efficiency
        batch_size = 500  # Larger batches = fewer HTTP requests
        client = DirectoryClient()
        total_batches = (len(missing_hashes) + batch_size - 1) // batch_size
        authorities = get_shuffled_authorities()
        max_retries = 3

        print(f"Fetching {len(missing_hashes)} microdescriptors in {total_batches} batches...")

        for batch_num, i in enumerate(range(0, len(missing_hashes), batch_size)):
            batch = missing_hashes[i : i + batch_size]
            print(f"  Batch {batch_num + 1}/{total_batches}...", end="", flush=True)

            # Try with retries and different authorities
            success = False
            for retry in range(max_retries):
                # Rotate through authorities on retry
                authority = authorities[(batch_num + retry) % len(authorities)]
                try:
                    fetch_result = client.fetch_microdescriptors(batch, authority=authority)
                    if fetch_result:
                        content, _ = fetch_result
                        microdescriptors = MicrodescriptorParser.parse(content.decode("utf-8"))

                        # Save to cache and extract identities
                        save_microdescriptors(microdescriptors, authority.nickname, "authority")

                        for md in microdescriptors:
                            if md.ed25519_identity:
                                try:
                                    b64 = md.ed25519_identity
                                    padding = 4 - len(b64) % 4
                                    if padding != 4:
                                        b64 += "=" * padding
                                    result[md.digest] = base64.b64decode(b64)
                                except (ValueError, AttributeError):
                                    pass
                        print(f" OK ({len(microdescriptors)})")
                        success = True
                        break
                except (ConnectionError, OSError, TimeoutError):
                    if retry < max_retries - 1:
                        # Brief delay before retry
                        time.sleep(0.5 * (retry + 1))
                        continue

            if not success:
                print(" failed (after retries)")

        return result

    def _get_ed25519_id(self, router: RouterStatusEntry) -> bytes | None:
        """Get Ed25519 identity for a router.

        Uses the Ed25519 identity from the consensus "id ed25519" line if available.

        Args:
            router: Router status entry

        Returns:
            32-byte Ed25519 identity or None
        """
        if router.ed25519_identity is None:
            return None

        try:
            # The consensus provides base64-encoded Ed25519 identity
            # Add padding if needed (Tor uses unpadded base64)
            b64 = router.ed25519_identity
            padding = 4 - len(b64) % 4
            if padding != 4:
                b64 += "=" * padding
            return base64.b64decode(b64)
        except (ValueError, AttributeError):
            return None

    def _compute_hsdir_index(self, ed25519_id: bytes) -> bytes:
        """Compute HSDir index on the hashring.

        hsdir_index = H("node-idx" | ed25519_id | shared_random |
                        INT_8(period_num) | INT_8(period_length))

        Args:
            ed25519_id: 32-byte Ed25519 identity

        Returns:
            32-byte hash (position on ring)
        """
        data = (
            b"node-idx"
            + ed25519_id
            + self.shared_random
            + struct.pack(">Q", self.time_period)
            + struct.pack(">Q", self.period_length)
        )
        return sha3_256(data)

    def get_responsible_hsdirs(
        self,
        blinded_key: bytes,
        n_replicas: int = HS_N_REPLICAS,
        spread: int = HSDIR_SPREAD_FETCH,
    ) -> list[RouterStatusEntry]:
        """Find HSDirs responsible for a hidden service descriptor.

        For each replica, we compute the service's position on the ring
        and find the closest HSDirs.

        Args:
            blinded_key: 32-byte blinded public key of the hidden service
            n_replicas: Number of replicas (default: 2)
            spread: Number of HSDirs per replica (default: 3 for fetch)

        Returns:
            List of responsible HSDir routers (deduplicated)
        """
        if not self.entries:
            return []

        responsible: list[RouterStatusEntry] = []
        seen_fingerprints: set[str] = set()

        for replica in range(1, n_replicas + 1):  # 1-indexed per spec
            # Compute service's position for this replica
            hs_index = self._compute_hs_index(blinded_key, replica)

            # Find closest HSDirs on the ring
            closest = self._find_closest(hs_index, spread)

            for entry in closest:
                fp = entry.router.fingerprint
                if fp not in seen_fingerprints:
                    seen_fingerprints.add(fp)
                    responsible.append(entry.router)

        return responsible

    def _compute_hs_index(self, blinded_key: bytes, replica: int) -> bytes:
        """Compute hidden service index on the hashring.

        hs_index = H("store-at-idx" | blinded_key | INT_8(replica) |
                     INT_8(period_length) | INT_8(period_num))

        Note: INT_8 means 8 bytes (64-bit big-endian integer).

        Args:
            blinded_key: 32-byte blinded public key
            replica: Replica number (0-based)

        Returns:
            32-byte hash (position on ring)
        """
        data = (
            b"store-at-idx"
            + blinded_key
            + struct.pack(">Q", replica)
            + struct.pack(">Q", self.period_length)
            + struct.pack(">Q", self.time_period)
        )
        return sha3_256(data)

    def _find_closest(self, target: bytes, n: int) -> list[HSDirectoryEntry]:
        """Find n closest HSDirs to target position on the ring.

        Uses binary search to find insertion point, then takes n entries
        starting from that point (wrapping around).

        Args:
            target: Target position (32-byte hash)
            n: Number of entries to return

        Returns:
            List of closest HSDir entries
        """
        if not self.entries:
            return []

        # Binary search for insertion point
        left, right = 0, len(self.entries)
        while left < right:
            mid = (left + right) // 2
            if self.entries[mid].index < target:
                left = mid + 1
            else:
                right = mid

        # Take n entries starting from insertion point (with wraparound)
        result: list[HSDirectoryEntry] = []
        for i in range(min(n, len(self.entries))):
            idx = (left + i) % len(self.entries)
            result.append(self.entries[idx])

        return result

    @property
    def size(self) -> int:
        """Number of HSDirs on the ring."""
        return len(self.entries)

    @classmethod
    def fetch_ed25519_map(cls, consensus: ConsensusDocument) -> dict[str, bytes]:
        """Fetch Ed25519 identities for all HSDir relays.

        This is a convenience method to pre-fetch the Ed25519 map for use with
        multiple HSDir ring instances.

        Args:
            consensus: Network consensus document

        Returns:
            Dict mapping microdesc_hash -> 32-byte Ed25519 identity
        """
        # Collect all HSDir microdesc hashes
        microdesc_hashes: list[str] = []
        for router in consensus.routers:
            if "HSDir" in router.flags and router.microdesc_hash:
                microdesc_hashes.append(router.microdesc_hash)

        # Create temporary instance to use the fetch method
        dummy = object.__new__(cls)
        return dummy._fetch_ed25519_identities(microdesc_hashes)


def get_responsible_hsdirs(
    consensus: ConsensusDocument,
    blinded_key: bytes,
    time_period: int,
    n_replicas: int = HS_N_REPLICAS,
    spread: int = HSDIR_SPREAD_FETCH,
) -> list[RouterStatusEntry]:
    """Convenience function to find responsible HSDirs.

    Args:
        consensus: Network consensus
        blinded_key: 32-byte blinded public key
        time_period: Current time period number
        n_replicas: Number of replicas
        spread: Number of HSDirs per replica

    Returns:
        List of responsible HSDir routers
    """
    ring = HSDirectoryRing(consensus, time_period)
    return ring.get_responsible_hsdirs(blinded_key, n_replicas, spread)
