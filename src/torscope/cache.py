"""
Cache module for torscope.

Provides caching for consensus and microdescriptor documents in .torscope/ directory.
"""

import base64
import json
from datetime import UTC, datetime
from pathlib import Path

from torscope.directory.consensus import ConsensusParser
from torscope.directory.models import ConsensusDocument, Microdescriptor

CACHE_DIR = Path(".torscope")
CONSENSUS_FILE = CACHE_DIR / "consensus.bin"
CONSENSUS_META = CACHE_DIR / "consensus.json"
MICRODESC_FILE = CACHE_DIR / "microdescriptors.json"

# In-memory cache for microdescriptors (avoid repeated disk reads)
_microdesc_cache: dict[str, dict[str, str | None]] | None = None
_microdesc_cache_mtime: float = 0.0


def _ensure_cache_dir() -> None:
    """Create cache directory if it doesn't exist."""
    CACHE_DIR.mkdir(exist_ok=True)


def save_consensus(content: bytes, source: str, source_type: str = "authority") -> None:
    """
    Save consensus content to cache.

    Args:
        content: Raw consensus bytes
        source: Source name (authority/fallback/relay nickname)
        source_type: Type of source ("authority", "fallback", or "cache")
    """
    _ensure_cache_dir()

    # Save raw content
    CONSENSUS_FILE.write_bytes(content)

    # Save metadata
    meta = {
        "source": source,
        "source_type": source_type,
        "fetched_at": datetime.now(UTC).isoformat(),
    }
    CONSENSUS_META.write_text(json.dumps(meta))


def load_consensus(allow_expired: bool = False) -> tuple[ConsensusDocument, dict[str, str]] | None:
    """
    Load consensus from cache.

    Args:
        allow_expired: If True, return expired consensus with expired=True in metadata

    Returns:
        Tuple of (ConsensusDocument, metadata) if cached, None otherwise.
        Metadata contains: source, source_type, expired
    """
    if not CONSENSUS_FILE.exists() or not CONSENSUS_META.exists():
        return None

    try:
        # Load and parse
        content = CONSENSUS_FILE.read_bytes()
        meta = json.loads(CONSENSUS_META.read_text())

        # Handle backwards compatibility (old cache format)
        source = meta.get("source") or meta.get("authority", "unknown")
        source_type = meta.get("source_type", "authority")

        consensus = ConsensusParser.parse(content, source)

        # Check if still valid
        if consensus.is_valid:
            return consensus, {"source": source, "source_type": source_type, "expired": False}

        # Return expired consensus if allowed
        if allow_expired:
            return consensus, {"source": source, "source_type": source_type, "expired": True}

        return None

    # pylint: disable-next=broad-exception-caught
    except Exception:
        return None


def get_cache_info() -> dict[str, str] | None:
    """
    Get information about cached consensus.

    Returns:
        Dict with cache info or None if no cache
    """
    if not CONSENSUS_META.exists():
        return None

    try:
        result: dict[str, str] = json.loads(CONSENSUS_META.read_text())
        return result
    # pylint: disable-next=broad-exception-caught
    except Exception:
        return None


def clear_cache() -> None:
    """Remove all cached files."""
    if CONSENSUS_FILE.exists():
        CONSENSUS_FILE.unlink()
    if CONSENSUS_META.exists():
        CONSENSUS_META.unlink()
    if MICRODESC_FILE.exists():
        MICRODESC_FILE.unlink()


def save_microdescriptors(
    microdescriptors: list[Microdescriptor],
    source_name: str = "",
    source_type: str = "",
) -> None:
    """
    Save microdescriptors to cache.

    Args:
        microdescriptors: List of parsed Microdescriptor objects
        source_name: Name of the source relay/authority
        source_type: Type of source ("authority", "dircache", etc.)
    """
    _ensure_cache_dir()

    # Load existing cache and merge
    existing = _load_microdesc_cache()

    # Add new microdescriptors (overwrite if exists)
    for md in microdescriptors:
        existing[md.digest] = {
            "raw": md.raw_descriptor,
            "ntor_key": md.onion_key_ntor,
            "ed25519_identity": md.ed25519_identity,
            "source_name": source_name,
            "source_type": source_type,
            "fetched_at": datetime.now(UTC).isoformat(),
        }

    # Save merged cache and invalidate in-memory cache
    global _microdesc_cache, _microdesc_cache_mtime  # noqa: PLW0603
    MICRODESC_FILE.write_text(json.dumps(existing))
    _microdesc_cache = existing  # Update in-memory cache directly
    _microdesc_cache_mtime = MICRODESC_FILE.stat().st_mtime


def _load_microdesc_cache() -> dict[str, dict[str, str | None]]:
    """Load microdescriptor cache file with in-memory caching."""
    global _microdesc_cache, _microdesc_cache_mtime  # noqa: PLW0603

    if not MICRODESC_FILE.exists():
        _microdesc_cache = {}
        return _microdesc_cache

    try:
        # Check if file has been modified since last read
        current_mtime = MICRODESC_FILE.stat().st_mtime
        if _microdesc_cache is not None and current_mtime == _microdesc_cache_mtime:
            return _microdesc_cache

        # Reload from disk
        result: dict[str, dict[str, str | None]] = json.loads(MICRODESC_FILE.read_text())
        _microdesc_cache = result
        _microdesc_cache_mtime = current_mtime
        return result
    # pylint: disable-next=broad-exception-caught
    except Exception:
        _microdesc_cache = {}
        return _microdesc_cache


def get_microdescriptor(digest: str) -> Microdescriptor | None:
    """
    Get a microdescriptor by its digest.

    Args:
        digest: Base64-encoded SHA256 digest (with or without padding)

    Returns:
        Microdescriptor if cached, None otherwise
    """
    cache = _load_microdesc_cache()

    # Try both with and without trailing '='
    digest_stripped = digest.rstrip("=")
    digest_padded = digest_stripped + "=" * ((4 - len(digest_stripped) % 4) % 4)

    entry = cache.get(digest_padded) or cache.get(digest_stripped)
    if entry is None:
        return None

    # Reconstruct Microdescriptor from cached data
    return Microdescriptor(
        digest=digest_padded,
        onion_key_ntor=entry.get("ntor_key"),
        ed25519_identity=entry.get("ed25519_identity"),
        raw_descriptor=entry.get("raw") or "",
    )


def get_ntor_key_from_cache(digest: str) -> tuple[bytes, str, str] | None:
    """
    Get ntor-onion-key for a relay from cached microdescriptor.

    Args:
        digest: Base64-encoded microdescriptor digest

    Returns:
        Tuple of (32-byte ntor-onion-key, source_name, source_type) or None if not cached
    """
    cache = _load_microdesc_cache()

    # Try both with and without trailing '='
    digest_stripped = digest.rstrip("=")
    digest_padded = digest_stripped + "=" * ((4 - len(digest_stripped) % 4) % 4)

    entry = cache.get(digest_padded) or cache.get(digest_stripped)
    if entry is None:
        return None

    ntor_key_b64 = entry.get("ntor_key")
    if ntor_key_b64 is None:
        return None

    # Decode base64 key (add padding if needed)
    padding = (4 - len(ntor_key_b64) % 4) % 4
    if padding:
        ntor_key_b64 += "=" * padding

    try:
        ntor_key = base64.b64decode(ntor_key_b64)
    except ValueError:
        return None

    source_name = entry.get("source_name") or ""
    source_type = entry.get("source_type") or ""

    return ntor_key, source_name, source_type


def get_ed25519_from_cache(digest: str) -> bytes | None:
    """
    Get Ed25519 identity for a relay from cached microdescriptor.

    Args:
        digest: Base64-encoded microdescriptor digest

    Returns:
        32-byte Ed25519 identity or None if not cached
    """
    cache = _load_microdesc_cache()

    # Try both with and without trailing '='
    digest_stripped = digest.rstrip("=")
    digest_padded = digest_stripped + "=" * ((4 - len(digest_stripped) % 4) % 4)

    entry = cache.get(digest_padded) or cache.get(digest_stripped)
    if entry is None:
        return None

    ed25519_b64 = entry.get("ed25519_identity")
    if ed25519_b64 is None:
        return None

    # Decode base64 key (add padding if needed)
    padding = (4 - len(ed25519_b64) % 4) % 4
    if padding:
        ed25519_b64 += "=" * padding

    try:
        return base64.b64decode(ed25519_b64)
    except ValueError:
        return None


def get_cached_microdesc_count() -> int:
    """Get number of cached microdescriptors."""
    return len(_load_microdesc_cache())
