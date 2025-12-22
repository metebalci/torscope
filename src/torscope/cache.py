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
from torscope.utils import pad_base64

CACHE_DIR = Path(".torscope")
CONSENSUS_FILE = CACHE_DIR / "consensus.bin"
CONSENSUS_META = CACHE_DIR / "consensus.json"
MICRODESC_DIR = CACHE_DIR / "microdesc"

# In-memory cache for microdescriptors (avoid repeated disk reads)
_microdesc_cache: dict[str, dict[str, str | None]] = {}


def _ensure_cache_dir() -> None:
    """Create cache directory if it doesn't exist."""
    CACHE_DIR.mkdir(exist_ok=True)


def _ensure_microdesc_dir() -> None:
    """Create microdescriptor cache directory if it doesn't exist."""
    _ensure_cache_dir()
    MICRODESC_DIR.mkdir(exist_ok=True)


def _digest_to_filename(digest: str) -> str:
    """Convert base64 digest to filesystem-safe hex filename."""
    # Decode base64 to bytes, then encode as hex (always unique and safe)
    normalized = _normalize_digest(digest)
    try:
        raw_bytes = base64.b64decode(normalized)
        return f"{raw_bytes.hex()}.json"
    except ValueError:
        # Fallback: use the digest directly with unsafe chars replaced
        safe = digest.rstrip("=").replace("/", "_").replace("+", "-")
        return f"{safe}.json"


def _filename_to_digest(filename: str) -> str:
    """Convert hex filename back to base64 digest."""
    hex_str = filename.removesuffix(".json")
    try:
        raw_bytes = bytes.fromhex(hex_str)
        return base64.b64encode(raw_bytes).decode("ascii")
    except ValueError:
        # Fallback: assume old format with replaced chars
        base = hex_str.replace("_", "/").replace("-", "+")
        return pad_base64(base)


def _normalize_digest(digest: str) -> str:
    """Normalize digest to padded base64."""
    return pad_base64(digest)


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
    global _microdesc_cache  # noqa: PLW0603

    if CONSENSUS_FILE.exists():
        CONSENSUS_FILE.unlink()
    if CONSENSUS_META.exists():
        CONSENSUS_META.unlink()

    # Clear microdescriptor cache directory
    if MICRODESC_DIR.exists():
        for f in MICRODESC_DIR.iterdir():
            if f.is_file() and f.suffix == ".json":
                f.unlink()

    # Clear in-memory cache
    _microdesc_cache = {}


def save_microdescriptors(
    microdescriptors: list[Microdescriptor],
    source_name: str = "",
    source_type: str = "",
) -> None:
    """
    Save microdescriptors to cache as individual files.

    Args:
        microdescriptors: List of parsed Microdescriptor objects
        source_name: Name of the source relay/authority
        source_type: Type of source ("authority", "dircache", etc.)
    """
    _ensure_microdesc_dir()

    for md in microdescriptors:
        digest = _normalize_digest(md.digest)
        entry = {
            "raw": md.raw_descriptor,
            "ntor_key": md.onion_key_ntor,
            "ed25519_identity": md.ed25519_identity,
            "source_name": source_name,
            "source_type": source_type,
            "fetched_at": datetime.now(UTC).isoformat(),
        }

        # Save to individual file
        filepath = MICRODESC_DIR / _digest_to_filename(digest)
        filepath.write_text(json.dumps(entry))

        # Update in-memory cache
        _microdesc_cache[digest] = entry


def _load_microdesc_entry(digest: str) -> dict[str, str | None] | None:
    """Load a single microdescriptor from cache."""
    digest = _normalize_digest(digest)

    # Check in-memory cache first
    if digest in _microdesc_cache:
        return _microdesc_cache[digest]

    # Try loading from file
    filepath = MICRODESC_DIR / _digest_to_filename(digest)
    if not filepath.exists():
        return None

    try:
        entry: dict[str, str | None] = json.loads(filepath.read_text())
        _microdesc_cache[digest] = entry
        return entry
    except (json.JSONDecodeError, OSError):
        return None


def get_microdescriptor(digest: str) -> Microdescriptor | None:
    """
    Get a microdescriptor by its digest.

    Args:
        digest: Base64-encoded SHA256 digest (with or without padding)

    Returns:
        Microdescriptor if cached, None otherwise
    """
    entry = _load_microdesc_entry(digest)
    if entry is None:
        return None

    digest_normalized = _normalize_digest(digest)

    # Reconstruct Microdescriptor from cached data
    return Microdescriptor(
        digest=digest_normalized,
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
    entry = _load_microdesc_entry(digest)
    if entry is None:
        return None

    ntor_key_b64 = entry.get("ntor_key")
    if ntor_key_b64 is None:
        return None

    # Decode base64 key (add padding if needed)
    try:
        ntor_key = base64.b64decode(pad_base64(ntor_key_b64))
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
    entry = _load_microdesc_entry(digest)
    if entry is None:
        return None

    ed25519_b64 = entry.get("ed25519_identity")
    if ed25519_b64 is None:
        return None

    # Decode base64 key (add padding if needed)
    try:
        return base64.b64decode(pad_base64(ed25519_b64))
    except ValueError:
        return None


def get_cached_microdesc_count() -> int:
    """Get number of cached microdescriptors."""
    if not MICRODESC_DIR.exists():
        return 0
    return sum(1 for f in MICRODESC_DIR.iterdir() if f.suffix == ".json")


def cleanup_stale_microdescriptors(consensus: ConsensusDocument) -> int:
    """
    Remove cached microdescriptors not present in the current consensus.

    Args:
        consensus: Current network consensus

    Returns:
        Number of files removed
    """
    if not MICRODESC_DIR.exists():
        return 0

    # Build set of valid digests from consensus
    valid_digests = {
        _normalize_digest(r.microdesc_hash) for r in consensus.routers if r.microdesc_hash
    }

    removed = 0

    for filepath in MICRODESC_DIR.iterdir():
        if filepath.suffix != ".json":
            continue

        try:
            digest = _filename_to_digest(filepath.name)
            if digest not in valid_digests:
                # Remove from in-memory cache
                _microdesc_cache.pop(digest, None)

                # Remove file
                filepath.unlink()
                removed += 1
        except OSError:
            continue

    return removed
