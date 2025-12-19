"""
Cache module for torscope.

Provides caching for consensus documents in .torscope/ directory.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from torscope.directory.consensus import ConsensusParser
from torscope.directory.models import ConsensusDocument

CACHE_DIR = Path(".torscope")
CONSENSUS_FILE = CACHE_DIR / "consensus.bin"
CONSENSUS_META = CACHE_DIR / "consensus.json"


def _ensure_cache_dir() -> None:
    """Create cache directory if it doesn't exist."""
    CACHE_DIR.mkdir(exist_ok=True)


def save_consensus(content: bytes, authority: str) -> None:
    """
    Save consensus content to cache.

    Args:
        content: Raw consensus bytes
        authority: Authority nickname the consensus was fetched from
    """
    _ensure_cache_dir()

    # Save raw content
    CONSENSUS_FILE.write_bytes(content)

    # Save metadata
    meta = {
        "authority": authority,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }
    CONSENSUS_META.write_text(json.dumps(meta))


def load_consensus() -> Optional[ConsensusDocument]:
    """
    Load consensus from cache if valid.

    Returns:
        ConsensusDocument if cached and still valid, None otherwise
    """
    if not CONSENSUS_FILE.exists() or not CONSENSUS_META.exists():
        return None

    try:
        # Load and parse
        content = CONSENSUS_FILE.read_bytes()
        meta = json.loads(CONSENSUS_META.read_text())
        authority = meta.get("authority", "unknown")

        consensus = ConsensusParser.parse(content, authority)

        # Check if still valid
        if consensus.is_valid:
            return consensus

        return None

    # pylint: disable-next=broad-exception-caught
    except Exception:
        return None


def get_cache_info() -> Optional[dict[str, str]]:
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
