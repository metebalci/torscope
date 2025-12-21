"""
Microdescriptor fetching and caching.

Provides centralized logic for fetching ntor keys from microdescriptors,
with multi-tier fallback (cache → V2Dir → authority → server descriptor).
"""

import random

import httpx

from torscope.cache import get_ntor_key_from_cache, save_microdescriptors
from torscope.directory.client import DirectoryClient
from torscope.directory.microdescriptor import MicrodescriptorParser
from torscope.directory.models import ConsensusDocument, RouterStatusEntry
from torscope.directory.or_client import fetch_ntor_key


def select_v2dir_router(
    consensus: ConsensusDocument, exclude: list[str] | None = None
) -> RouterStatusEntry | None:
    """Select a random V2Dir router with a DirPort for fetching directory documents."""
    exclude_set = set(exclude) if exclude else set()
    candidates = [
        r
        for r in consensus.routers
        if r.has_flag("V2Dir")
        and r.has_flag("Fast")
        and r.has_flag("Stable")
        and r.dirport > 0  # Must have a DirPort
        and r.fingerprint not in exclude_set
    ]
    if not candidates:
        return None
    return random.choice(candidates)


def fetch_microdesc_from_router(
    router: RouterStatusEntry, hashes: list[str], timeout: float = 10.0
) -> tuple[bytes, RouterStatusEntry] | None:
    """Fetch microdescriptors from a V2Dir router's DirPort."""
    hash_string = "-".join(h.rstrip("=") for h in hashes)
    url = f"http://{router.ip}:{router.dirport}/tor/micro/d/{hash_string}"

    headers = {
        "Accept-Encoding": "deflate, gzip",
        "User-Agent": "torscope/0.1.0",
    }

    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.get(url, headers=headers, follow_redirects=True)
            response.raise_for_status()
            return response.content, router
    except httpx.HTTPError:
        return None


def get_ntor_key(
    router: RouterStatusEntry, consensus: ConsensusDocument | None = None
) -> tuple[bytes, str, str, bool] | None:
    """
    Get ntor-onion-key for a router, using cache or fetching on-demand.

    Tries sources in order:
    1. Local cache (microdescriptors.json)
    2. V2Dir router (if consensus provided)
    3. Directory authority
    4. Server descriptor (via OR client)

    Args:
        router: Router status entry with fingerprint and microdesc_hash
        consensus: Network consensus for finding V2Dir routers (optional)

    Returns:
        Tuple of (32-byte ntor key, source_name, source_type, from_cache) or None
        source_type is "dircache", "authority", or "descriptor"
        from_cache indicates if this was retrieved from local cache
    """
    # Try cached microdescriptor first
    if router.microdesc_hash:
        cache_result = get_ntor_key_from_cache(router.microdesc_hash)
        if cache_result is not None:
            ntor_key, source_name, source_type = cache_result
            return ntor_key, source_name, source_type, True

        # Try fetching from a V2Dir router (directory cache)
        if consensus is not None:
            v2dir_router = select_v2dir_router(consensus, exclude=[router.fingerprint])
            if v2dir_router:
                result = fetch_microdesc_from_router(v2dir_router, [router.microdesc_hash])
                if result:
                    md_content, used_router = result
                    microdescriptors = MicrodescriptorParser.parse(md_content)
                    if microdescriptors:
                        save_microdescriptors(microdescriptors, used_router.nickname, "dircache")
                        cache_result = get_ntor_key_from_cache(router.microdesc_hash)
                        if cache_result is not None:
                            return cache_result[0], used_router.nickname, "dircache", False

        # Fall back to authority
        try:
            client = DirectoryClient()
            md_content, authority = client.fetch_microdescriptors([router.microdesc_hash])
            microdescriptors = MicrodescriptorParser.parse(md_content)
            if microdescriptors:
                save_microdescriptors(microdescriptors, authority.nickname, "authority")
                cache_result = get_ntor_key_from_cache(router.microdesc_hash)
                if cache_result is not None:
                    return cache_result[0], authority.nickname, "authority", False
        except Exception:  # noqa: BLE001  # pylint: disable=broad-exception-caught
            pass  # Fall through to server descriptor

    # Fall back to fetching server descriptor
    desc_result = fetch_ntor_key(router.fingerprint)
    if desc_result is not None:
        ntor_key, source_name = desc_result
        return ntor_key, source_name, "descriptor", False
    return None
