"""
HTTP client for fetching directory documents.

This module provides functionality to fetch consensus documents and descriptors
from Tor directory authorities.
"""

import httpx

from torscope import output
from torscope.directory.authority import (
    DirectoryAuthority,
    get_random_authority,
    get_shuffled_authorities,
)


class DirectoryClient:
    """HTTP client for fetching Tor directory documents."""

    def __init__(self, timeout: int = 30) -> None:
        """
        Initialize the directory client.

        Args:
            timeout: HTTP request timeout in seconds
        """
        self.timeout = timeout

    def fetch_consensus(
        self,
        authority: DirectoryAuthority | None = None,
        consensus_type: str = "microdesc",
    ) -> tuple[bytes, DirectoryAuthority]:
        """
        Fetch consensus document from a directory authority.

        If no authority is specified, tries multiple authorities until one succeeds.

        Args:
            authority: Directory authority to fetch from (tries multiple if None)
            consensus_type: Type of consensus ("microdesc" or "full")

        Returns:
            Tuple of (consensus_bytes, authority_used)

        Raises:
            httpx.HTTPError: If all authorities fail
        """
        # If specific authority requested, try only that one
        if authority is not None:
            return self._fetch_consensus_from(authority, consensus_type)

        # Try multiple authorities until one succeeds
        authorities = get_shuffled_authorities()
        last_error: Exception | None = None

        for auth in authorities:
            try:
                return self._fetch_consensus_from(auth, consensus_type)
            except httpx.HTTPError as e:
                last_error = e
                continue

        # All authorities failed
        raise last_error or httpx.HTTPError("All authorities unreachable")

    def _fetch_consensus_from(
        self,
        authority: DirectoryAuthority,
        consensus_type: str,
    ) -> tuple[bytes, DirectoryAuthority]:
        """Fetch consensus from a specific authority."""
        # Determine URL based on consensus type
        if consensus_type == "microdesc":
            url = f"{authority.http_url}/tor/status-vote/current/consensus-microdesc"
        else:
            url = f"{authority.http_url}/tor/status-vote/current/consensus"

        output.verbose(f"GET {url}")

        # Set headers to request compression
        headers = {
            "Accept-Encoding": "deflate, gzip",
            "User-Agent": "torscope/0.1.0",
        }

        # Fetch the document
        with httpx.Client(timeout=self.timeout) as client:
            response = client.get(url, headers=headers, follow_redirects=True)
            response.raise_for_status()
            output.debug(f"Response: {response.status_code}, {len(response.content)} bytes")
            return response.content, authority

    def fetch_microdescriptors(
        self,
        hashes: list[str],
        authority: DirectoryAuthority | None = None,
    ) -> tuple[bytes, DirectoryAuthority]:
        """
        Fetch microdescriptors by their hashes.

        Args:
            hashes: List of base64-encoded SHA256 hashes
            authority: Directory authority to fetch from (random if None)

        Returns:
            Tuple of (descriptors_bytes, authority_used)

        Raises:
            httpx.HTTPError: If fetch fails
        """
        if authority is None:
            authority = get_random_authority()

        # Remove trailing '=' from base64 hashes and join with '-'
        hash_string = "-".join(h.rstrip("=") for h in hashes)
        url = f"{authority.http_url}/tor/micro/d/{hash_string}"

        output.verbose(f"GET microdescriptors ({len(hashes)} hashes) from {authority.nickname}")
        output.debug(f"URL: {url[:80]}...")

        headers = {
            "Accept-Encoding": "deflate, gzip",
            "User-Agent": "torscope/0.1.0",
        }

        with httpx.Client(timeout=self.timeout) as client:
            response = client.get(url, headers=headers, follow_redirects=True)
            response.raise_for_status()
            output.debug(f"Response: {response.status_code}, {len(response.content)} bytes")
            return response.content, authority

    def fetch_server_descriptors(
        self,
        fingerprints: list[str],
        authority: DirectoryAuthority | None = None,
    ) -> tuple[bytes, DirectoryAuthority]:
        """
        Fetch server descriptors by fingerprints.

        Args:
            fingerprints: List of hex-encoded fingerprints
            authority: Directory authority to fetch from (random if None)

        Returns:
            Tuple of (descriptors_bytes, authority_used)

        Raises:
            httpx.HTTPError: If fetch fails
        """
        if authority is None:
            authority = get_random_authority()

        # Join fingerprints with '+'
        fp_string = "+".join(fingerprints)
        url = f"{authority.http_url}/tor/server/fp/{fp_string}"

        output.verbose(f"GET server descriptors ({len(fingerprints)}) from {authority.nickname}")

        headers = {
            "Accept-Encoding": "deflate, gzip",
            "User-Agent": "torscope/0.1.0",
        }

        with httpx.Client(timeout=self.timeout) as client:
            response = client.get(url, headers=headers, follow_redirects=True)
            response.raise_for_status()
            output.debug(f"Response: {response.status_code}, {len(response.content)} bytes")
            return response.content, authority

    def fetch_extra_info(
        self,
        fingerprints: list[str],
        authority: DirectoryAuthority | None = None,
    ) -> tuple[bytes, DirectoryAuthority]:
        """
        Fetch extra-info descriptors by fingerprints.

        Args:
            fingerprints: List of hex-encoded fingerprints
            authority: Directory authority to fetch from (random if None)

        Returns:
            Tuple of (descriptors_bytes, authority_used)

        Raises:
            httpx.HTTPError: If fetch fails
        """
        if authority is None:
            authority = get_random_authority()

        # Join fingerprints with '+'
        fp_string = "+".join(fingerprints)
        url = f"{authority.http_url}/tor/extra/fp/{fp_string}"

        output.verbose(f"GET extra-info ({len(fingerprints)}) from {authority.nickname}")

        headers = {
            "Accept-Encoding": "deflate, gzip",
            "User-Agent": "torscope/0.1.0",
        }

        with httpx.Client(timeout=self.timeout) as client:
            response = client.get(url, headers=headers, follow_redirects=True)
            response.raise_for_status()
            output.debug(f"Response: {response.status_code}, {len(response.content)} bytes")
            return response.content, authority

    def fetch_key_certificates(
        self,
        authority: DirectoryAuthority | None = None,
    ) -> tuple[bytes, DirectoryAuthority]:
        """
        Fetch all authority key certificates.

        If no authority is specified, tries multiple authorities until one succeeds.

        Args:
            authority: Directory authority to fetch from (tries multiple if None)

        Returns:
            Tuple of (certificates_bytes, authority_used)

        Raises:
            httpx.HTTPError: If all authorities fail
        """
        # If specific authority requested, try only that one
        if authority is not None:
            return self._fetch_key_certificates_from(authority)

        # Try multiple authorities until one succeeds
        authorities = get_shuffled_authorities()
        last_error: Exception | None = None

        for auth in authorities:
            try:
                return self._fetch_key_certificates_from(auth)
            except httpx.HTTPError as e:
                last_error = e
                continue

        # All authorities failed
        raise last_error or httpx.HTTPError("All authorities unreachable")

    def _fetch_key_certificates_from(
        self,
        authority: DirectoryAuthority,
    ) -> tuple[bytes, DirectoryAuthority]:
        """Fetch key certificates from a specific authority."""
        url = f"{authority.http_url}/tor/keys/all"

        output.verbose(f"GET key certificates from {authority.nickname}")

        headers = {
            "Accept-Encoding": "deflate, gzip",
            "User-Agent": "torscope/0.1.0",
        }

        with httpx.Client(timeout=self.timeout) as client:
            response = client.get(url, headers=headers, follow_redirects=True)
            response.raise_for_status()
            output.debug(f"Response: {response.status_code}, {len(response.content)} bytes")
            return response.content, authority
