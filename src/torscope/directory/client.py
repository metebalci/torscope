"""
HTTP client for fetching directory documents.

This module provides functionality to fetch consensus documents and descriptors
from Tor directory authorities.
"""

from typing import Optional

import httpx

from torscope.directory.authority import DirectoryAuthority, get_random_authority


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
        authority: Optional[DirectoryAuthority] = None,
        consensus_type: str = "microdesc",
    ) -> tuple[bytes, DirectoryAuthority]:
        """
        Fetch consensus document from a directory authority.

        Args:
            authority: Directory authority to fetch from (random if None)
            consensus_type: Type of consensus ("microdesc" or "full")

        Returns:
            Tuple of (consensus_bytes, authority_used)

        Raises:
            httpx.HTTPError: If fetch fails
        """
        if authority is None:
            authority = get_random_authority()

        # Determine URL based on consensus type
        if consensus_type == "microdesc":
            url = f"{authority.http_url}/tor/status-vote/current/consensus-microdesc"
        else:
            url = f"{authority.http_url}/tor/status-vote/current/consensus"

        # Set headers to request compression
        headers = {
            "Accept-Encoding": "deflate, gzip",
            "User-Agent": "torscope/0.1.0",
        }

        # Fetch the document
        with httpx.Client(timeout=self.timeout) as client:
            response = client.get(url, headers=headers, follow_redirects=True)
            response.raise_for_status()
            return response.content, authority

    def fetch_microdescriptors(
        self,
        hashes: list[str],
        authority: Optional[DirectoryAuthority] = None,
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

        headers = {
            "Accept-Encoding": "deflate, gzip",
            "User-Agent": "torscope/0.1.0",
        }

        with httpx.Client(timeout=self.timeout) as client:
            response = client.get(url, headers=headers, follow_redirects=True)
            response.raise_for_status()
            return response.content, authority

    def fetch_server_descriptors(
        self,
        fingerprints: list[str],
        authority: Optional[DirectoryAuthority] = None,
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

        headers = {
            "Accept-Encoding": "deflate, gzip",
            "User-Agent": "torscope/0.1.0",
        }

        with httpx.Client(timeout=self.timeout) as client:
            response = client.get(url, headers=headers, follow_redirects=True)
            response.raise_for_status()
            return response.content, authority
