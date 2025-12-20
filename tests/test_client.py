"""Tests for directory HTTP client."""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from torscope.directory.authority import DirectoryAuthority
from torscope.directory.client import DirectoryClient


class TestDirectoryClient:
    """Tests for DirectoryClient class."""

    def test_initialization_default_timeout(self):
        """Test client initialization with default timeout."""
        client = DirectoryClient()
        assert client.timeout == 30

    def test_initialization_custom_timeout(self):
        """Test client initialization with custom timeout."""
        client = DirectoryClient(timeout=60)
        assert client.timeout == 60


class TestFetchConsensus:
    """Tests for fetch_consensus method."""

    @patch("httpx.Client")
    def test_fetch_microdesc_consensus_from_specified_authority(self, mock_client_class):
        """Test fetching microdescriptor consensus from specified authority."""
        # Setup mock
        mock_response = MagicMock()
        mock_response.content = b"consensus data"
        mock_response.raise_for_status = MagicMock()

        mock_client_instance = MagicMock()
        mock_client_instance.get.return_value = mock_response
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.__exit__.return_value = False
        mock_client_class.return_value = mock_client_instance

        # Create authority and client
        authority = DirectoryAuthority(
            nickname="moria1",
            ip="128.31.0.34",
            dirport=9131,
            orport=9101,
            v3ident="D586D18309DED4CD6D57C18FDB97EFA96D330566",
        )
        client = DirectoryClient()

        # Fetch consensus
        content, used_authority = client.fetch_consensus(
            authority=authority, consensus_type="microdesc"
        )

        # Verify results
        assert content == b"consensus data"
        assert used_authority == authority

        # Verify HTTP request
        expected_url = "http://128.31.0.34:9131/tor/status-vote/current/consensus-microdesc"
        mock_client_instance.get.assert_called_once()
        call_args = mock_client_instance.get.call_args
        assert call_args[0][0] == expected_url
        assert call_args[1]["headers"]["Accept-Encoding"] == "deflate, gzip"
        assert call_args[1]["headers"]["User-Agent"] == "torscope/0.1.0"
        assert call_args[1]["follow_redirects"] is True

    @patch("httpx.Client")
    def test_fetch_full_consensus(self, mock_client_class):
        """Test fetching full consensus."""
        # Setup mock
        mock_response = MagicMock()
        mock_response.content = b"full consensus data"
        mock_response.raise_for_status = MagicMock()

        mock_client_instance = MagicMock()
        mock_client_instance.get.return_value = mock_response
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.__exit__.return_value = False
        mock_client_class.return_value = mock_client_instance

        authority = DirectoryAuthority(
            nickname="moria1",
            ip="128.31.0.34",
            dirport=9131,
            orport=9101,
            v3ident="ABC123",
        )
        client = DirectoryClient()

        content, used_authority = client.fetch_consensus(authority=authority, consensus_type="full")

        # Verify URL for full consensus
        expected_url = "http://128.31.0.34:9131/tor/status-vote/current/consensus"
        call_args = mock_client_instance.get.call_args
        assert call_args[0][0] == expected_url

    @patch("torscope.directory.client.get_shuffled_authorities")
    @patch("httpx.Client")
    def test_fetch_consensus_tries_multiple_authorities(
        self, mock_client_class, mock_get_shuffled_authorities
    ):
        """Test fetching consensus tries authorities until one succeeds."""
        # Setup mock authorities
        authority1 = DirectoryAuthority(
            nickname="tor26",
            ip="86.59.21.38",
            dirport=80,
            orport=443,
            v3ident="ABC123",
        )
        authority2 = DirectoryAuthority(
            nickname="moria1",
            ip="128.31.0.34",
            dirport=9131,
            orport=9101,
            v3ident="DEF456",
        )
        mock_get_shuffled_authorities.return_value = [authority1, authority2]

        # Setup mock HTTP response
        mock_response = MagicMock()
        mock_response.content = b"consensus data"
        mock_response.raise_for_status = MagicMock()

        mock_client_instance = MagicMock()
        mock_client_instance.get.return_value = mock_response
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.__exit__.return_value = False
        mock_client_class.return_value = mock_client_instance

        client = DirectoryClient()
        content, used_authority = client.fetch_consensus()

        # Verify first authority was used (since it succeeded)
        assert used_authority == authority1
        mock_get_shuffled_authorities.assert_called_once()

    @patch("torscope.directory.client.get_shuffled_authorities")
    @patch("httpx.Client")
    def test_fetch_consensus_retries_on_failure(
        self, mock_client_class, mock_get_shuffled_authorities
    ):
        """Test fetching consensus retries when first authority fails."""
        # Setup mock authorities
        authority1 = DirectoryAuthority(
            nickname="failing",
            ip="192.0.2.1",
            dirport=80,
            orport=443,
            v3ident="FAIL",
        )
        authority2 = DirectoryAuthority(
            nickname="working",
            ip="192.0.2.2",
            dirport=80,
            orport=443,
            v3ident="WORK",
        )
        mock_get_shuffled_authorities.return_value = [authority1, authority2]

        # Setup mock to fail on first call, succeed on second
        mock_response = MagicMock()
        mock_response.content = b"consensus data"
        mock_response.raise_for_status = MagicMock()

        mock_client_instance = MagicMock()
        mock_client_instance.get.side_effect = [
            httpx.ConnectError("Connection failed"),
            mock_response,
        ]
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.__exit__.return_value = False
        mock_client_class.return_value = mock_client_instance

        client = DirectoryClient()
        content, used_authority = client.fetch_consensus()

        # Verify second authority was used after first failed
        assert used_authority == authority2
        assert mock_client_instance.get.call_count == 2

    @patch("httpx.Client")
    def test_fetch_consensus_with_custom_timeout(self, mock_client_class):
        """Test that custom timeout is passed to httpx.Client."""
        mock_response = MagicMock()
        mock_response.content = b"data"
        mock_response.raise_for_status = MagicMock()

        mock_client_instance = MagicMock()
        mock_client_instance.get.return_value = mock_response
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.__exit__.return_value = False
        mock_client_class.return_value = mock_client_instance

        authority = DirectoryAuthority(
            nickname="test", ip="192.0.2.1", dirport=9131, orport=9101, v3ident="ABC"
        )
        client = DirectoryClient(timeout=60)

        client.fetch_consensus(authority=authority)

        # Verify timeout was passed to httpx.Client
        mock_client_class.assert_called_once_with(timeout=60)

    @patch("httpx.Client")
    def test_fetch_consensus_http_error(self, mock_client_class):
        """Test handling of HTTP errors."""
        # Setup mock to raise HTTPError
        mock_client_instance = MagicMock()
        mock_client_instance.get.side_effect = httpx.HTTPStatusError(
            "404 Not Found",
            request=MagicMock(),
            response=MagicMock(status_code=404),
        )
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.__exit__.return_value = False
        mock_client_class.return_value = mock_client_instance

        authority = DirectoryAuthority(
            nickname="test", ip="192.0.2.1", dirport=9131, orport=9101, v3ident="ABC"
        )
        client = DirectoryClient()

        with pytest.raises(httpx.HTTPStatusError):
            client.fetch_consensus(authority=authority)


class TestFetchMicrodescriptors:
    """Tests for fetch_microdescriptors method."""

    @patch("httpx.Client")
    def test_fetch_microdescriptors_single_hash(self, mock_client_class):
        """Test fetching a single microdescriptor."""
        mock_response = MagicMock()
        mock_response.content = b"microdescriptor data"
        mock_response.raise_for_status = MagicMock()

        mock_client_instance = MagicMock()
        mock_client_instance.get.return_value = mock_response
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.__exit__.return_value = False
        mock_client_class.return_value = mock_client_instance

        authority = DirectoryAuthority(
            nickname="test", ip="192.0.2.1", dirport=9131, orport=9101, v3ident="ABC"
        )
        client = DirectoryClient()

        hashes = ["dGVzdGhhc2g="]
        content, used_authority = client.fetch_microdescriptors(hashes, authority)

        assert content == b"microdescriptor data"
        assert used_authority == authority

        # Verify URL construction (trailing = should be stripped)
        expected_url = "http://192.0.2.1:9131/tor/micro/d/dGVzdGhhc2g"
        call_args = mock_client_instance.get.call_args
        assert call_args[0][0] == expected_url

    @patch("httpx.Client")
    def test_fetch_microdescriptors_multiple_hashes(self, mock_client_class):
        """Test fetching multiple microdescriptors."""
        mock_response = MagicMock()
        mock_response.content = b"microdescriptor data"
        mock_response.raise_for_status = MagicMock()

        mock_client_instance = MagicMock()
        mock_client_instance.get.return_value = mock_response
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.__exit__.return_value = False
        mock_client_class.return_value = mock_client_instance

        authority = DirectoryAuthority(
            nickname="test", ip="192.0.2.1", dirport=9131, orport=9101, v3ident="ABC"
        )
        client = DirectoryClient()

        hashes = ["aGFzaDE=", "aGFzaDI=", "aGFzaDM="]
        client.fetch_microdescriptors(hashes, authority)

        # Verify URL construction with multiple hashes joined by '-'
        expected_url = "http://192.0.2.1:9131/tor/micro/d/aGFzaDE-aGFzaDI-aGFzaDM"
        call_args = mock_client_instance.get.call_args
        assert call_args[0][0] == expected_url

    @patch("torscope.directory.client.get_random_authority")
    @patch("httpx.Client")
    def test_fetch_microdescriptors_random_authority(
        self, mock_client_class, mock_get_random_authority
    ):
        """Test fetching microdescriptors from random authority."""
        random_authority = DirectoryAuthority(
            nickname="random", ip="192.0.2.100", dirport=80, orport=443, v3ident="XYZ"
        )
        mock_get_random_authority.return_value = random_authority

        mock_response = MagicMock()
        mock_response.content = b"data"
        mock_response.raise_for_status = MagicMock()

        mock_client_instance = MagicMock()
        mock_client_instance.get.return_value = mock_response
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.__exit__.return_value = False
        mock_client_class.return_value = mock_client_instance

        client = DirectoryClient()
        _, used_authority = client.fetch_microdescriptors(["hash="])

        assert used_authority == random_authority


class TestFetchServerDescriptors:
    """Tests for fetch_server_descriptors method."""

    @patch("httpx.Client")
    def test_fetch_server_descriptors_single_fingerprint(self, mock_client_class):
        """Test fetching single server descriptor."""
        mock_response = MagicMock()
        mock_response.content = b"server descriptor data"
        mock_response.raise_for_status = MagicMock()

        mock_client_instance = MagicMock()
        mock_client_instance.get.return_value = mock_response
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.__exit__.return_value = False
        mock_client_class.return_value = mock_client_instance

        authority = DirectoryAuthority(
            nickname="test", ip="192.0.2.1", dirport=9131, orport=9101, v3ident="ABC"
        )
        client = DirectoryClient()

        fingerprints = ["ABCDEF123456"]
        content, used_authority = client.fetch_server_descriptors(fingerprints, authority)

        assert content == b"server descriptor data"
        assert used_authority == authority

        # Verify URL construction
        expected_url = "http://192.0.2.1:9131/tor/server/fp/ABCDEF123456"
        call_args = mock_client_instance.get.call_args
        assert call_args[0][0] == expected_url

    @patch("httpx.Client")
    def test_fetch_server_descriptors_multiple_fingerprints(self, mock_client_class):
        """Test fetching multiple server descriptors."""
        mock_response = MagicMock()
        mock_response.content = b"descriptors data"
        mock_response.raise_for_status = MagicMock()

        mock_client_instance = MagicMock()
        mock_client_instance.get.return_value = mock_response
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.__exit__.return_value = False
        mock_client_class.return_value = mock_client_instance

        authority = DirectoryAuthority(
            nickname="test", ip="192.0.2.1", dirport=9131, orport=9101, v3ident="ABC"
        )
        client = DirectoryClient()

        fingerprints = ["FP1", "FP2", "FP3"]
        client.fetch_server_descriptors(fingerprints, authority)

        # Verify URL construction with fingerprints joined by '+'
        expected_url = "http://192.0.2.1:9131/tor/server/fp/FP1+FP2+FP3"
        call_args = mock_client_instance.get.call_args
        assert call_args[0][0] == expected_url

    @patch("torscope.directory.client.get_random_authority")
    @patch("httpx.Client")
    def test_fetch_server_descriptors_random_authority(
        self, mock_client_class, mock_get_random_authority
    ):
        """Test fetching server descriptors from random authority."""
        random_authority = DirectoryAuthority(
            nickname="random", ip="192.0.2.100", dirport=80, orport=443, v3ident="XYZ"
        )
        mock_get_random_authority.return_value = random_authority

        mock_response = MagicMock()
        mock_response.content = b"data"
        mock_response.raise_for_status = MagicMock()

        mock_client_instance = MagicMock()
        mock_client_instance.get.return_value = mock_response
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.__exit__.return_value = False
        mock_client_class.return_value = mock_client_instance

        client = DirectoryClient()
        _, used_authority = client.fetch_server_descriptors(["FP1"])

        assert used_authority == random_authority

    @patch("httpx.Client")
    def test_fetch_server_descriptors_headers(self, mock_client_class):
        """Test that correct headers are sent."""
        mock_response = MagicMock()
        mock_response.content = b"data"
        mock_response.raise_for_status = MagicMock()

        mock_client_instance = MagicMock()
        mock_client_instance.get.return_value = mock_response
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.__exit__.return_value = False
        mock_client_class.return_value = mock_client_instance

        authority = DirectoryAuthority(
            nickname="test", ip="192.0.2.1", dirport=9131, orport=9101, v3ident="ABC"
        )
        client = DirectoryClient()

        client.fetch_server_descriptors(["FP1"], authority)

        call_args = mock_client_instance.get.call_args
        headers = call_args[1]["headers"]
        assert headers["Accept-Encoding"] == "deflate, gzip"
        assert headers["User-Agent"] == "torscope/0.1.0"
