"""Tests for OR protocol directory client."""

import base64
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from torscope.directory.models import ConsensusDocument, RouterStatusEntry
from torscope.directory.or_client import ORDirectoryClient, fetch_ntor_key


# =============================================================================
# Test Helpers
# =============================================================================


def make_router(
    nickname: str,
    identity_hex: str,
    flags: list[str] | None = None,
    ip: str = "192.0.2.1",
    orport: int = 9001,
) -> RouterStatusEntry:
    """Create a RouterStatusEntry for testing."""
    fp_bytes = bytes.fromhex(identity_hex)
    identity_b64 = base64.b64encode(fp_bytes).decode("ascii").rstrip("=")

    return RouterStatusEntry(
        nickname=nickname,
        identity=identity_b64,
        digest="AAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        published=datetime(2024, 1, 1, 0, 0, 0),
        ip=ip,
        orport=orport,
        dirport=9030,
        flags=flags or ["Fast", "Running", "Stable", "Valid"],
        bandwidth=1000000,
    )


def make_consensus(routers: list[RouterStatusEntry]) -> MagicMock:
    """Create a mock ConsensusDocument."""
    mock = MagicMock(spec=ConsensusDocument)
    mock.routers = routers
    return mock


# =============================================================================
# Tests for fetch_ntor_key()
# =============================================================================


class TestFetchNtorKey:
    """Tests for fetch_ntor_key()."""

    @patch("torscope.directory.descriptor.ServerDescriptorParser")
    @patch("torscope.directory.client.DirectoryClient")
    def test_fetch_ntor_key_success(self, mock_client_class, mock_parser_class):
        """Test successful ntor key fetch."""
        # Create mock descriptor with ntor key
        mock_desc = MagicMock()
        # Valid base64 ntor key (32 bytes)
        ntor_key_bytes = b"A" * 32
        mock_desc.ntor_onion_key = base64.b64encode(ntor_key_bytes).decode()

        mock_parser_class.parse.return_value = [mock_desc]

        mock_authority = MagicMock()
        mock_authority.nickname = "moria1"

        mock_client = MagicMock()
        mock_client.fetch_server_descriptors.return_value = (b"descriptor", mock_authority)
        mock_client_class.return_value = mock_client

        result = fetch_ntor_key("AABBCCDD" * 5)

        assert result is not None
        key, authority = result
        assert len(key) == 32
        assert authority == "moria1"

    @patch("torscope.directory.descriptor.ServerDescriptorParser")
    @patch("torscope.directory.client.DirectoryClient")
    def test_fetch_ntor_key_no_descriptors(self, mock_client_class, mock_parser_class):
        """Test fetch when no descriptors returned."""
        mock_parser_class.parse.return_value = []

        mock_client = MagicMock()
        mock_client.fetch_server_descriptors.return_value = (b"", MagicMock())
        mock_client_class.return_value = mock_client

        result = fetch_ntor_key("AABBCCDD" * 5)

        assert result is None

    @patch("torscope.directory.descriptor.ServerDescriptorParser")
    @patch("torscope.directory.client.DirectoryClient")
    def test_fetch_ntor_key_no_ntor_key(self, mock_client_class, mock_parser_class):
        """Test fetch when descriptor has no ntor key."""
        mock_desc = MagicMock()
        mock_desc.ntor_onion_key = None

        mock_parser_class.parse.return_value = [mock_desc]

        mock_client = MagicMock()
        mock_client.fetch_server_descriptors.return_value = (b"descriptor", MagicMock())
        mock_client_class.return_value = mock_client

        result = fetch_ntor_key("AABBCCDD" * 5)

        assert result is None

    @patch("torscope.directory.descriptor.ServerDescriptorParser")
    @patch("torscope.directory.client.DirectoryClient")
    def test_fetch_ntor_key_adds_padding(self, mock_client_class, mock_parser_class):
        """Test fetch adds base64 padding if needed."""
        mock_desc = MagicMock()
        # Base64 without padding
        ntor_key_bytes = b"B" * 32
        mock_desc.ntor_onion_key = base64.b64encode(ntor_key_bytes).decode().rstrip("=")

        mock_parser_class.parse.return_value = [mock_desc]

        mock_authority = MagicMock()
        mock_authority.nickname = "tor26"

        mock_client = MagicMock()
        mock_client.fetch_server_descriptors.return_value = (b"descriptor", mock_authority)
        mock_client_class.return_value = mock_client

        result = fetch_ntor_key("AABBCCDD" * 5)

        assert result is not None
        key, _ = result
        assert key == ntor_key_bytes


# =============================================================================
# Tests for ORDirectoryClient
# =============================================================================


class TestORDirectoryClientInit:
    """Tests for ORDirectoryClient initialization."""

    def test_init_with_consensus(self):
        """Test initialization with consensus."""
        routers = [make_router("relay1", "AA" * 20)]
        consensus = make_consensus(routers)

        client = ORDirectoryClient(consensus)

        assert client.consensus == consensus
        assert client.timeout == 30.0

    def test_init_with_custom_timeout(self):
        """Test initialization with custom timeout."""
        consensus = make_consensus([])

        client = ORDirectoryClient(consensus, timeout=60.0)

        assert client.timeout == 60.0


class TestSelectV2dirRelay:
    """Tests for ORDirectoryClient._select_v2dir_relay()."""

    def test_selects_v2dir_relay(self):
        """Test selecting a relay with V2Dir flag."""
        routers = [
            make_router("v2dir_relay", "AA" * 20, ["V2Dir", "Fast", "Stable", "Running"]),
            make_router("no_v2dir", "BB" * 20, ["Fast", "Stable", "Running"]),
        ]
        consensus = make_consensus(routers)
        client = ORDirectoryClient(consensus)

        # Only one valid candidate
        result = client._select_v2dir_relay()

        assert result is not None
        assert result.nickname == "v2dir_relay"

    def test_requires_fast_and_stable(self):
        """Test that Fast and Stable flags are required."""
        routers = [
            make_router("only_v2dir", "AA" * 20, ["V2Dir", "Running"]),
            make_router("v2dir_fast", "BB" * 20, ["V2Dir", "Fast", "Running"]),
            make_router("complete", "CC" * 20, ["V2Dir", "Fast", "Stable", "Running"]),
        ]
        consensus = make_consensus(routers)
        client = ORDirectoryClient(consensus)

        result = client._select_v2dir_relay()

        assert result is not None
        assert result.nickname == "complete"

    def test_returns_none_when_no_candidates(self):
        """Test returns None when no suitable relay found."""
        routers = [
            make_router("no_v2dir", "AA" * 20, ["Fast", "Stable", "Running"]),
        ]
        consensus = make_consensus(routers)
        client = ORDirectoryClient(consensus)

        result = client._select_v2dir_relay()

        assert result is None

    def test_excludes_specified_fingerprints(self):
        """Test excluding specific fingerprints."""
        routers = [
            make_router("relay1", "AA" * 20, ["V2Dir", "Fast", "Stable", "Running"]),
            make_router("relay2", "BB" * 20, ["V2Dir", "Fast", "Stable", "Running"]),
        ]
        consensus = make_consensus(routers)
        client = ORDirectoryClient(consensus)

        # Exclude relay1
        result = client._select_v2dir_relay(exclude=["AA" * 20])

        assert result is not None
        assert result.nickname == "relay2"

    def test_exclude_all_candidates(self):
        """Test returns None when all candidates excluded."""
        routers = [
            make_router("relay1", "AA" * 20, ["V2Dir", "Fast", "Stable", "Running"]),
        ]
        consensus = make_consensus(routers)
        client = ORDirectoryClient(consensus)

        result = client._select_v2dir_relay(exclude=["AA" * 20])

        assert result is None


class TestGetNtorKey:
    """Tests for ORDirectoryClient._get_ntor_key()."""

    @patch("torscope.directory.or_client.fetch_ntor_key")
    def test_get_ntor_key_success(self, mock_fetch):
        """Test successful ntor key fetch."""
        mock_fetch.return_value = (b"X" * 32, "authority")

        consensus = make_consensus([])
        client = ORDirectoryClient(consensus, timeout=45.0)

        result = client._get_ntor_key("AABBCCDD" * 5)

        assert result == b"X" * 32
        mock_fetch.assert_called_once_with("AABBCCDD" * 5, 45)

    @patch("torscope.directory.or_client.fetch_ntor_key")
    def test_get_ntor_key_returns_none(self, mock_fetch):
        """Test returns None when fetch fails."""
        mock_fetch.return_value = None

        consensus = make_consensus([])
        client = ORDirectoryClient(consensus)

        result = client._get_ntor_key("AABBCCDD" * 5)

        assert result is None


class TestFetchViaBeginDir:
    """Tests for ORDirectoryClient._fetch_via_begin_dir()."""

    @patch("torscope.directory.or_client.RelayConnection")
    @patch("torscope.directory.or_client.Circuit")
    @patch.object(ORDirectoryClient, "_get_ntor_key")
    def test_fetch_success(self, mock_get_key, mock_circuit_class, mock_conn_class):
        """Test successful fetch via BEGIN_DIR."""
        mock_get_key.return_value = b"K" * 32

        # Setup mock connection
        mock_conn = MagicMock()
        mock_conn.handshake.return_value = True
        mock_conn_class.return_value = mock_conn

        # Setup mock circuit
        mock_circuit = MagicMock()
        mock_circuit.extend_to.return_value = True
        mock_circuit.begin_dir.return_value = 1
        mock_circuit.recv_data.side_effect = [
            b"HTTP/1.0 200 OK\r\n\r\nbody content",
            None,
        ]
        mock_circuit_class.create.return_value = mock_circuit

        relay = make_router("relay1", "AA" * 20, ["V2Dir", "Fast", "Stable"])
        consensus = make_consensus([relay])
        client = ORDirectoryClient(consensus)

        body, used_relay = client._fetch_via_begin_dir(relay, "/tor/test")

        assert body == b"body content"
        assert used_relay == relay
        mock_circuit.destroy.assert_called()

    @patch.object(ORDirectoryClient, "_get_ntor_key")
    def test_fetch_no_ntor_key(self, mock_get_key):
        """Test raises when no ntor key available."""
        mock_get_key.return_value = None

        relay = make_router("relay1", "AA" * 20)
        consensus = make_consensus([relay])
        client = ORDirectoryClient(consensus)

        with pytest.raises(RuntimeError, match="No ntor-onion-key"):
            client._fetch_via_begin_dir(relay, "/tor/test")

    @patch("torscope.directory.or_client.RelayConnection")
    @patch.object(ORDirectoryClient, "_get_ntor_key")
    def test_fetch_handshake_fails(self, mock_get_key, mock_conn_class):
        """Test raises when handshake fails."""
        mock_get_key.return_value = b"K" * 32

        mock_conn = MagicMock()
        mock_conn.handshake.return_value = False
        mock_conn_class.return_value = mock_conn

        relay = make_router("relay1", "AA" * 20)
        consensus = make_consensus([relay])
        client = ORDirectoryClient(consensus)

        with pytest.raises(ConnectionError, match="handshake failed"):
            client._fetch_via_begin_dir(relay, "/tor/test")

    @patch("torscope.directory.or_client.RelayConnection")
    @patch("torscope.directory.or_client.Circuit")
    @patch.object(ORDirectoryClient, "_get_ntor_key")
    def test_fetch_create2_fails(self, mock_get_key, mock_circuit_class, mock_conn_class):
        """Test raises when CREATE2 fails."""
        mock_get_key.return_value = b"K" * 32

        mock_conn = MagicMock()
        mock_conn.handshake.return_value = True
        mock_conn_class.return_value = mock_conn

        mock_circuit = MagicMock()
        mock_circuit.extend_to.return_value = False
        mock_circuit_class.create.return_value = mock_circuit

        relay = make_router("relay1", "AA" * 20)
        consensus = make_consensus([relay])
        client = ORDirectoryClient(consensus)

        with pytest.raises(RuntimeError, match="CREATE2 failed"):
            client._fetch_via_begin_dir(relay, "/tor/test")

    @patch("torscope.directory.or_client.RelayConnection")
    @patch("torscope.directory.or_client.Circuit")
    @patch.object(ORDirectoryClient, "_get_ntor_key")
    def test_fetch_begin_dir_rejected(self, mock_get_key, mock_circuit_class, mock_conn_class):
        """Test raises when BEGIN_DIR is rejected."""
        mock_get_key.return_value = b"K" * 32

        mock_conn = MagicMock()
        mock_conn.handshake.return_value = True
        mock_conn_class.return_value = mock_conn

        mock_circuit = MagicMock()
        mock_circuit.extend_to.return_value = True
        mock_circuit.begin_dir.return_value = None
        mock_circuit_class.create.return_value = mock_circuit

        relay = make_router("relay1", "AA" * 20)
        consensus = make_consensus([relay])
        client = ORDirectoryClient(consensus)

        with pytest.raises(RuntimeError, match="BEGIN_DIR rejected"):
            client._fetch_via_begin_dir(relay, "/tor/test")

    @patch("torscope.directory.or_client.RelayConnection")
    @patch("torscope.directory.or_client.Circuit")
    @patch.object(ORDirectoryClient, "_get_ntor_key")
    def test_fetch_no_response(self, mock_get_key, mock_circuit_class, mock_conn_class):
        """Test raises when no response received."""
        mock_get_key.return_value = b"K" * 32

        mock_conn = MagicMock()
        mock_conn.handshake.return_value = True
        mock_conn_class.return_value = mock_conn

        mock_circuit = MagicMock()
        mock_circuit.extend_to.return_value = True
        mock_circuit.begin_dir.return_value = 1
        mock_circuit.recv_data.return_value = None  # No data
        mock_circuit_class.create.return_value = mock_circuit

        relay = make_router("relay1", "AA" * 20)
        consensus = make_consensus([relay])
        client = ORDirectoryClient(consensus)

        with pytest.raises(RuntimeError, match="No response"):
            client._fetch_via_begin_dir(relay, "/tor/test")


class TestFetchConsensus:
    """Tests for ORDirectoryClient.fetch_consensus()."""

    @patch.object(ORDirectoryClient, "_fetch_via_begin_dir")
    @patch.object(ORDirectoryClient, "_select_v2dir_relay")
    def test_fetch_consensus_default(self, mock_select, mock_fetch):
        """Test fetching microdesc consensus by default."""
        relay = make_router("relay1", "AA" * 20)
        mock_select.return_value = relay
        mock_fetch.return_value = (b"consensus", relay)

        consensus = make_consensus([relay])
        client = ORDirectoryClient(consensus)

        body, used = client.fetch_consensus()

        assert body == b"consensus"
        mock_fetch.assert_called_with(relay, "/tor/status-vote/current/consensus-microdesc")

    @patch.object(ORDirectoryClient, "_fetch_via_begin_dir")
    @patch.object(ORDirectoryClient, "_select_v2dir_relay")
    def test_fetch_consensus_full(self, mock_select, mock_fetch):
        """Test fetching full consensus."""
        relay = make_router("relay1", "AA" * 20)
        mock_select.return_value = relay
        mock_fetch.return_value = (b"consensus", relay)

        consensus = make_consensus([relay])
        client = ORDirectoryClient(consensus)

        body, used = client.fetch_consensus(consensus_type="full")

        mock_fetch.assert_called_with(relay, "/tor/status-vote/current/consensus")

    @patch.object(ORDirectoryClient, "_fetch_via_begin_dir")
    def test_fetch_consensus_specific_relay(self, mock_fetch):
        """Test fetching from specific relay."""
        relay = make_router("specific", "AA" * 20)
        mock_fetch.return_value = (b"consensus", relay)

        consensus = make_consensus([])
        client = ORDirectoryClient(consensus)

        body, used = client.fetch_consensus(relay=relay)

        assert used == relay

    @patch.object(ORDirectoryClient, "_select_v2dir_relay")
    def test_fetch_consensus_no_relay(self, mock_select):
        """Test raises when no suitable relay found."""
        mock_select.return_value = None

        consensus = make_consensus([])
        client = ORDirectoryClient(consensus)

        with pytest.raises(RuntimeError, match="No suitable V2Dir relay"):
            client.fetch_consensus()


class TestFetchServerDescriptors:
    """Tests for ORDirectoryClient.fetch_server_descriptors()."""

    @patch.object(ORDirectoryClient, "_fetch_via_begin_dir")
    @patch.object(ORDirectoryClient, "_select_v2dir_relay")
    def test_fetch_server_descriptors(self, mock_select, mock_fetch):
        """Test fetching server descriptors."""
        relay = make_router("relay1", "AA" * 20)
        mock_select.return_value = relay
        mock_fetch.return_value = (b"descriptors", relay)

        consensus = make_consensus([relay])
        client = ORDirectoryClient(consensus)

        body, used = client.fetch_server_descriptors(["AABB" * 10, "CCDD" * 10])

        expected_path = f"/tor/server/fp/{'AABB' * 10}+{'CCDD' * 10}"
        mock_fetch.assert_called_with(relay, expected_path)

    @patch.object(ORDirectoryClient, "_select_v2dir_relay")
    def test_fetch_server_descriptors_no_relay(self, mock_select):
        """Test raises when no suitable relay found."""
        mock_select.return_value = None

        consensus = make_consensus([])
        client = ORDirectoryClient(consensus)

        with pytest.raises(RuntimeError, match="No suitable V2Dir relay"):
            client.fetch_server_descriptors(["AABB" * 10])


class TestFetchExtraInfo:
    """Tests for ORDirectoryClient.fetch_extra_info()."""

    @patch.object(ORDirectoryClient, "_fetch_via_begin_dir")
    @patch.object(ORDirectoryClient, "_select_v2dir_relay")
    def test_fetch_extra_info(self, mock_select, mock_fetch):
        """Test fetching extra-info descriptors."""
        relay = make_router("relay1", "AA" * 20)
        mock_select.return_value = relay
        mock_fetch.return_value = (b"extra-info", relay)

        consensus = make_consensus([relay])
        client = ORDirectoryClient(consensus)

        body, used = client.fetch_extra_info(["AABB" * 10])

        expected_path = f"/tor/extra/fp/{'AABB' * 10}"
        mock_fetch.assert_called_with(relay, expected_path)

    @patch.object(ORDirectoryClient, "_select_v2dir_relay")
    def test_fetch_extra_info_no_relay(self, mock_select):
        """Test raises when no suitable relay found."""
        mock_select.return_value = None

        consensus = make_consensus([])
        client = ORDirectoryClient(consensus)

        with pytest.raises(RuntimeError, match="No suitable V2Dir relay"):
            client.fetch_extra_info(["AABB" * 10])


class TestFetchMicrodescriptors:
    """Tests for ORDirectoryClient.fetch_microdescriptors()."""

    @patch.object(ORDirectoryClient, "_fetch_via_begin_dir")
    @patch.object(ORDirectoryClient, "_select_v2dir_relay")
    def test_fetch_microdescriptors(self, mock_select, mock_fetch):
        """Test fetching microdescriptors."""
        relay = make_router("relay1", "AA" * 20)
        mock_select.return_value = relay
        mock_fetch.return_value = (b"microdesc", relay)

        consensus = make_consensus([relay])
        client = ORDirectoryClient(consensus)

        # Hashes with trailing =
        hashes = ["abc123==", "def456="]
        body, used = client.fetch_microdescriptors(hashes)

        # Should strip = and join with -
        expected_path = "/tor/micro/d/abc123-def456"
        mock_fetch.assert_called_with(relay, expected_path)

    @patch.object(ORDirectoryClient, "_select_v2dir_relay")
    def test_fetch_microdescriptors_no_relay(self, mock_select):
        """Test raises when no suitable relay found."""
        mock_select.return_value = None

        consensus = make_consensus([])
        client = ORDirectoryClient(consensus)

        with pytest.raises(RuntimeError, match="No suitable V2Dir relay"):
            client.fetch_microdescriptors(["abc123"])
