"""Tests for the CLI module."""

import argparse
import base64
from datetime import datetime
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

from torscope import __version__
from torscope.cli import (
    cmd_authorities,
    cmd_clear,
    cmd_fallbacks,
    cmd_path,
    cmd_router,
    cmd_routers,
    cmd_version,
    main,
)
from torscope.directory.models import ConsensusDocument, RouterStatusEntry


# =============================================================================
# Test Helpers
# =============================================================================


def make_router(
    nickname: str,
    identity_hex: str,
    flags: list[str] | None = None,
    bandwidth: int = 1000000,
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
        bandwidth=bandwidth,
    )


def make_consensus(routers: list[RouterStatusEntry]) -> MagicMock:
    """Create a mock ConsensusDocument."""
    mock = MagicMock(spec=ConsensusDocument)
    mock.routers = routers
    return mock


# =============================================================================
# Basic Command Tests
# =============================================================================


def test_version_command() -> None:
    """Test the version command outputs correct version."""
    args = argparse.Namespace()

    with patch("sys.stdout", new=StringIO()) as fake_out:
        result = cmd_version(args)
        output = fake_out.getvalue()

    assert result == 0
    assert output.strip() == __version__


def test_authorities_command() -> None:
    """Test the authorities command lists all authorities."""
    args = argparse.Namespace()

    with patch("sys.stdout", new=StringIO()) as fake_out:
        result = cmd_authorities(args)
        output = fake_out.getvalue()

    assert result == 0
    assert "Directory Authorities" in output
    assert "moria1" in output
    assert "tor26" in output


def test_clear_command() -> None:
    """Test the clear command clears the cache."""
    args = argparse.Namespace()

    with patch("torscope.cli.clear_cache") as mock_clear:
        with patch("sys.stdout", new=StringIO()) as fake_out:
            result = cmd_clear(args)
            output = fake_out.getvalue()

    assert result == 0
    assert "Cache cleared" in output
    mock_clear.assert_called_once()


def test_fallbacks_command() -> None:
    """Test the fallbacks command lists fallback directories."""
    args = argparse.Namespace()

    with patch("sys.stdout", new=StringIO()) as fake_out:
        result = cmd_fallbacks(args)
        output = fake_out.getvalue()

    assert result == 0
    assert "Fallback Directories" in output
    # Should have at least some fallbacks
    assert "Address:" in output


# =============================================================================
# Routers Command Tests
# =============================================================================


class TestCmdRouters:
    """Tests for cmd_routers()."""

    def test_routers_lists_all(self):
        """Test listing all routers."""
        routers = [
            make_router("relay1", "AA" * 20, ["Fast", "Guard"]),
            make_router("relay2", "BB" * 20, ["Fast", "Exit"]),
        ]
        consensus = make_consensus(routers)
        args = argparse.Namespace(flags=None, list_flags=False)

        with patch("torscope.cli.get_consensus", return_value=consensus):
            with patch("sys.stdout", new=StringIO()) as fake_out:
                result = cmd_routers(args)
                output = fake_out.getvalue()

        assert result == 0
        assert "relay1" in output
        assert "relay2" in output
        assert "2 total" in output

    def test_routers_filter_by_flags(self):
        """Test filtering routers by flags."""
        routers = [
            make_router("guard", "AA" * 20, ["Fast", "Guard", "Stable"]),
            make_router("exit", "BB" * 20, ["Fast", "Exit"]),
            make_router("both", "CC" * 20, ["Fast", "Guard", "Exit"]),
        ]
        consensus = make_consensus(routers)
        args = argparse.Namespace(flags="Guard", list_flags=False)

        with patch("torscope.cli.get_consensus", return_value=consensus):
            with patch("sys.stdout", new=StringIO()) as fake_out:
                result = cmd_routers(args)
                output = fake_out.getvalue()

        assert result == 0
        assert "guard" in output
        assert "both" in output
        # exit doesn't have Guard flag
        assert "2 total" in output

    def test_routers_list_flags(self):
        """Test listing available flags."""
        routers = [
            make_router("r1", "AA" * 20, ["Fast", "Guard"]),
            make_router("r2", "BB" * 20, ["Fast", "Exit"]),
        ]
        consensus = make_consensus(routers)
        args = argparse.Namespace(flags=None, list_flags=True)

        with patch("torscope.cli.get_consensus", return_value=consensus):
            with patch("sys.stdout", new=StringIO()) as fake_out:
                result = cmd_routers(args)
                output = fake_out.getvalue()

        assert result == 0
        assert "Available flags" in output
        assert "Fast" in output
        assert "Guard" in output
        assert "Exit" in output

    def test_routers_handles_error(self):
        """Test error handling in routers command."""
        args = argparse.Namespace(flags=None, list_flags=False)

        with patch("torscope.cli.get_consensus", side_effect=Exception("Network error")):
            with patch("sys.stderr", new=StringIO()) as fake_err:
                result = cmd_routers(args)
                error_output = fake_err.getvalue()

        assert result == 1
        assert "Error" in error_output


# =============================================================================
# Router Command Tests
# =============================================================================


class TestCmdRouter:
    """Tests for cmd_router()."""

    def test_router_by_nickname(self):
        """Test looking up router by nickname."""
        routers = [
            make_router("myrelay", "AA" * 20, ["Fast", "Guard", "Stable"]),
        ]
        consensus = make_consensus(routers)
        args = argparse.Namespace(query="myrelay")

        # Mock descriptor data
        mock_desc = MagicMock()
        mock_desc.platform = "Tor 0.4.8.0"
        mock_desc.bandwidth_avg = 1000000
        mock_desc.bandwidth_burst = 2000000
        mock_desc.bandwidth_observed = 1500000
        mock_desc.uptime = 86400
        mock_desc.uptime_days = 1.0
        mock_desc.contact = "test@example.com"
        mock_desc.family = []
        mock_desc.exit_policy = ["accept *:80"]
        mock_desc.hibernating = False
        mock_desc.caches_extra_info = False
        mock_desc.tunnelled_dir_server = False

        mock_client = MagicMock()
        mock_source = MagicMock()
        mock_source.nickname = "authority"
        mock_client.fetch_server_descriptors.return_value = (b"descriptor", mock_source)

        with patch("torscope.cli.get_consensus", return_value=consensus):
            with patch("torscope.cli.DirectoryClient", return_value=mock_client):
                with patch("torscope.cli.ServerDescriptorParser") as mock_parser:
                    mock_parser.parse.return_value = [mock_desc]
                    with patch("sys.stdout", new=StringIO()) as fake_out:
                        with patch("sys.stderr", new=StringIO()):
                            result = cmd_router(args)
                            output = fake_out.getvalue()

        assert result == 0
        assert "myrelay" in output

    def test_router_by_fingerprint(self):
        """Test looking up router by fingerprint."""
        routers = [
            make_router("myrelay", "ABCD" * 10, ["Fast", "Guard"]),
        ]
        consensus = make_consensus(routers)
        args = argparse.Namespace(query="ABCDABCD")  # Partial fingerprint

        mock_desc = MagicMock()
        mock_desc.platform = "Tor 0.4.8.0"
        mock_desc.bandwidth_avg = 1000000
        mock_desc.bandwidth_burst = 2000000
        mock_desc.bandwidth_observed = 1500000
        mock_desc.uptime = None
        mock_desc.contact = None
        mock_desc.family = None
        mock_desc.exit_policy = []
        mock_desc.hibernating = False
        mock_desc.caches_extra_info = False
        mock_desc.tunnelled_dir_server = False

        mock_client = MagicMock()
        mock_source = MagicMock()
        mock_source.nickname = "authority"
        mock_client.fetch_server_descriptors.return_value = (b"descriptor", mock_source)

        with patch("torscope.cli.get_consensus", return_value=consensus):
            with patch("torscope.cli.DirectoryClient", return_value=mock_client):
                with patch("torscope.cli.ServerDescriptorParser") as mock_parser:
                    mock_parser.parse.return_value = [mock_desc]
                    with patch("sys.stdout", new=StringIO()) as fake_out:
                        with patch("sys.stderr", new=StringIO()):
                            result = cmd_router(args)
                            output = fake_out.getvalue()

        assert result == 0
        assert "myrelay" in output

    def test_router_not_found(self):
        """Test router not found error."""
        routers = [
            make_router("existing", "AA" * 20, ["Fast"]),
        ]
        consensus = make_consensus(routers)
        args = argparse.Namespace(query="nonexistent")

        with patch("torscope.cli.get_consensus", return_value=consensus):
            with patch("sys.stderr", new=StringIO()) as fake_err:
                result = cmd_router(args)
                error_output = fake_err.getvalue()

        assert result == 1
        assert "not found" in error_output.lower()

    def test_router_handles_fetch_error(self):
        """Test error handling when descriptor fetch fails."""
        routers = [
            make_router("myrelay", "AA" * 20, ["Fast"]),
        ]
        consensus = make_consensus(routers)
        args = argparse.Namespace(query="myrelay")

        mock_client = MagicMock()
        mock_client.fetch_server_descriptors.side_effect = Exception("Network error")

        with patch("torscope.cli.get_consensus", return_value=consensus):
            with patch("torscope.cli.DirectoryClient", return_value=mock_client):
                with patch("sys.stderr", new=StringIO()) as fake_err:
                    result = cmd_router(args)
                    error_output = fake_err.getvalue()

        assert result == 1
        assert "Error" in error_output


# =============================================================================
# Path Command Tests
# =============================================================================


class TestCmdPath:
    """Tests for cmd_path()."""

    def test_path_default(self):
        """Test default 3-hop path selection."""
        routers = [
            make_router("guard", "AA" * 20, ["Fast", "Guard", "Stable"], bandwidth=1000000),
            make_router("middle", "BB" * 20, ["Fast", "Stable"], bandwidth=1000000),
            make_router("exit", "CC" * 20, ["Fast", "Exit", "Stable"], bandwidth=1000000),
        ]
        consensus = make_consensus(routers)
        args = argparse.Namespace(hops=3, guard=None, middle=None, exit=None, port=None)

        mock_path = MagicMock()
        mock_path.routers = routers
        mock_path.hops = 3
        mock_path.roles = ["Guard", "Middle", "Exit"]
        mock_path.guard = routers[0]
        mock_path.middle = routers[1]
        mock_path.exit = routers[2]

        with patch("torscope.cli.get_consensus", return_value=consensus):
            with patch("torscope.cli.PathSelector") as mock_selector_class:
                mock_selector_class.return_value.select_path.return_value = mock_path
                with patch("sys.stdout", new=StringIO()) as fake_out:
                    result = cmd_path(args)
                    output = fake_out.getvalue()

        assert result == 0
        assert "guard" in output.lower() or "Guard" in output

    def test_path_with_port(self):
        """Test path selection with exit port requirement."""
        routers = [
            make_router("guard", "AA" * 20, ["Fast", "Guard"]),
            make_router("exit", "BB" * 20, ["Fast", "Exit"]),
        ]
        consensus = make_consensus(routers)
        args = argparse.Namespace(hops=2, guard=None, middle=None, exit=None, port=443)

        mock_path = MagicMock()
        mock_path.routers = routers
        mock_path.hops = 2
        mock_path.roles = ["Guard", "Exit"]
        mock_path.guard = routers[0]
        mock_path.exit = routers[1]

        with patch("torscope.cli.get_consensus", return_value=consensus):
            with patch("torscope.cli.PathSelector") as mock_selector_class:
                mock_selector_class.return_value.select_path.return_value = mock_path
                with patch("sys.stdout", new=StringIO()) as fake_out:
                    result = cmd_path(args)
                    output = fake_out.getvalue()

        assert result == 0

    def test_path_handles_error(self):
        """Test error handling in path command."""
        args = argparse.Namespace(hops=3, guard=None, middle=None, exit=None, port=None)

        with patch("torscope.cli.get_consensus", side_effect=Exception("Network error")):
            with patch("sys.stderr", new=StringIO()) as fake_err:
                result = cmd_path(args)
                error_output = fake_err.getvalue()

        assert result == 1
        assert "Error" in error_output

    def test_path_selection_failure(self):
        """Test handling of path selection ValueError."""
        routers = [
            make_router("relay", "AA" * 20, ["Fast"]),
        ]
        consensus = make_consensus(routers)
        args = argparse.Namespace(hops=3, guard=None, middle=None, exit=None, port=None)

        with patch("torscope.cli.get_consensus", return_value=consensus):
            with patch("torscope.cli.PathSelector") as mock_selector_class:
                mock_selector_class.return_value.select_path.side_effect = ValueError(
                    "Not enough relays"
                )
                with patch("sys.stderr", new=StringIO()) as fake_err:
                    result = cmd_path(args)
                    error_output = fake_err.getvalue()

        assert result == 1
        assert "Path selection failed" in error_output


# =============================================================================
# Main Function Tests
# =============================================================================


def test_main_no_command() -> None:
    """Test that main with no command prints help."""
    with patch("sys.argv", ["torscope"]):
        with patch("sys.stdout", new=StringIO()) as fake_out:
            result = main()
            output = fake_out.getvalue()

    assert result == 0
    assert "usage:" in output.lower() or "torscope" in output


def test_main_version_command() -> None:
    """Test that version subcommand works."""
    with patch("sys.argv", ["torscope", "version"]):
        with patch("sys.stdout", new=StringIO()) as fake_out:
            result = main()
            output = fake_out.getvalue()

    assert result == 0
    assert output.strip() == __version__


def test_main_authorities_command() -> None:
    """Test that authorities subcommand works."""
    with patch("sys.argv", ["torscope", "authorities"]):
        with patch("sys.stdout", new=StringIO()) as fake_out:
            result = main()
            output = fake_out.getvalue()

    assert result == 0
    assert "moria1" in output


def test_main_fallbacks_command() -> None:
    """Test that fallbacks subcommand works."""
    with patch("sys.argv", ["torscope", "fallbacks"]):
        with patch("sys.stdout", new=StringIO()) as fake_out:
            result = main()
            output = fake_out.getvalue()

    assert result == 0
    assert "Fallback" in output


def test_main_clear_command() -> None:
    """Test that clear subcommand works."""
    with patch("sys.argv", ["torscope", "clear"]):
        with patch("torscope.cli.clear_cache"):
            with patch("sys.stdout", new=StringIO()) as fake_out:
                result = main()
                output = fake_out.getvalue()

    assert result == 0
    assert "Cache cleared" in output
