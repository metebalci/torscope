"""Tests for the CLI module."""

import argparse
from io import StringIO
from unittest.mock import patch

from torscope import __version__
from torscope.cli import cmd_authorities, cmd_version, main


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
