"""Tests for the CLI module."""

from io import StringIO
from unittest.mock import patch

from torscope import __version__
from torscope.cli import TorscopeREPL


def test_version_command() -> None:
    """Test the version command outputs correct version."""
    repl = TorscopeREPL()

    with patch("sys.stdout", new=StringIO()) as fake_out:
        repl.do_version("")
        output = fake_out.getvalue()

    assert output.strip() == __version__


def test_exit_command() -> None:
    """Test the exit command returns True to stop the loop."""
    repl = TorscopeREPL()

    with patch("sys.stdout", new=StringIO()):
        result = repl.do_exit("")

    assert result is True


def test_quit_command() -> None:
    """Test the quit command (alias for exit) returns True."""
    repl = TorscopeREPL()

    with patch("sys.stdout", new=StringIO()):
        result = repl.do_quit("")

    assert result is True


def test_empty_line() -> None:
    """Test that empty line doesn't repeat last command."""
    repl = TorscopeREPL()
    result = repl.emptyline()

    # Returns False to indicate "don't exit the REPL"
    assert result is False


def test_unknown_command() -> None:
    """Test that unknown commands show helpful message."""
    repl = TorscopeREPL()

    with patch("sys.stdout", new=StringIO()) as fake_out:
        repl.default("unknowncommand")
        output = fake_out.getvalue()

    assert "Unknown command" in output
    assert "help" in output
