"""
Output context for controlling verbosity levels.

Provides three levels of detail:
- explain: Brief description of what's happening (educational)
- verbose: Protocol-level information (message names, states)
- debug: Raw internals (bytes, payloads, detailed data)

Usage:
    from torscope.output import configure, explain, verbose, debug

    # At CLI startup:
    configure(explain=True, verbose=True, debug=False)

    # Throughout the code:
    explain("Extending circuit to middle relay")
    verbose("EXTEND2 → moria1, waiting for EXTENDED2")
    debug(f"Cell payload: {payload.hex()}")
"""

from dataclasses import dataclass


@dataclass
class OutputContext:
    """Holds the current output verbosity settings."""

    explain: bool = False
    verbose: bool = False
    debug: bool = False


# Module-level context, configured by CLI at startup
_ctx = OutputContext()


def configure(*, explain: bool = False, verbose: bool = False, debug: bool = False) -> None:
    """
    Configure output verbosity levels.

    Args:
        explain: Enable educational explanations of what's happening
        verbose: Enable protocol-level information (message names, states)
        debug: Enable raw internals (bytes, payloads)
    """
    _ctx.explain = explain
    _ctx.verbose = verbose
    _ctx.debug = debug


def is_explain() -> bool:
    """Check if explain mode is enabled."""
    return _ctx.explain


def is_verbose() -> bool:
    """Check if verbose mode is enabled."""
    return _ctx.verbose


def is_debug() -> bool:
    """Check if debug mode is enabled."""
    return _ctx.debug


def explain(message: str) -> None:
    """
    Print educational explanation if --explain is enabled.

    Use for brief, one-line descriptions of what the code is doing.
    Example: "Fetching network consensus from directory authority"
    """
    if _ctx.explain:
        print(f"→ {message}")


def verbose(message: str) -> None:
    """
    Print protocol-level info if --verbose is enabled.

    Use for message names, protocol states, high-level operations.
    Example: "CREATE2 sent, waiting for CREATED2"
    """
    if _ctx.verbose:
        print(f"[verbose] {message}")


def debug(message: str) -> None:
    """
    Print raw debug info if --debug is enabled.

    Use for bytes, hex dumps, internal data structures.
    Example: "Cell payload: 0x0007002000..."
    """
    if _ctx.debug:
        print(f"[debug] {message}")
