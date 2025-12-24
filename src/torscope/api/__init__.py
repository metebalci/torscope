"""
Torscope REST and WebSocket API.

Provides JSON endpoints for all torscope functionality plus
real-time WebSocket events for circuit building visualization.
"""

from torscope.api.app import create_app

__all__ = ["create_app"]
