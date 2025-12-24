"""
API route handlers.
"""

from torscope.api.routes.circuit import router as circuit_router
from torscope.api.routes.directory import router as directory_router
from torscope.api.routes.hidden_service import router as hidden_service_router

__all__ = ["directory_router", "circuit_router", "hidden_service_router"]
