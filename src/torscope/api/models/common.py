"""
Common API models for responses and errors.
"""

from typing import Any

from pydantic import BaseModel


class ErrorDetail(BaseModel):
    """Error details."""

    code: str
    message: str
    details: dict[str, Any] | None = None


class APIResponse[T](BaseModel):
    """Standard API response wrapper."""

    success: bool
    data: T | None = None
    error: ErrorDetail | None = None


class ErrorResponse(BaseModel):
    """Error response."""

    success: bool = False
    error: ErrorDetail
