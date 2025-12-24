"""
Pydantic models for API request/response schemas.
"""

from torscope.api.models.common import APIResponse, ErrorDetail, ErrorResponse
from torscope.api.models.directory import (
    AuthoritiesResponse,
    AuthorityInfo,
    ConsensusInfo,
    ConsensusResponse,
    ExtraInfoResponse,
    FallbackInfo,
    FallbacksResponse,
    LocationInfo,
    RouterDetailResponse,
    RouterInfo,
    RoutersResponse,
)

__all__ = [
    "APIResponse",
    "ErrorDetail",
    "ErrorResponse",
    "LocationInfo",
    "AuthorityInfo",
    "AuthoritiesResponse",
    "FallbackInfo",
    "FallbacksResponse",
    "RouterInfo",
    "RoutersResponse",
    "RouterDetailResponse",
    "ConsensusInfo",
    "ConsensusResponse",
    "ExtraInfoResponse",
]
