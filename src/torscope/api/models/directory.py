"""
Directory-related API models.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class LocationInfo(BaseModel):
    """Geographic location information."""

    latitude: float
    longitude: float
    country_code: str
    country_name: str
    city: str | None = None


class AuthorityInfo(BaseModel):
    """Directory authority information."""

    nickname: str
    ip: str
    dirport: int
    orport: int
    v3ident: str
    ipv6_address: str | None = None
    location: LocationInfo | None = None


class AuthoritiesData(BaseModel):
    """Data for authorities response."""

    authorities: list[AuthorityInfo]
    count: int


class AuthoritiesResponse(BaseModel):
    """Response for /authorities endpoint."""

    success: bool = True
    data: AuthoritiesData


class FallbackInfo(BaseModel):
    """Fallback directory information."""

    ip: str
    orport: int
    fingerprint: str
    nickname: str | None = None
    ipv6_address: str | None = None
    location: LocationInfo | None = None


class FallbacksData(BaseModel):
    """Data for fallbacks response."""

    fallbacks: list[FallbackInfo]
    count: int
    total: int


class FallbacksResponse(BaseModel):
    """Response for /fallbacks endpoint."""

    success: bool = True
    data: FallbacksData


class RouterInfo(BaseModel):
    """Router information from consensus."""

    nickname: str
    fingerprint: str
    ip: str
    orport: int
    dirport: int
    flags: list[str]
    bandwidth: int | None = None
    version: str | None = None
    published: datetime | None = None
    exit_policy: str | None = None
    ipv6_addresses: list[str] = []
    location: LocationInfo | None = None


class RoutersData(BaseModel):
    """Data for routers response."""

    routers: list[RouterInfo]
    count: int
    total: int
    consensus_valid_until: datetime | None = None


class RoutersResponse(BaseModel):
    """Response for /routers endpoint."""

    success: bool = True
    data: RoutersData


class DescriptorInfo(BaseModel):
    """Server descriptor details."""

    platform: str | None = None
    bandwidth_avg: int | None = None
    bandwidth_burst: int | None = None
    bandwidth_observed: int | None = None
    uptime_seconds: int | None = None
    uptime_days: float | None = None
    contact: str | None = None
    family: list[str] = []
    exit_policy: list[str] = []
    hibernating: bool = False
    caches_extra_info: bool = False
    tunnelled_dir_server: bool = False


class RouterDetailData(BaseModel):
    """Data for single router response."""

    router: RouterInfo
    descriptor: DescriptorInfo | None = None


class RouterDetailResponse(BaseModel):
    """Response for /router/{query} endpoint."""

    success: bool = True
    data: RouterDetailData


class ConsensusInfo(BaseModel):
    """Consensus metadata."""

    valid_after: datetime
    fresh_until: datetime
    valid_until: datetime
    consensus_method: int
    known_flags: list[str]
    total_routers: int
    params: dict[str, int]
    shared_rand_current: tuple[int, str] | None = None
    shared_rand_previous: tuple[int, str] | None = None


class ConsensusData(BaseModel):
    """Data for consensus response."""

    consensus: ConsensusInfo


class ConsensusResponse(BaseModel):
    """Response for /consensus endpoint."""

    success: bool = True
    data: ConsensusData


class BandwidthHistory(BaseModel):
    """Bandwidth history data."""

    average_bytes_per_second: float
    total_bytes: int


class ExtraInfoData(BaseModel):
    """Extra-info descriptor data."""

    nickname: str
    fingerprint: str
    published: datetime | None = None
    write_history: BandwidthHistory | None = None
    read_history: BandwidthHistory | None = None
    dirreq_v3_ips: dict[str, int] | None = None
    entry_ips: dict[str, int] | None = None
    exit_streams_opened: dict[str, int] | None = None
    exit_kibibytes_written: dict[str, int] | None = None
    exit_kibibytes_read: dict[str, int] | None = None
    hidserv_rend_relayed_cells: int | None = None
    hidserv_dir_onions_seen: int | None = None


class ExtraInfoResponse(BaseModel):
    """Response for /extra-info/{query} endpoint."""

    success: bool = True
    data: dict[str, Any]  # Contains extra_info: ExtraInfoData
