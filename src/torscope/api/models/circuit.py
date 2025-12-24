"""
Circuit-related API models.
"""

from pydantic import BaseModel

from torscope.api.models.directory import LocationInfo


class PathRequest(BaseModel):
    """Request for path selection."""

    hops: int = 3
    guard: str | None = None
    middle: str | None = None
    exit: str | None = None
    port: int | None = None


class PathHop(BaseModel):
    """A hop in a selected path."""

    role: str  # Guard, Middle, Exit
    nickname: str
    fingerprint: str
    ip: str
    orport: int
    bandwidth: int | None = None
    flags: list[str] = []
    location: LocationInfo | None = None


class PathData(BaseModel):
    """Path selection result data."""

    hops: int
    routers: list[PathHop]
    bottleneck_bandwidth: int | None = None


class PathResponse(BaseModel):
    """Response for /path endpoint."""

    success: bool = True
    data: dict  # Contains "path": PathData


class CircuitRequest(BaseModel):
    """Request for circuit building."""

    hops: int = 3
    guard: str | None = None
    middle: str | None = None
    exit: str | None = None
    port: int | None = None
    bridge: str | None = None


class CircuitHop(BaseModel):
    """A hop in a built circuit."""

    role: str
    nickname: str
    fingerprint: str
    status: str  # created, extended
    location: LocationInfo | None = None


class CircuitData(BaseModel):
    """Circuit building result data."""

    circuit_id: str
    hops: list[CircuitHop]
    status: str  # open, closed, failed
    link_protocol: int | None = None


class CircuitResponse(BaseModel):
    """Response for /circuit endpoint."""

    success: bool = True
    data: dict  # Contains "circuit": CircuitData


class ResolveRequest(BaseModel):
    """Request for DNS resolution."""

    hostname: str


class ResolvedAnswer(BaseModel):
    """A DNS resolution answer."""

    type: str  # A, AAAA, PTR, ERROR
    value: str
    ttl: int | None = None


class ResolveData(BaseModel):
    """DNS resolution result data."""

    hostname: str
    answers: list[ResolvedAnswer]


class ResolveResponse(BaseModel):
    """Response for /resolve endpoint."""

    success: bool = True
    data: dict  # Contains "resolve": ResolveData


class StreamRequest(BaseModel):
    """Request for opening a stream."""

    destination: str  # addr:port
    http_get: str | None = None  # Path for HTTP GET
    hops: int = 3
    guard: str | None = None
    exit: str | None = None
    ipv6_ok: bool = False
    ipv4_not_ok: bool = False
    ipv6_preferred: bool = False


class StreamData(BaseModel):
    """Stream result data."""

    stream_id: int
    destination: str
    status: str  # connected, closed


class HTTPResponse(BaseModel):
    """HTTP response data."""

    status_code: int | None = None
    headers: dict[str, str] = {}
    body: str | None = None
    body_length: int = 0


class StreamResponse(BaseModel):
    """Response for /stream endpoint."""

    success: bool = True
    data: dict  # Contains "stream": StreamData, optionally "response": HTTPResponse
