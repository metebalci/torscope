"""
Hidden service API models.
"""

from pydantic import BaseModel

from torscope.api.models.directory import LocationInfo


class HiddenServiceRequest(BaseModel):
    """Request for hidden service access."""

    address: str  # .onion address
    connect_port: int | None = None  # Port to connect to
    hsdir: str | None = None  # Manually specify HSDir
    auth_key: str | None = None  # Client auth key (base64)
    all_hsdirs: bool = False  # Query all HSDirs
    time_period: int | None = None  # Time period override


class OnionAddressInfo(BaseModel):
    """Parsed onion address info."""

    address: str
    version: int
    public_key: str  # hex
    checksum: str  # hex


class TimePeriodInfo(BaseModel):
    """Time period information."""

    current: int
    remaining_minutes: float


class HSDirectoryInfo(BaseModel):
    """HSDir information."""

    nickname: str
    fingerprint: str
    ip: str
    orport: int
    location: LocationInfo | None = None


class IntroductionPointInfo(BaseModel):
    """Introduction point information."""

    index: int
    link_specifiers: list[dict]  # [{"type": "ipv4", "value": "1.2.3.4:9001"}, ...]
    onion_key: str  # base64
    auth_key: str  # base64
    enc_key: str  # base64
    location: LocationInfo | None = None


class DescriptorInfo(BaseModel):
    """Hidden service descriptor info."""

    version: int
    revision_counter: int
    lifetime_minutes: int
    decrypted: bool
    introduction_points: list[IntroductionPointInfo] = []
    decryption_error: str | None = None


class HiddenServiceData(BaseModel):
    """Hidden service access result."""

    onion_address: OnionAddressInfo
    time_period: TimePeriodInfo
    blinded_key: str  # hex
    hsdir_ring_size: int
    responsible_hsdirs: list[HSDirectoryInfo]
    descriptor: DescriptorInfo | None = None


class HiddenServiceResponse(BaseModel):
    """Response for /hidden-service endpoint."""

    success: bool = True
    data: dict  # Contains HiddenServiceData
