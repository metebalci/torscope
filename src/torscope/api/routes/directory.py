"""
Directory-related API endpoints.

Provides endpoints for authorities, fallbacks, routers, and consensus.
"""

from typing import Literal

from fastapi import APIRouter, HTTPException, Query

from torscope.api.geoip import GeoIPLookup, get_geoip
from torscope.api.models.directory import (
    AuthoritiesData,
    AuthoritiesResponse,
    AuthorityInfo,
    BandwidthHistory,
    ConsensusData,
    ConsensusInfo,
    ConsensusResponse,
    DescriptorInfo,
    ExtraInfoData,
    ExtraInfoResponse,
    FallbackInfo,
    FallbacksData,
    FallbacksResponse,
    LocationInfo,
    RouterDetailData,
    RouterDetailResponse,
    RouterInfo,
    RoutersData,
    RoutersResponse,
)
from torscope.directory.authority import get_authorities
from torscope.directory.client import DirectoryClient
from torscope.directory.descriptor import ServerDescriptorParser
from torscope.directory.extra_info import ExtraInfoParser
from torscope.directory.fallback import get_fallbacks
from torscope.directory.models import ConsensusDocument, RouterStatusEntry

router = APIRouter(prefix="/api/v1", tags=["directory"])

# Module-level consensus cache
_consensus_cache: ConsensusDocument | None = None


def _get_location(ip: str, geoip: GeoIPLookup) -> LocationInfo | None:
    """Get location info for an IP address."""
    loc = geoip.lookup(ip)
    if loc is None:
        return None
    return LocationInfo(
        latitude=loc.latitude,
        longitude=loc.longitude,
        country_code=loc.country_code,
        country_name=loc.country_name,
        city=loc.city,
    )


def _router_to_info(router: RouterStatusEntry, geoip: GeoIPLookup) -> RouterInfo:
    """Convert RouterStatusEntry to RouterInfo."""
    return RouterInfo(
        nickname=router.nickname,
        fingerprint=router.fingerprint,
        ip=router.ip,
        orport=router.orport,
        dirport=router.dirport,
        flags=router.flags,
        bandwidth=router.bandwidth,
        version=router.version,
        published=router.published,
        exit_policy=router.exit_policy,
        ipv6_addresses=router.ipv6_addresses,
        location=_get_location(router.ip, geoip),
    )


def get_consensus_cached() -> ConsensusDocument:
    """Get consensus from cache or fetch from network."""
    global _consensus_cache

    # Import here to avoid circular imports
    from torscope.cli import get_consensus

    if _consensus_cache is None:
        _consensus_cache = get_consensus()
    return _consensus_cache


def clear_consensus_cache() -> None:
    """Clear the consensus cache."""
    global _consensus_cache
    _consensus_cache = None


@router.get("/authorities", response_model=AuthoritiesResponse)
async def list_authorities() -> AuthoritiesResponse:
    """List all 9 directory authorities."""
    geoip = get_geoip()
    authorities = get_authorities()

    auth_list = []
    for auth in authorities:
        # Parse IP from address (format: "ip:port")
        ip = auth.ip

        auth_list.append(
            AuthorityInfo(
                nickname=auth.nickname,
                ip=ip,
                dirport=auth.dirport,
                orport=auth.orport,
                v3ident=auth.v3ident,
                ipv6_address=auth.ipv6_address,
                location=_get_location(ip, geoip),
            )
        )

    return AuthoritiesResponse(
        data=AuthoritiesData(
            authorities=auth_list,
            count=len(auth_list),
        )
    )


@router.get("/fallbacks", response_model=FallbacksResponse)
async def list_fallbacks(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> FallbacksResponse:
    """List fallback directories."""
    geoip = get_geoip()
    fallbacks = get_fallbacks()

    total = len(fallbacks)
    fallbacks = fallbacks[offset : offset + limit]

    fb_list = []
    for fb in fallbacks:
        fb_list.append(
            FallbackInfo(
                ip=fb.ip,
                orport=fb.orport,
                fingerprint=fb.fingerprint,
                nickname=fb.nickname,
                ipv6_address=fb.ipv6_address,
                location=_get_location(fb.ip, geoip),
            )
        )

    return FallbacksResponse(
        data=FallbacksData(
            fallbacks=fb_list,
            count=len(fb_list),
            total=total,
        )
    )


@router.get("/routers", response_model=RoutersResponse)
async def list_routers(
    flags: str | None = Query(default=None, description="Comma-separated flags filter"),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    sort_by: Literal["bandwidth", "nickname", "published"] | None = Query(default=None),
) -> RoutersResponse:
    """List routers from network consensus."""
    geoip = get_geoip()
    consensus = get_consensus_cached()

    routers = consensus.routers

    # Filter by flags
    if flags:
        flag_list = [f.strip() for f in flags.split(",")]
        routers = [r for r in routers if all(r.has_flag(flag) for flag in flag_list)]

    # Sort
    if sort_by == "bandwidth":
        routers = sorted(routers, key=lambda r: r.bandwidth or 0, reverse=True)
    elif sort_by == "nickname":
        routers = sorted(routers, key=lambda r: r.nickname.lower())
    elif sort_by == "published":
        routers = sorted(routers, key=lambda r: r.published, reverse=True)

    total = len(routers)
    routers = routers[offset : offset + limit]

    router_list = [_router_to_info(r, geoip) for r in routers]

    return RoutersResponse(
        data=RoutersData(
            routers=router_list,
            count=len(router_list),
            total=total,
            consensus_valid_until=consensus.valid_until,
        )
    )


@router.get("/router/{query}", response_model=RouterDetailResponse)
async def get_router(query: str) -> RouterDetailResponse:
    """Get details for a specific router by nickname or fingerprint."""
    geoip = get_geoip()
    consensus = get_consensus_cached()

    # Find router
    query_upper = query.upper()
    router = None

    for r in consensus.routers:
        if r.fingerprint.startswith(query_upper):
            router = r
            break
        if r.nickname.upper() == query_upper:
            router = r
            break

    if router is None:
        raise HTTPException(status_code=404, detail=f"Router not found: {query}")

    router_info = _router_to_info(router, geoip)

    # Fetch full descriptor
    descriptor_info = None
    try:
        client = DirectoryClient()
        content, _ = client.fetch_server_descriptors([router.fingerprint])
        descriptors = ServerDescriptorParser.parse(content)

        if descriptors:
            desc = descriptors[0]
            descriptor_info = DescriptorInfo(
                platform=desc.platform,
                bandwidth_avg=desc.bandwidth_avg,
                bandwidth_burst=desc.bandwidth_burst,
                bandwidth_observed=desc.bandwidth_observed,
                uptime_seconds=desc.uptime,
                uptime_days=desc.uptime_days if desc.uptime is not None else None,
                contact=desc.contact,
                family=desc.family,
                exit_policy=desc.exit_policy,
                hibernating=desc.hibernating,
                caches_extra_info=desc.caches_extra_info,
                tunnelled_dir_server=desc.tunnelled_dir_server,
            )
    except Exception:  # pylint: disable=broad-exception-caught
        pass

    return RouterDetailResponse(
        data=RouterDetailData(
            router=router_info,
            descriptor=descriptor_info,
        )
    )


@router.get("/extra-info/{query}", response_model=ExtraInfoResponse)
async def get_extra_info(query: str) -> ExtraInfoResponse:
    """Get extra-info descriptor for a router."""
    consensus = get_consensus_cached()

    # Find router
    query_upper = query.upper()
    router = None

    for r in consensus.routers:
        if r.fingerprint.startswith(query_upper):
            router = r
            break
        if r.nickname.upper() == query_upper:
            router = r
            break

    if router is None:
        raise HTTPException(status_code=404, detail=f"Router not found: {query}")

    # Fetch extra-info
    try:
        client = DirectoryClient()
        content, _ = client.fetch_extra_info([router.fingerprint])
        extra_infos = ExtraInfoParser.parse(content)

        if not extra_infos:
            raise HTTPException(
                status_code=404, detail=f"No extra-info available for {router.nickname}"
            )

        extra = extra_infos[0]

        extra_data = ExtraInfoData(
            nickname=router.nickname,
            fingerprint=router.fingerprint,
            published=extra.published,
            write_history=(
                BandwidthHistory(
                    average_bytes_per_second=extra.write_history.average_bytes_per_second,
                    total_bytes=extra.write_history.total_bytes,
                )
                if extra.write_history
                else None
            ),
            read_history=(
                BandwidthHistory(
                    average_bytes_per_second=extra.read_history.average_bytes_per_second,
                    total_bytes=extra.read_history.total_bytes,
                )
                if extra.read_history
                else None
            ),
            dirreq_v3_ips=extra.dirreq_v3_ips,
            entry_ips=extra.entry_ips,
            exit_streams_opened=extra.exit_streams_opened,
            exit_kibibytes_written=extra.exit_kibibytes_written,
            exit_kibibytes_read=extra.exit_kibibytes_read,
            hidserv_rend_relayed_cells=extra.hidserv_rend_relayed_cells,
            hidserv_dir_onions_seen=extra.hidserv_dir_onions_seen,
        )

        return ExtraInfoResponse(data={"extra_info": extra_data.model_dump()})

    except HTTPException:
        raise
    except Exception as e:  # pylint: disable=broad-exception-caught
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/consensus", response_model=ConsensusResponse)
async def get_consensus_info() -> ConsensusResponse:
    """Get consensus metadata."""
    consensus = get_consensus_cached()

    return ConsensusResponse(
        data=ConsensusData(
            consensus=ConsensusInfo(
                valid_after=consensus.valid_after,
                fresh_until=consensus.fresh_until,
                valid_until=consensus.valid_until,
                consensus_method=consensus.consensus_method,
                known_flags=consensus.known_flags,
                total_routers=consensus.total_routers,
                params=consensus.params,
                shared_rand_current=consensus.shared_rand_current,
                shared_rand_previous=consensus.shared_rand_previous,
            )
        )
    )


@router.post("/consensus/refresh")
async def refresh_consensus() -> dict[str, str]:
    """Force refresh of consensus from network."""
    clear_consensus_cache()
    get_consensus_cached()  # Re-fetch
    return {"status": "refreshed"}
