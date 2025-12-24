"""
Hidden service API endpoints.
"""

import base64
import traceback

from fastapi import APIRouter, HTTPException

from torscope.api.geoip import get_geoip
from torscope.api.models.directory import LocationInfo
from torscope.api.models.hidden_service import (
    DescriptorInfo,
    HiddenServiceData,
    HiddenServiceRequest,
    HiddenServiceResponse,
    HSDirectoryInfo,
    IntroductionPointInfo,
    OnionAddressInfo,
    TimePeriodInfo,
)
from torscope.api.routes.directory import get_consensus_cached
from torscope.cli import get_timeout
from torscope.cli_helpers import find_router
from torscope.directory.client_auth import parse_client_auth_key
from torscope.directory.hs_descriptor import fetch_hs_descriptor, parse_hs_descriptor
from torscope.directory.hsdir import HSDirectoryRing
from torscope.onion.address import OnionAddress, get_current_time_period, get_time_period_info

router = APIRouter(prefix="/api/v1", tags=["hidden-service"])


@router.get("/hsdirs/{address}")
async def get_responsible_hsdirs(address: str) -> dict:
    """
    Get the responsible HSDirs for an onion address.

    Returns the 6 HSDirs responsible for storing the descriptor.
    """
    try:
        # Parse onion address
        try:
            onion = OnionAddress.parse(address)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid onion address: {e}") from e

        # Get time period info
        current_period = get_current_time_period()
        period_info = get_time_period_info()

        # Get consensus
        consensus = get_consensus_cached()

        # Compute blinded key
        blinded_key = onion.compute_blinded_key(current_period)

        # Get SRV from consensus
        srv_current = None
        if consensus.shared_rand_current:
            srv_current = base64.b64decode(consensus.shared_rand_current[1])

        if srv_current is None:
            raise HTTPException(status_code=500, detail="No SRV in consensus")

        # Fetch Ed25519 identities for HSDirs
        ed25519_map = HSDirectoryRing.fetch_ed25519_map(consensus)

        # Determine which SRV to use
        hours_into_period = 24 - (period_info["remaining_minutes"] / 60)
        use_previous_srv = hours_into_period >= 12

        # Build HSDir ring
        hsdir_ring = HSDirectoryRing(
            consensus, current_period, use_second_srv=use_previous_srv, ed25519_map=ed25519_map
        )

        if hsdir_ring.size == 0:
            raise HTTPException(status_code=500, detail="No HSDirs in ring")

        # Find responsible HSDirs
        hsdirs = hsdir_ring.get_responsible_hsdirs(blinded_key)

        # Build HSDir info list with locations
        hsdir_list = []
        for h in hsdirs:
            loc = _get_location(h.ip)
            hsdir_list.append(
                {
                    "nickname": h.nickname,
                    "fingerprint": h.fingerprint,
                    "ip": h.ip,
                    "orport": h.orport,
                    "location": loc.model_dump() if loc else None,
                }
            )

        return {
            "success": True,
            "data": {
                "address": onion.address,
                "hsdirs": hsdir_list,
                "ring_size": hsdir_ring.size,
            },
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


def _get_location(ip: str) -> LocationInfo | None:
    """Get location info for an IP address."""
    geoip = get_geoip()
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


@router.post("/hidden-service", response_model=HiddenServiceResponse)
async def access_hidden_service(request: HiddenServiceRequest) -> HiddenServiceResponse:
    """
    Access a v3 hidden service (.onion address).

    Parses the onion address, finds responsible HSDirs, and fetches/decrypts
    the hidden service descriptor.
    """
    try:
        # Parse onion address
        try:
            onion = OnionAddress.parse(request.address)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid onion address: {e}") from e

        # Parse client auth key if provided
        client_privkey = None
        if request.auth_key:
            try:
                client_privkey = parse_client_auth_key(request.auth_key)
            except ValueError as e:
                raise HTTPException(status_code=400, detail=f"Invalid auth key: {e}") from e

        # Get time period info
        current_period = get_current_time_period()
        period_info = get_time_period_info()

        if request.time_period is not None:
            time_period = request.time_period
        else:
            time_period = current_period

        # Get consensus
        consensus = get_consensus_cached()

        # Compute blinded key and subcredential
        blinded_key = onion.compute_blinded_key(time_period)
        subcredential = onion.compute_subcredential(time_period)

        # Get SRV from consensus
        srv_current = None
        if consensus.shared_rand_current:
            srv_current = base64.b64decode(consensus.shared_rand_current[1])

        if srv_current is None:
            raise HTTPException(status_code=500, detail="No SRV in consensus")

        # Fetch Ed25519 identities for HSDirs
        ed25519_map = HSDirectoryRing.fetch_ed25519_map(consensus)

        # Determine which SRV to use
        hours_into_period = 24 - (period_info["remaining_minutes"] / 60)
        use_previous_srv = hours_into_period >= 12

        # Build HSDir ring
        hsdir_ring = HSDirectoryRing(
            consensus, time_period, use_second_srv=use_previous_srv, ed25519_map=ed25519_map
        )

        if hsdir_ring.size == 0:
            raise HTTPException(status_code=500, detail="No HSDirs in ring")

        # Find responsible HSDirs
        if request.hsdir:
            hsdir = find_router(consensus, request.hsdir.strip())
            if hsdir is None:
                raise HTTPException(status_code=404, detail=f"HSDir not found: {request.hsdir}")
            hsdirs = [hsdir]
        else:
            hsdirs = hsdir_ring.get_responsible_hsdirs(blinded_key)

        # Build HSDir info list
        hsdir_list = []
        for h in hsdirs:
            hsdir_list.append(
                HSDirectoryInfo(
                    nickname=h.nickname,
                    fingerprint=h.fingerprint,
                    ip=h.ip,
                    orport=h.orport,
                    location=_get_location(h.ip),
                )
            )

        # Fetch descriptor
        descriptor_text = None

        for hsdir in hsdirs[:6]:
            try:
                result = fetch_hs_descriptor(
                    consensus=consensus,
                    hsdir=hsdir,
                    blinded_key=blinded_key,
                    timeout=get_timeout(),
                    use_3hop_circuit=True,
                    verbose=False,
                )
                if result:
                    descriptor_text, _ = result
                    break
            except Exception:  # pylint: disable=broad-exception-caught
                continue

        descriptor_info = None
        if descriptor_text:
            try:
                descriptor = parse_hs_descriptor(
                    descriptor_text, blinded_key, subcredential, client_privkey=client_privkey
                )

                intro_points = []
                if descriptor.decrypted and descriptor.introduction_points:
                    for i, ip in enumerate(descriptor.introduction_points):
                        # Parse link specifiers: list of (type, bytes)
                        link_specs = []
                        ip_addr = None
                        for spec_type, spec_data in ip.link_specifiers:
                            if spec_type == 0 and len(spec_data) == 6:  # TLS_TCP_IPV4
                                addr = ".".join(str(b) for b in spec_data[:4])
                                port = int.from_bytes(spec_data[4:6], "big")
                                link_specs.append({"type": "ipv4", "value": f"{addr}:{port}"})
                                ip_addr = addr
                            elif spec_type == 1 and len(spec_data) == 18:  # TLS_TCP_IPV6
                                # Skip IPv6 for now
                                link_specs.append({"type": "ipv6", "value": spec_data.hex()})
                            elif spec_type == 2:  # Legacy ID
                                link_specs.append({"type": "legacy_id", "value": spec_data.hex()})
                            elif spec_type == 3:  # Ed25519 ID
                                link_specs.append({"type": "ed25519_id", "value": spec_data.hex()})

                        intro_points.append(
                            IntroductionPointInfo(
                                index=i,
                                link_specifiers=link_specs,
                                onion_key=(
                                    base64.b64encode(ip.onion_key_ntor).decode()
                                    if ip.onion_key_ntor
                                    else ""
                                ),
                                auth_key=(
                                    base64.b64encode(ip.auth_key).decode() if ip.auth_key else ""
                                ),
                                enc_key=base64.b64encode(ip.enc_key).decode() if ip.enc_key else "",
                                location=_get_location(ip_addr) if ip_addr else None,
                            )
                        )

                descriptor_info = DescriptorInfo(
                    version=descriptor.outer.version,
                    revision_counter=descriptor.outer.revision_counter,
                    lifetime_minutes=descriptor.outer.descriptor_lifetime,
                    decrypted=descriptor.decrypted,
                    introduction_points=intro_points,
                    decryption_error=descriptor.decryption_error,
                )

            except Exception as e:  # pylint: disable=broad-exception-caught
                descriptor_info = DescriptorInfo(
                    version=3,
                    revision_counter=0,
                    lifetime_minutes=0,
                    decrypted=False,
                    decryption_error=str(e),
                )

        return HiddenServiceResponse(
            data={
                "hidden_service": HiddenServiceData(
                    onion_address=OnionAddressInfo(
                        address=onion.address,
                        version=onion.version,
                        public_key=onion.public_key.hex(),
                        checksum=onion.checksum.hex(),
                    ),
                    time_period=TimePeriodInfo(
                        current=current_period,
                        remaining_minutes=period_info["remaining_minutes"],
                    ),
                    blinded_key=blinded_key.hex(),
                    hsdir_ring_size=hsdir_ring.size,
                    responsible_hsdirs=hsdir_list,
                    descriptor=descriptor_info,
                ).model_dump()
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e)) from e
