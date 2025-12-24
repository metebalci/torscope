"""
Circuit-related API endpoints.

Provides endpoints for path selection, circuit building, DNS resolution, and streams.
"""

import traceback

from fastapi import APIRouter, HTTPException

from torscope.api.geoip import get_geoip
from torscope.api.models.circuit import (
    CircuitData,
    CircuitHop,
    CircuitRequest,
    CircuitResponse,
    PathData,
    PathHop,
    PathRequest,
    PathResponse,
    ResolvedAnswer,
    ResolveData,
    ResolveRequest,
    ResolveResponse,
    StreamData,
    StreamRequest,
    StreamResponse,
)
from torscope.api.models.directory import LocationInfo
from torscope.api.routes.directory import get_consensus_cached
from torscope.cli_helpers import find_router
from torscope.microdesc import get_ntor_key
from torscope.onion.circuit import Circuit
from torscope.onion.connection import RelayConnection
from torscope.onion.relay import (
    BEGIN_FLAG_IPV4_NOT_OK,
    BEGIN_FLAG_IPV6_OK,
    BEGIN_FLAG_IPV6_PREFERRED,
    ResolvedType,
)
from torscope.path import PathSelector

router = APIRouter(prefix="/api/v1", tags=["circuit"])

DEFAULT_TIMEOUT = 30.0


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


@router.post("/path", response_model=PathResponse)
async def select_path(request: PathRequest) -> PathResponse:
    """Select a bandwidth-weighted path through the Tor network."""
    try:
        consensus = get_consensus_cached()
        selector = PathSelector(consensus=consensus)

        # Resolve pre-selected routers
        guard = None
        middle = None
        exit_router = None

        if request.guard:
            guard = find_router(consensus, request.guard.strip())
            if guard is None:
                raise HTTPException(status_code=404, detail=f"Guard not found: {request.guard}")

        if request.middle and request.hops >= 3:
            middle = find_router(consensus, request.middle.strip())
            if middle is None:
                raise HTTPException(status_code=404, detail=f"Middle not found: {request.middle}")

        if request.exit and request.hops >= 2:
            exit_router = find_router(consensus, request.exit.strip())
            if exit_router is None:
                raise HTTPException(status_code=404, detail=f"Exit not found: {request.exit}")

        # Select path
        path = selector.select_path(
            num_hops=request.hops,
            target_port=request.port,
            guard=guard,
            middle=middle,
            exit_router=exit_router,
        )

        # Build response
        hops = []
        for role, router in zip(path.roles, path.routers, strict=True):
            hops.append(
                PathHop(
                    role=role,
                    nickname=router.nickname,
                    fingerprint=router.fingerprint,
                    ip=router.ip,
                    orport=router.orport,
                    bandwidth=router.bandwidth,
                    flags=router.flags,
                    location=_get_location(router.ip),
                )
            )

        bottleneck = min((r.bandwidth or 0) for r in path.routers) if path.routers else None

        return PathResponse(
            data={
                "path": PathData(
                    hops=path.hops,
                    routers=hops,
                    bottleneck_bandwidth=bottleneck,
                ).model_dump()
            }
        )

    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/circuit", response_model=CircuitResponse)
async def build_circuit(request: CircuitRequest) -> CircuitResponse:
    """Build a Tor circuit (synchronous, no real-time events)."""
    try:
        consensus = get_consensus_cached()
        selector = PathSelector(consensus=consensus)

        # Resolve pre-selected routers
        guard = None
        middle = None
        exit_router = None

        if request.guard:
            guard = find_router(consensus, request.guard.strip())
            if guard is None:
                raise HTTPException(status_code=404, detail=f"Guard not found: {request.guard}")

        if request.middle and request.hops >= 3:
            middle = find_router(consensus, request.middle.strip())
            if middle is None:
                raise HTTPException(status_code=404, detail=f"Middle not found: {request.middle}")

        if request.exit and request.hops >= 2:
            exit_router = find_router(consensus, request.exit.strip())
            if exit_router is None:
                raise HTTPException(status_code=404, detail=f"Exit not found: {request.exit}")

        # Select path
        path = selector.select_path(
            num_hops=request.hops,
            target_port=request.port,
            guard=guard,
            middle=middle,
            exit_router=exit_router,
        )

        routers = path.routers
        roles = path.roles

        # Fetch ntor keys
        ntor_keys = []
        for r in routers:
            result = get_ntor_key(r, consensus)
            if result is None:
                raise HTTPException(status_code=500, detail=f"No ntor key for {r.nickname}")
            ntor_keys.append(result[0])

        # Connect to first router
        first_router = routers[0]
        conn = RelayConnection(
            host=first_router.ip, port=first_router.orport, timeout=DEFAULT_TIMEOUT
        )

        circuit_hops = []
        circuit_id_str = "0x00000000"
        link_protocol = None

        try:
            conn.connect()

            if not conn.handshake():
                raise HTTPException(status_code=500, detail="Link handshake failed")

            link_protocol = conn.link_protocol

            # Create circuit
            circuit = Circuit.create(conn)
            circuit_id_str = f"0x{circuit.circ_id:08x}"

            # Extend through all hops
            for i, (r, ntor_key) in enumerate(zip(routers, ntor_keys, strict=True)):
                role = roles[i]

                if i == 0:
                    # First hop - CREATE2
                    success = circuit.extend_to(r.fingerprint, ntor_key)
                else:
                    # Subsequent hops - EXTEND2
                    success = circuit.extend_to(r.fingerprint, ntor_key, ip=r.ip, port=r.orport)

                if not success:
                    circuit.destroy()
                    raise HTTPException(status_code=500, detail=f"Failed to extend to hop {i+1}")

                circuit_hops.append(
                    CircuitHop(
                        role=role,
                        nickname=r.nickname,
                        fingerprint=r.fingerprint,
                        status="created" if i == 0 else "extended",
                        location=_get_location(r.ip),
                    )
                )

            # Clean up
            circuit.destroy()

            return CircuitResponse(
                data={
                    "circuit": CircuitData(
                        circuit_id=circuit_id_str,
                        hops=circuit_hops,
                        status="open",
                        link_protocol=link_protocol,
                    ).model_dump()
                }
            )

        finally:
            conn.close()

    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/resolve", response_model=ResolveResponse)
async def resolve_hostname(request: ResolveRequest) -> ResolveResponse:
    """Resolve a hostname through the Tor network."""
    try:
        consensus = get_consensus_cached()
        selector = PathSelector(consensus=consensus)

        # Select 3-hop path
        path = selector.select_path(num_hops=3)
        routers = path.routers

        # Fetch ntor keys
        ntor_keys = []
        for r in routers:
            result = get_ntor_key(r, consensus)
            if result is None:
                raise HTTPException(status_code=500, detail=f"No ntor key for {r.nickname}")
            ntor_keys.append(result[0])

        # Connect
        first_router = routers[0]
        conn = RelayConnection(
            host=first_router.ip, port=first_router.orport, timeout=DEFAULT_TIMEOUT
        )

        try:
            conn.connect()

            if not conn.handshake():
                raise HTTPException(status_code=500, detail="Link handshake failed")

            # Create circuit
            circuit = Circuit.create(conn)

            # Extend through all hops
            for i, (r, ntor_key) in enumerate(zip(routers, ntor_keys, strict=True)):
                if i == 0:
                    success = circuit.extend_to(r.fingerprint, ntor_key)
                else:
                    success = circuit.extend_to(r.fingerprint, ntor_key, ip=r.ip, port=r.orport)

                if not success:
                    circuit.destroy()
                    raise HTTPException(status_code=500, detail=f"Failed to extend to hop {i+1}")

            # Resolve
            raw_answers = circuit.resolve(request.hostname)
            circuit.destroy()

            if not raw_answers:
                return ResolveResponse(
                    data={
                        "resolve": ResolveData(
                            hostname=request.hostname,
                            answers=[],
                        ).model_dump()
                    }
                )

            answers = []
            for ans in raw_answers:
                if ans.addr_type == ResolvedType.IPV4:
                    answers.append(ResolvedAnswer(type="A", value=ans.value, ttl=ans.ttl))
                elif ans.addr_type == ResolvedType.IPV6:
                    answers.append(ResolvedAnswer(type="AAAA", value=ans.value, ttl=ans.ttl))
                elif ans.addr_type == ResolvedType.HOSTNAME:
                    answers.append(ResolvedAnswer(type="PTR", value=ans.value, ttl=ans.ttl))
                elif ans.addr_type == ResolvedType.ERROR_TRANSIENT:
                    answers.append(ResolvedAnswer(type="ERROR_TRANSIENT", value=ans.value))
                elif ans.addr_type == ResolvedType.ERROR_NONTRANSIENT:
                    answers.append(ResolvedAnswer(type="ERROR_NONTRANSIENT", value=ans.value))

            return ResolveResponse(
                data={
                    "resolve": ResolveData(
                        hostname=request.hostname,
                        answers=answers,
                    ).model_dump()
                }
            )

        finally:
            conn.close()

    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/stream", response_model=StreamResponse)
async def open_stream(request: StreamRequest) -> StreamResponse:
    """Open a stream to a destination through Tor."""
    try:
        # Parse destination
        if ":" not in request.destination:
            raise HTTPException(
                status_code=400, detail="Invalid destination format (expected host:port)"
            )

        parts = request.destination.rsplit(":", 1)
        target_addr = parts[0]
        try:
            target_port = int(parts[1])
        except ValueError as e:
            raise HTTPException(status_code=400, detail="Invalid port number") from e

        # Check for .onion
        if target_addr.endswith(".onion"):
            raise HTTPException(
                status_code=400,
                detail="Use /hidden-service endpoint for .onion addresses",
            )

        consensus = get_consensus_cached()
        selector = PathSelector(consensus=consensus)

        # Resolve pre-selected routers
        guard = None
        exit_router = None

        if request.guard:
            guard = find_router(consensus, request.guard.strip())
            if guard is None:
                raise HTTPException(status_code=404, detail=f"Guard not found: {request.guard}")

        if request.exit:
            exit_router = find_router(consensus, request.exit.strip())
            if exit_router is None:
                raise HTTPException(status_code=404, detail=f"Exit not found: {request.exit}")

        # Select path
        path = selector.select_path(
            num_hops=request.hops,
            target_port=target_port,
            guard=guard,
            exit_router=exit_router,
        )

        routers = path.routers

        # Fetch ntor keys
        ntor_keys = []
        for r in routers:
            result = get_ntor_key(r, consensus)
            if result is None:
                raise HTTPException(status_code=500, detail=f"No ntor key for {r.nickname}")
            ntor_keys.append(result[0])

        # Connect
        first_router = routers[0]
        conn = RelayConnection(
            host=first_router.ip, port=first_router.orport, timeout=DEFAULT_TIMEOUT
        )

        try:
            conn.connect()

            if not conn.handshake():
                raise HTTPException(status_code=500, detail="Link handshake failed")

            # Create circuit
            circuit = Circuit.create(conn)

            # Extend through all hops
            for i, (r, ntor_key) in enumerate(zip(routers, ntor_keys, strict=True)):
                if i == 0:
                    success = circuit.extend_to(r.fingerprint, ntor_key)
                else:
                    success = circuit.extend_to(r.fingerprint, ntor_key, ip=r.ip, port=r.orport)

                if not success:
                    circuit.destroy()
                    raise HTTPException(status_code=500, detail=f"Failed to extend to hop {i+1}")

            # Compute BEGIN flags
            begin_flags = 0
            if request.ipv6_ok:
                begin_flags |= BEGIN_FLAG_IPV6_OK
            if request.ipv4_not_ok:
                begin_flags |= BEGIN_FLAG_IPV4_NOT_OK
            if request.ipv6_preferred:
                begin_flags |= BEGIN_FLAG_IPV6_PREFERRED

            # Open stream
            stream_id = circuit.begin_stream(target_addr, target_port, flags=begin_flags)

            if stream_id is None:
                circuit.destroy()
                raise HTTPException(status_code=500, detail="Stream rejected by exit")

            response_data: dict = {
                "stream": StreamData(
                    stream_id=stream_id,
                    destination=request.destination,
                    status="connected",
                ).model_dump()
            }

            # Send HTTP GET if requested
            if request.http_get:
                from torscope import __version__

                http_path = request.http_get
                request_bytes = (
                    f"GET {http_path} HTTP/1.1\r\n"
                    f"Host: {target_addr}\r\n"
                    f"User-Agent: torscope/{__version__}\r\n"
                    f"Accept: */*\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("ascii")

                circuit.send_data(stream_id, request_bytes)

                # Receive response
                response_bytes = b""
                for _ in range(100):
                    chunk = circuit.recv_data(stream_id)
                    if chunk is None:
                        break
                    response_bytes += chunk

                if response_bytes:
                    raw_text = response_bytes.decode("utf-8", errors="replace")

                    # Parse status code
                    status_code = None
                    if raw_text.startswith("HTTP/"):
                        first_line = raw_text.split("\n")[0]
                        parts = first_line.split(" ", 2)
                        if len(parts) >= 2:
                            try:
                                status_code = int(parts[1])
                            except ValueError:
                                pass

                    # Split headers and body
                    headers = {}
                    body = ""
                    if "\r\n\r\n" in raw_text:
                        headers_part, body = raw_text.split("\r\n\r\n", 1)
                    elif "\n\n" in raw_text:
                        headers_part, body = raw_text.split("\n\n", 1)
                    else:
                        headers_part = raw_text

                    for line in headers_part.split("\n"):
                        if ":" in line:
                            key, val = line.split(":", 1)
                            headers[key.strip()] = val.strip()

                    response_data["response"] = {
                        "status_code": status_code,
                        "headers": headers,
                        "body": body,
                        "body_length": len(body),
                    }

            circuit.destroy()

            return StreamResponse(data=response_data)

        finally:
            conn.close()

    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e)) from e
