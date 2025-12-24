"""
WebSocket handlers for circuit building with real-time events.
"""

import asyncio
import functools
import traceback
from collections.abc import Callable, Coroutine
from typing import Any

from torscope.api.geoip import get_geoip
from torscope.api.models.directory import LocationInfo
from torscope.cli_helpers import find_router
from torscope.directory.models import ConsensusDocument, RouterStatusEntry
from torscope.microdesc import get_ntor_key
from torscope.onion.circuit import Circuit
from torscope.onion.connection import RelayConnection
from torscope.path import PathSelector

DEFAULT_TIMEOUT = 30.0
MAX_RETRIES = 3


def _get_location(ip: str) -> dict[str, Any] | None:
    """Get location info for an IP address as dict."""
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
    ).model_dump()


def _router_info(router: RouterStatusEntry, role: str) -> dict[str, Any]:
    """Get router info as dict for events."""
    return {
        "nickname": router.nickname,
        "fingerprint": router.fingerprint,
        "ip": router.ip,
        "orport": router.orport,
        "bandwidth": router.bandwidth,
        "flags": router.flags,
        "role": role,
        "location": _get_location(router.ip),
    }


class CircuitBuilder:
    """
    Circuit builder with event emission for WebSocket.

    Emits events at each step of circuit building for real-time visualization.
    """

    def __init__(
        self,
        emit: Callable[[str, dict[str, Any]], Coroutine[Any, Any, None]],
    ) -> None:
        """
        Initialize circuit builder.

        Args:
            emit: Async callback to emit events (event_name, data)
        """
        self.emit = emit
        self._cancelled = False

    def cancel(self) -> None:
        """Cancel the current operation."""
        self._cancelled = True

    async def build_circuit(
        self,
        consensus: ConsensusDocument,
        hops: int = 3,
        guard: str | None = None,
        middle: str | None = None,
        exit_router: str | None = None,
        port: int | None = None,
    ) -> dict[str, Any] | None:
        """
        Build a circuit with real-time events and automatic retry.

        Args:
            consensus: Network consensus
            hops: Number of hops (1-3)
            guard: Guard router query (nickname or fingerprint)
            middle: Middle router query
            exit_router: Exit router query
            port: Target port for exit filtering

        Returns:
            Circuit info dict on success, None on failure
        """
        self._cancelled = False

        selector = PathSelector(consensus=consensus)

        # Resolve pre-selected routers (only once, outside retry loop)
        guard_router = None
        middle_router = None
        exit_r = None

        if guard:
            guard_router = find_router(consensus, guard.strip())
            if guard_router is None:
                await self.emit("error", {"message": f"Guard not found: {guard}"})
                return None

        if middle and hops >= 3:
            middle_router = find_router(consensus, middle.strip())
            if middle_router is None:
                await self.emit("error", {"message": f"Middle not found: {middle}"})
                return None

        if exit_router and hops >= 2:
            exit_r = find_router(consensus, exit_router.strip())
            if exit_r is None:
                await self.emit("error", {"message": f"Exit not found: {exit_router}"})
                return None

        last_error: str | None = None

        for attempt in range(MAX_RETRIES):
            if self._cancelled:
                await self.emit("circuit.cancelled", {})
                return None

            try:
                result = await self._try_build_circuit(
                    consensus=consensus,
                    selector=selector,
                    hops=hops,
                    port=port,
                    guard_router=guard_router,
                    middle_router=middle_router,
                    exit_router=exit_r,
                    attempt=attempt,
                )
                if result is not None:
                    return result
                # If result is None but no exception, it was a non-retryable failure
                return None

            except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
                last_error = str(e)
                if attempt < MAX_RETRIES - 1:
                    await self.emit(
                        "circuit.retrying",
                        {
                            "attempt": attempt + 1,
                            "max_retries": MAX_RETRIES,
                            "error": last_error,
                            "message": f"Connection failed, retrying ({attempt + 2}/{MAX_RETRIES})",
                        },
                    )
                    continue
                await self.emit(
                    "circuit.failed",
                    {"error": f"All {MAX_RETRIES} attempts failed: {last_error}"},
                )
                return None

            except Exception as e:  # pylint: disable=broad-exception-caught
                traceback.print_exc()
                await self.emit("error", {"message": str(e)})
                return None

        return None

    async def _try_build_circuit(
        self,
        consensus: ConsensusDocument,
        selector: PathSelector,
        hops: int,
        port: int | None,
        guard_router: RouterStatusEntry | None,
        middle_router: RouterStatusEntry | None,
        exit_router: RouterStatusEntry | None,
        attempt: int,
    ) -> dict[str, Any] | None:
        """Try to build a circuit once. Raises on connection errors for retry."""
        # Path selection
        await self.emit("path.selecting", {"hops": hops, "port": port, "attempt": attempt + 1})

        # Select path
        path = selector.select_path(
            num_hops=hops,
            target_port=port,
            guard=guard_router,
            middle=middle_router,
            exit_router=exit_router,
        )

        routers = path.routers
        roles = path.roles

        # Emit path selected event with all routers
        await self.emit(
            "path.selected",
            {
                "hops": path.hops,
                "routers": [_router_info(r, role) for r, role in zip(routers, roles, strict=True)],
            },
        )

        if self._cancelled:
            await self.emit("circuit.cancelled", {})
            return None

        # Fetch ntor keys
        ntor_keys = []
        for r in routers:
            result = get_ntor_key(r, consensus)
            if result is None:
                await self.emit("error", {"message": f"No ntor key for {r.nickname}"})
                return None
            ntor_keys.append(result[0])

        # Connect to first router
        first_router = routers[0]
        await self.emit(
            "connection.connecting",
            {
                "host": first_router.ip,
                "port": first_router.orport,
                "nickname": first_router.nickname,
                "role": "Guard",
                "location": _get_location(first_router.ip),
            },
        )

        if self._cancelled:
            await self.emit("circuit.cancelled", {})
            return None

        # Run blocking I/O in thread pool
        loop = asyncio.get_event_loop()
        conn = RelayConnection(
            host=first_router.ip, port=first_router.orport, timeout=DEFAULT_TIMEOUT
        )

        try:
            # Connect - this may raise ConnectionRefusedError
            await loop.run_in_executor(None, conn.connect)
            await self.emit(
                "connection.tls_established",
                {"nickname": first_router.nickname},
            )

            if self._cancelled:
                await self.emit("circuit.cancelled", {})
                return None

            # Handshake
            success = await loop.run_in_executor(None, conn.handshake)
            if not success:
                await self.emit("circuit.failed", {"error": "Link handshake failed"})
                return None

            await self.emit(
                "connection.connected",
                {
                    "nickname": first_router.nickname,
                    "link_protocol": conn.link_protocol,
                },
            )

            if self._cancelled:
                await self.emit("circuit.cancelled", {})
                return None

            # Create circuit
            circuit = Circuit.create(conn)
            circuit_id_str = f"0x{circuit.circ_id:08x}"

            await self.emit(
                "circuit.created",
                {"circuit_id": circuit_id_str},
            )

            # Extend through all hops
            circuit_hops = []
            for i, (router, ntor_key) in enumerate(zip(routers, ntor_keys, strict=True)):
                role = roles[i]

                await self.emit(
                    "hop.creating",
                    {
                        "hop_number": i + 1,
                        "nickname": router.nickname,
                        "fingerprint": router.fingerprint,
                        "role": role,
                        "handshake_type": "ntor",
                        "location": _get_location(router.ip),
                    },
                )

                if self._cancelled:
                    circuit.destroy()
                    await self.emit("circuit.cancelled", {})
                    return None

                # Extend - use functools.partial to avoid lambda type inference issues
                if i == 0:
                    extend_fn = functools.partial(circuit.extend_to, router.fingerprint, ntor_key)
                else:
                    extend_fn = functools.partial(
                        circuit.extend_to,
                        router.fingerprint,
                        ntor_key,
                        ip=router.ip,
                        port=router.orport,
                    )
                success = await loop.run_in_executor(None, extend_fn)

                if not success:
                    await self.emit(
                        "hop.failed",
                        {
                            "hop_number": i + 1,
                            "nickname": router.nickname,
                            "role": role,
                            "error": "Extension failed",
                        },
                    )
                    circuit.destroy()
                    await self.emit(
                        "circuit.failed",
                        {"error": f"Failed at hop {i + 1}", "failed_at_hop": i + 1},
                    )
                    return None

                await self.emit(
                    "hop.created",
                    {
                        "hop_number": i + 1,
                        "nickname": router.nickname,
                        "role": role,
                        "circuit_id": circuit_id_str,
                    },
                )

                circuit_hops.append(
                    {
                        "nickname": router.nickname,
                        "role": role,
                        "location": _get_location(router.ip),
                    }
                )

            # Circuit complete
            bottleneck = min((r.bandwidth or 0) for r in routers)

            await self.emit(
                "circuit.open",
                {
                    "circuit_id": circuit_id_str,
                    "hops": circuit_hops,
                    "bottleneck_bandwidth": bottleneck,
                },
            )

            # Clean up
            circuit.destroy()
            await self.emit("circuit.closed", {"circuit_id": circuit_id_str})

            return {
                "circuit_id": circuit_id_str,
                "hops": circuit_hops,
                "status": "completed",
            }

        finally:
            conn.close()
