"""
FastAPI application setup.
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from torscope import __version__
from torscope.api.geoip import get_geoip, init_geoip
from torscope.api.routes.circuit import router as circuit_router
from torscope.api.routes.directory import router as directory_router
from torscope.api.routes.hidden_service import router as hidden_service_router
from torscope.api.websocket.handlers import CircuitBuilder
from torscope.api.websocket.manager import manager

# Static files directory (look in current working directory)
STATIC_DIR = Path.cwd() / "static"


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager."""
    # Startup - only init if not already initialized (e.g., via --geoip-db flag)
    geoip = get_geoip()
    if not geoip.available:
        geoip = init_geoip()

    if geoip.available:
        db_path = geoip.db_path or "unknown"
        print(f"GeoIP database: {db_path}")
    else:
        print("GeoIP database not available (location data will be empty)")
        print("  Place GeoLite2-City.mmdb in current directory or use --geoip-db")

    yield

    # Shutdown
    geoip = get_geoip()
    geoip.close()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="Torscope API",
        description="REST and WebSocket API for Tor network exploration",
        version=__version__,
        lifespan=lifespan,
    )

    # CORS middleware for web frontend
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure appropriately for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include routers
    app.include_router(directory_router)
    app.include_router(circuit_router)
    app.include_router(hidden_service_router)

    @app.get("/", response_model=None)
    async def root() -> Response:
        """Serve the circuit visualizer page."""
        index_file = STATIC_DIR / "index.html"
        if index_file.exists():
            return FileResponse(
                index_file,
                headers={
                    "Cache-Control": "no-cache, no-store, must-revalidate",
                    "Pragma": "no-cache",
                    "Expires": "0",
                },
            )
        # Fallback: redirect to API docs if no static files
        from fastapi.responses import RedirectResponse

        return RedirectResponse(url="/docs")

    @app.get("/api")
    async def api_info() -> dict[str, str]:
        """API info endpoint."""
        return {
            "name": "Torscope API",
            "version": __version__,
            "docs": "/docs",
            "websocket": "/api/v1/ws",
        }

    @app.get("/health")
    async def health() -> dict[str, str]:
        """Health check endpoint."""
        return {"status": "healthy"}

    @app.websocket("/api/v1/ws")
    async def websocket_endpoint(websocket: WebSocket) -> None:
        """
        WebSocket endpoint for real-time circuit building events.

        Client sends:
            {"action": "build_circuit", "params": {"hops": 3, ...}}
            {"action": "cancel"}

        Server sends events:
            {"event": "path.selected", "timestamp": "...", "data": {...}}
            {"event": "connection.connecting", ...}
            {"event": "hop.creating", ...}
            {"event": "hop.created", ...}
            {"event": "circuit.open", ...}
        """
        session_id = await manager.connect(websocket)
        builder: CircuitBuilder | None = None

        try:
            # Send welcome message
            await manager.send_event(
                session_id,
                "connected",
                {"session_id": session_id, "message": "Connected to Torscope WebSocket"},
            )

            while True:
                data = await websocket.receive_json()
                action = data.get("action")
                params = data.get("params", {})

                if action == "build_circuit":
                    # Import here to avoid circular imports
                    from torscope.api.routes.directory import get_consensus_cached

                    async def emit(event: str, event_data: dict[str, Any]) -> None:
                        await manager.send_event(session_id, event, event_data)

                    builder = CircuitBuilder(emit=emit)
                    consensus = get_consensus_cached()

                    await builder.build_circuit(
                        consensus=consensus,
                        hops=params.get("hops", 3),
                        guard=params.get("guard"),
                        middle=params.get("middle"),
                        exit_router=params.get("exit"),
                        port=params.get("port"),
                    )

                elif action == "cancel":
                    if builder is not None:
                        builder.cancel()
                    await manager.send_event(
                        session_id, "cancelled", {"message": "Operation cancelled"}
                    )

                elif action == "ping":
                    await manager.send_event(session_id, "pong", {})

                else:
                    await manager.send_event(
                        session_id,
                        "error",
                        {"message": f"Unknown action: {action}"},
                    )

        except WebSocketDisconnect:
            pass
        except Exception as e:  # pylint: disable=broad-exception-caught
            await manager.send_event(session_id, "error", {"message": str(e)})
        finally:
            manager.disconnect(session_id)

    return app


# Default app instance
app = create_app()
