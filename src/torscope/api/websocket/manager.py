"""
WebSocket connection manager.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import WebSocket


class ConnectionManager:
    """Manages WebSocket connections and event broadcasting."""

    def __init__(self) -> None:
        self.active_connections: dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket) -> str:
        """
        Accept a WebSocket connection and assign a session ID.

        Args:
            websocket: The WebSocket connection

        Returns:
            Session ID for this connection
        """
        await websocket.accept()
        session_id = str(uuid.uuid4())
        self.active_connections[session_id] = websocket
        return session_id

    def disconnect(self, session_id: str) -> None:
        """
        Remove a connection.

        Args:
            session_id: The session ID to remove
        """
        if session_id in self.active_connections:
            del self.active_connections[session_id]

    async def send_event(self, session_id: str, event: str, data: dict[str, Any]) -> None:
        """
        Send an event to a specific connection.

        Args:
            session_id: Target session ID
            event: Event type name
            data: Event data
        """
        if session_id in self.active_connections:
            message = {
                "event": event,
                "timestamp": datetime.now(UTC).isoformat(),
                "session_id": session_id,
                "data": data,
            }
            await self.active_connections[session_id].send_json(message)

    async def broadcast(self, event: str, data: dict[str, Any]) -> None:
        """
        Broadcast an event to all connected clients.

        Args:
            event: Event type name
            data: Event data
        """
        message = {
            "event": event,
            "timestamp": datetime.now(UTC).isoformat(),
            "data": data,
        }
        for websocket in self.active_connections.values():
            await websocket.send_json(message)


# Global manager instance
manager = ConnectionManager()
