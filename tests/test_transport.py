"""Tests for pluggable transport module."""

import pytest

from torscope.onion.transport import (
    TransportError,
    WebTunnelTransport,
    _compute_websocket_accept,
    _generate_websocket_key,
)


class TestWebSocketHelpers:
    """Tests for WebSocket helper functions."""

    def test_generate_websocket_key_length(self):
        """Test that generated key is correct length (base64 of 16 bytes)."""
        key = _generate_websocket_key()
        # 16 bytes base64 encoded = 24 characters (with padding)
        assert len(key) == 24

    def test_generate_websocket_key_unique(self):
        """Test that generated keys are unique."""
        keys = {_generate_websocket_key() for _ in range(100)}
        assert len(keys) == 100

    def test_compute_websocket_accept_known_value(self):
        """Test accept key computation with known value from RFC 6455."""
        # Example from RFC 6455 Section 1.3
        key = "dGhlIHNhbXBsZSBub25jZQ=="
        expected = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        assert _compute_websocket_accept(key) == expected


class TestWebTunnelTransport:
    """Tests for WebTunnelTransport class."""

    def test_init_basic(self):
        """Test basic initialization."""
        transport = WebTunnelTransport(
            host="192.0.2.1",
            port=443,
            url="https://example.com/secret-path",
        )
        assert transport.host == "192.0.2.1"
        assert transport.port == 443
        assert transport.url == "https://example.com/secret-path"
        assert transport.timeout == 30.0

    def test_init_custom_timeout(self):
        """Test initialization with custom timeout."""
        transport = WebTunnelTransport(
            host="192.0.2.1",
            port=443,
            url="https://example.com/path",
            timeout=60.0,
        )
        assert transport.timeout == 60.0

    def test_connect_requires_https(self):
        """Test that HTTP URLs are rejected."""
        transport = WebTunnelTransport(
            host="192.0.2.1",
            port=443,
            url="http://example.com/path",
        )
        with pytest.raises(TransportError, match="requires HTTPS"):
            transport.connect()

    def test_connect_requires_hostname(self):
        """Test that URLs without hostname are rejected."""
        transport = WebTunnelTransport(
            host="192.0.2.1",
            port=443,
            url="https:///path",
        )
        with pytest.raises(TransportError, match="no hostname"):
            transport.connect()

    def test_validate_upgrade_response_success(self):
        """Test successful upgrade response validation."""
        transport = WebTunnelTransport(
            host="192.0.2.1",
            port=443,
            url="https://example.com/path",
        )
        websocket_key = "dGhlIHNhbXBsZSBub25jZQ=="
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {_compute_websocket_accept(websocket_key)}\r\n"
            "\r\n"
        )
        # Should not raise
        transport._validate_upgrade_response(response, websocket_key)

    def test_validate_upgrade_response_wrong_status(self):
        """Test that non-101 status is rejected."""
        transport = WebTunnelTransport(
            host="192.0.2.1",
            port=443,
            url="https://example.com/path",
        )
        response = "HTTP/1.1 404 Not Found\r\n" "Content-Type: text/html\r\n" "\r\n"
        with pytest.raises(TransportError, match="HTTP 404"):
            transport._validate_upgrade_response(response, "somekey")

    def test_validate_upgrade_response_missing_upgrade_header(self):
        """Test that missing Upgrade header is rejected."""
        transport = WebTunnelTransport(
            host="192.0.2.1",
            port=443,
            url="https://example.com/path",
        )
        websocket_key = "dGhlIHNhbXBsZSBub25jZQ=="
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {_compute_websocket_accept(websocket_key)}\r\n"
            "\r\n"
        )
        with pytest.raises(TransportError, match="Upgrade header"):
            transport._validate_upgrade_response(response, websocket_key)

    def test_validate_upgrade_response_wrong_accept_key(self):
        """Test that wrong accept key is rejected."""
        transport = WebTunnelTransport(
            host="192.0.2.1",
            port=443,
            url="https://example.com/path",
        )
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: wrongvalue==\r\n"
            "\r\n"
        )
        with pytest.raises(TransportError, match="Invalid Sec-WebSocket-Accept"):
            transport._validate_upgrade_response(response, "somekey")

    def test_close_no_connection(self):
        """Test closing when not connected."""
        transport = WebTunnelTransport(
            host="192.0.2.1",
            port=443,
            url="https://example.com/path",
        )
        # Should not raise
        transport.close()


class TestCreateTransport:
    """Tests for create_transport function in bridge module."""

    def test_create_transport_direct_bridge(self):
        """Test that direct bridges return None transport."""
        from torscope.directory.bridge import BridgeRelay, create_transport

        bridge = BridgeRelay(
            ip="192.0.2.1",
            port=443,
            fingerprint="4352E58420E68F5E40BF7C74FADDCCD9D1349413",
        )
        assert create_transport(bridge) is None

    def test_create_transport_webtunnel(self):
        """Test that WebTunnel bridges create WebTunnelTransport."""
        from torscope.directory.bridge import BridgeRelay, create_transport

        bridge = BridgeRelay(
            ip="192.0.2.1",
            port=443,
            fingerprint="4352E58420E68F5E40BF7C74FADDCCD9D1349413",
            transport="webtunnel",
            transport_params={"url": "https://example.com/secret"},
        )
        transport = create_transport(bridge)
        assert isinstance(transport, WebTunnelTransport)
        assert transport.host == "192.0.2.1"
        assert transport.port == 443
        assert transport.url == "https://example.com/secret"

    def test_create_transport_webtunnel_missing_url(self):
        """Test that WebTunnel without URL raises error."""
        from torscope.directory.bridge import BridgeParseError, BridgeRelay, create_transport

        bridge = BridgeRelay(
            ip="192.0.2.1",
            port=443,
            fingerprint="4352E58420E68F5E40BF7C74FADDCCD9D1349413",
            transport="webtunnel",
        )
        with pytest.raises(BridgeParseError, match="requires 'url' parameter"):
            create_transport(bridge)

    def test_create_transport_unsupported(self):
        """Test that unsupported transports raise error."""
        from torscope.directory.bridge import BridgeParseError, BridgeRelay, create_transport

        bridge = BridgeRelay(
            ip="192.0.2.1",
            port=443,
            fingerprint="4352E58420E68F5E40BF7C74FADDCCD9D1349413",
            transport="snowflake",  # Not yet implemented
        )
        with pytest.raises(BridgeParseError, match="not yet supported"):
            create_transport(bridge)
