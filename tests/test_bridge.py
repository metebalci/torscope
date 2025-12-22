"""Tests for bridge relay module."""

import pytest

from torscope.directory.bridge import (
    BridgeParseError,
    BridgeRelay,
    parse_bridge_line,
    validate_bridge,
)


class TestBridgeRelay:
    """Tests for BridgeRelay dataclass."""

    def test_address_property(self):
        """Test address string formatting."""
        bridge = BridgeRelay(
            ip="192.0.2.1",
            port=443,
            fingerprint="4352E58420E68F5E40BF7C74FADDCCD9D1349413",
        )
        assert bridge.address == "192.0.2.1:443"

    def test_is_direct_without_transport(self):
        """Test is_direct property when no transport is set."""
        bridge = BridgeRelay(
            ip="192.0.2.1",
            port=443,
            fingerprint="4352E58420E68F5E40BF7C74FADDCCD9D1349413",
        )
        assert bridge.is_direct is True

    def test_is_direct_with_transport(self):
        """Test is_direct property when transport is set."""
        bridge = BridgeRelay(
            ip="192.0.2.1",
            port=443,
            fingerprint="4352E58420E68F5E40BF7C74FADDCCD9D1349413",
            transport="obfs4",
        )
        assert bridge.is_direct is False

    def test_short_fingerprint(self):
        """Test short fingerprint property."""
        bridge = BridgeRelay(
            ip="192.0.2.1",
            port=443,
            fingerprint="4352E58420E68F5E40BF7C74FADDCCD9D1349413",
        )
        assert bridge.short_fingerprint == "4352E584"

    def test_str_without_transport(self):
        """Test string representation without transport."""
        bridge = BridgeRelay(
            ip="192.0.2.1",
            port=443,
            fingerprint="4352E58420E68F5E40BF7C74FADDCCD9D1349413",
        )
        assert str(bridge) == "192.0.2.1:443 4352E58420E68F5E40BF7C74FADDCCD9D1349413"

    def test_str_with_transport(self):
        """Test string representation with transport."""
        bridge = BridgeRelay(
            ip="192.0.2.1",
            port=443,
            fingerprint="4352E58420E68F5E40BF7C74FADDCCD9D1349413",
            transport="obfs4",
            transport_params={"cert": "ABC123", "iat-mode": "0"},
        )
        result = str(bridge)
        assert result.startswith("obfs4 192.0.2.1:443")
        assert "4352E58420E68F5E40BF7C74FADDCCD9D1349413" in result
        assert "cert=ABC123" in result
        assert "iat-mode=0" in result


class TestParseBridgeLine:
    """Tests for parse_bridge_line function."""

    def test_parse_direct_bridge(self):
        """Test parsing a direct bridge line (no transport)."""
        bridge = parse_bridge_line(
            "192.0.2.1:443 4352E58420E68F5E40BF7C74FADDCCD9D1349413"
        )
        assert bridge.ip == "192.0.2.1"
        assert bridge.port == 443
        assert bridge.fingerprint == "4352E58420E68F5E40BF7C74FADDCCD9D1349413"
        assert bridge.transport is None
        assert bridge.transport_params == {}

    def test_parse_with_bridge_prefix(self):
        """Test parsing with 'Bridge' prefix (torrc format)."""
        bridge = parse_bridge_line(
            "Bridge 192.0.2.1:443 4352E58420E68F5E40BF7C74FADDCCD9D1349413"
        )
        assert bridge.ip == "192.0.2.1"
        assert bridge.port == 443
        assert bridge.fingerprint == "4352E58420E68F5E40BF7C74FADDCCD9D1349413"
        assert bridge.transport is None

    def test_parse_case_insensitive_bridge_prefix(self):
        """Test parsing with case-insensitive 'Bridge' prefix."""
        bridge = parse_bridge_line(
            "BRIDGE 192.0.2.1:443 4352E58420E68F5E40BF7C74FADDCCD9D1349413"
        )
        assert bridge.ip == "192.0.2.1"
        assert bridge.port == 443

    def test_parse_obfs4_bridge(self):
        """Test parsing an obfs4 bridge line."""
        bridge = parse_bridge_line(
            "obfs4 192.0.2.1:443 4352E58420E68F5E40BF7C74FADDCCD9D1349413 "
            "cert=SSgKOvVu+w6bJOXTNi53JNV0+ECFkVQ iat-mode=0"
        )
        assert bridge.ip == "192.0.2.1"
        assert bridge.port == 443
        assert bridge.fingerprint == "4352E58420E68F5E40BF7C74FADDCCD9D1349413"
        assert bridge.transport == "obfs4"
        assert bridge.transport_params["cert"] == "SSgKOvVu+w6bJOXTNi53JNV0+ECFkVQ"
        assert bridge.transport_params["iat-mode"] == "0"

    def test_parse_meek_bridge(self):
        """Test parsing a meek bridge line."""
        bridge = parse_bridge_line(
            "meek 192.0.2.1:443 4352E58420E68F5E40BF7C74FADDCCD9D1349413"
        )
        assert bridge.transport == "meek"

    def test_parse_snowflake_bridge(self):
        """Test parsing a snowflake bridge line."""
        bridge = parse_bridge_line(
            "snowflake 192.0.2.1:443 4352E58420E68F5E40BF7C74FADDCCD9D1349413"
        )
        assert bridge.transport == "snowflake"

    def test_parse_webtunnel_bridge(self):
        """Test parsing a webtunnel bridge line."""
        bridge = parse_bridge_line(
            "webtunnel 192.0.2.1:443 4352E58420E68F5E40BF7C74FADDCCD9D1349413 "
            "url=https://example.com/path"
        )
        assert bridge.transport == "webtunnel"
        assert bridge.transport_params["url"] == "https://example.com/path"

    def test_parse_fingerprint_uppercase(self):
        """Test that fingerprint is normalized to uppercase."""
        bridge = parse_bridge_line(
            "192.0.2.1:443 4352e58420e68f5e40bf7c74faddccd9d1349413"
        )
        assert bridge.fingerprint == "4352E58420E68F5E40BF7C74FADDCCD9D1349413"

    def test_parse_whitespace_handling(self):
        """Test that extra whitespace is handled."""
        bridge = parse_bridge_line(
            "  192.0.2.1:443   4352E58420E68F5E40BF7C74FADDCCD9D1349413  "
        )
        assert bridge.ip == "192.0.2.1"
        assert bridge.port == 443

    def test_parse_invalid_too_few_parts(self):
        """Test that too few parts raises error."""
        with pytest.raises(BridgeParseError, match="too few parts"):
            parse_bridge_line("192.0.2.1:443")

    def test_parse_invalid_address(self):
        """Test that invalid address raises error."""
        with pytest.raises(BridgeParseError, match="Invalid address"):
            parse_bridge_line("not-an-ip:443 4352E58420E68F5E40BF7C74FADDCCD9D1349413")

    def test_parse_invalid_port(self):
        """Test that invalid port raises error."""
        with pytest.raises(BridgeParseError, match="Invalid port"):
            parse_bridge_line(
                "192.0.2.1:99999 4352E58420E68F5E40BF7C74FADDCCD9D1349413"
            )

    def test_parse_invalid_fingerprint(self):
        """Test that invalid fingerprint raises error."""
        with pytest.raises(BridgeParseError, match="Invalid fingerprint"):
            parse_bridge_line("192.0.2.1:443 not-a-valid-fingerprint")

    def test_parse_invalid_fingerprint_too_short(self):
        """Test that too-short fingerprint raises error."""
        with pytest.raises(BridgeParseError, match="Invalid fingerprint"):
            parse_bridge_line("192.0.2.1:443 4352E584")  # Only 8 chars

    def test_parse_port_zero(self):
        """Test that port 0 raises error."""
        with pytest.raises(BridgeParseError, match="Invalid port"):
            parse_bridge_line("192.0.2.1:0 4352E58420E68F5E40BF7C74FADDCCD9D1349413")


class TestValidateBridge:
    """Tests for validate_bridge function."""

    def test_validate_valid_bridge(self):
        """Test that valid bridge passes validation."""
        bridge = BridgeRelay(
            ip="192.0.2.1",
            port=443,
            fingerprint="4352E58420E68F5E40BF7C74FADDCCD9D1349413",
        )
        # Should not raise
        validate_bridge(bridge)

    def test_validate_invalid_ip(self):
        """Test that invalid IP raises error."""
        bridge = BridgeRelay(
            ip="999.999.999.999",
            port=443,
            fingerprint="4352E58420E68F5E40BF7C74FADDCCD9D1349413",
        )
        with pytest.raises(BridgeParseError, match="Invalid IP"):
            validate_bridge(bridge)

    def test_validate_invalid_port_too_high(self):
        """Test that port > 65535 raises error."""
        bridge = BridgeRelay(
            ip="192.0.2.1",
            port=70000,
            fingerprint="4352E58420E68F5E40BF7C74FADDCCD9D1349413",
        )
        with pytest.raises(BridgeParseError, match="Invalid port"):
            validate_bridge(bridge)

    def test_validate_invalid_fingerprint(self):
        """Test that invalid fingerprint raises error."""
        bridge = BridgeRelay(
            ip="192.0.2.1",
            port=443,
            fingerprint="not-valid",
        )
        with pytest.raises(BridgeParseError, match="Invalid fingerprint"):
            validate_bridge(bridge)

    def test_validate_unknown_transport(self):
        """Test that unknown transport raises error."""
        bridge = BridgeRelay(
            ip="192.0.2.1",
            port=443,
            fingerprint="4352E58420E68F5E40BF7C74FADDCCD9D1349413",
            transport="unknown_transport",
        )
        with pytest.raises(BridgeParseError, match="Unknown transport"):
            validate_bridge(bridge)

    def test_validate_known_transports(self):
        """Test that known transports pass validation."""
        known_transports = ["obfs4", "obfs3", "meek", "snowflake", "webtunnel"]
        for transport in known_transports:
            bridge = BridgeRelay(
                ip="192.0.2.1",
                port=443,
                fingerprint="4352E58420E68F5E40BF7C74FADDCCD9D1349413",
                transport=transport,
            )
            # Should not raise
            validate_bridge(bridge)
