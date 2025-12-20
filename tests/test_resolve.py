"""Tests for DNS resolution (RELAY_RESOLVE/RESOLVED)."""

import struct

from torscope.onion.relay import (
    ResolvedAnswer,
    ResolvedType,
    create_resolve_payload,
    parse_resolved_payload,
)


class TestCreateResolvePayload:
    """Tests for create_resolve_payload function."""

    def test_simple_hostname(self):
        """Test creating payload for simple hostname."""
        payload = create_resolve_payload("example.com")
        assert payload == b"example.com\x00"

    def test_hostname_with_subdomain(self):
        """Test creating payload for hostname with subdomain."""
        payload = create_resolve_payload("www.example.com")
        assert payload == b"www.example.com\x00"

    def test_reverse_lookup(self):
        """Test creating payload for reverse DNS lookup."""
        payload = create_resolve_payload("1.0.168.192.in-addr.arpa")
        assert payload == b"1.0.168.192.in-addr.arpa\x00"


class TestParseResolvedPayload:
    """Tests for parse_resolved_payload function."""

    def test_single_ipv4(self):
        """Test parsing single IPv4 answer."""
        # Type=0x04, Length=4, Value=93.184.216.34, TTL=3600
        payload = bytes([0x04, 4]) + bytes([93, 184, 216, 34]) + struct.pack(">I", 3600)
        answers = parse_resolved_payload(payload)

        assert len(answers) == 1
        assert answers[0].addr_type == ResolvedType.IPV4
        assert answers[0].value == "93.184.216.34"
        assert answers[0].ttl == 3600

    def test_single_ipv6(self):
        """Test parsing single IPv6 answer."""
        # Type=0x06, Length=16, Value=2606:2800:220:1:248:1893:25c8:1946, TTL=7200
        ipv6_bytes = bytes.fromhex("2606280002200001024818932c581946")
        payload = bytes([0x06, 16]) + ipv6_bytes + struct.pack(">I", 7200)
        answers = parse_resolved_payload(payload)

        assert len(answers) == 1
        assert answers[0].addr_type == ResolvedType.IPV6
        assert answers[0].value == "2606:2800:0220:0001:0248:1893:2c58:1946"
        assert answers[0].ttl == 7200

    def test_multiple_ipv4(self):
        """Test parsing multiple IPv4 answers."""
        # Two IPv4 addresses
        payload = (
            bytes([0x04, 4])
            + bytes([93, 184, 216, 34])
            + struct.pack(">I", 3600)
            + bytes([0x04, 4])
            + bytes([93, 184, 216, 35])
            + struct.pack(">I", 3600)
        )
        answers = parse_resolved_payload(payload)

        assert len(answers) == 2
        assert answers[0].value == "93.184.216.34"
        assert answers[1].value == "93.184.216.35"

    def test_ipv4_and_ipv6(self):
        """Test parsing mixed IPv4 and IPv6 answers."""
        # IPv4 first (required by spec), then IPv6
        ipv6_bytes = bytes.fromhex("26062800022000010248189325c81946")
        payload = (
            bytes([0x04, 4])
            + bytes([93, 184, 216, 34])
            + struct.pack(">I", 3600)
            + bytes([0x06, 16])
            + ipv6_bytes
            + struct.pack(">I", 7200)
        )
        answers = parse_resolved_payload(payload)

        assert len(answers) == 2
        assert answers[0].addr_type == ResolvedType.IPV4
        assert answers[1].addr_type == ResolvedType.IPV6

    def test_hostname_answer(self):
        """Test parsing hostname (PTR) answer."""
        # Type=0x00, Length=11, Value="example.com", TTL=86400
        hostname = b"example.com"
        payload = bytes([0x00, len(hostname)]) + hostname + struct.pack(">I", 86400)
        answers = parse_resolved_payload(payload)

        assert len(answers) == 1
        assert answers[0].addr_type == ResolvedType.HOSTNAME
        assert answers[0].value == "example.com"
        assert answers[0].ttl == 86400

    def test_transient_error(self):
        """Test parsing transient error answer."""
        # Type=0xF0, Length=0, no value, TTL=0
        payload = bytes([0xF0, 0]) + struct.pack(">I", 0)
        answers = parse_resolved_payload(payload)

        assert len(answers) == 1
        assert answers[0].addr_type == ResolvedType.ERROR_TRANSIENT
        assert answers[0].value == "error"
        assert answers[0].ttl == 0

    def test_nontransient_error(self):
        """Test parsing non-transient error answer."""
        # Type=0xF1, Length=0, no value, TTL=0
        payload = bytes([0xF1, 0]) + struct.pack(">I", 0)
        answers = parse_resolved_payload(payload)

        assert len(answers) == 1
        assert answers[0].addr_type == ResolvedType.ERROR_NONTRANSIENT
        assert answers[0].value == "error"
        assert answers[0].ttl == 0

    def test_empty_payload(self):
        """Test parsing empty payload."""
        answers = parse_resolved_payload(b"")
        assert len(answers) == 0

    def test_truncated_payload(self):
        """Test parsing truncated payload (incomplete header)."""
        # Only 1 byte, need at least 2 for type+length
        answers = parse_resolved_payload(b"\x04")
        assert len(answers) == 0

    def test_truncated_value(self):
        """Test parsing payload with truncated value."""
        # Type=0x04, Length=4, but only 2 bytes of value
        payload = bytes([0x04, 4]) + bytes([93, 184])
        answers = parse_resolved_payload(payload)
        assert len(answers) == 0

    def test_unknown_type_skipped(self):
        """Test that unknown address types are skipped."""
        # Unknown type 0x99, then valid IPv4
        payload = (
            bytes([0x99, 4])
            + bytes([1, 2, 3, 4])
            + struct.pack(">I", 100)
            + bytes([0x04, 4])
            + bytes([93, 184, 216, 34])
            + struct.pack(">I", 3600)
        )
        answers = parse_resolved_payload(payload)

        # Only IPv4 should be returned
        assert len(answers) == 1
        assert answers[0].addr_type == ResolvedType.IPV4


class TestResolvedAnswer:
    """Tests for ResolvedAnswer dataclass."""

    def test_ipv4_answer(self):
        """Test creating IPv4 answer."""
        answer = ResolvedAnswer(addr_type=ResolvedType.IPV4, value="1.2.3.4", ttl=3600)
        assert answer.addr_type == ResolvedType.IPV4
        assert answer.value == "1.2.3.4"
        assert answer.ttl == 3600

    def test_ipv6_answer(self):
        """Test creating IPv6 answer."""
        answer = ResolvedAnswer(
            addr_type=ResolvedType.IPV6, value="2001:0db8:0000:0000:0000:0000:0000:0001", ttl=7200
        )
        assert answer.addr_type == ResolvedType.IPV6
        assert answer.ttl == 7200


class TestResolvedType:
    """Tests for ResolvedType enum."""

    def test_type_values(self):
        """Test that type values match Tor spec."""
        assert ResolvedType.HOSTNAME == 0x00
        assert ResolvedType.IPV4 == 0x04
        assert ResolvedType.IPV6 == 0x06
        assert ResolvedType.ERROR_TRANSIENT == 0xF0
        assert ResolvedType.ERROR_NONTRANSIENT == 0xF1
