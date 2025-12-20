"""Tests for consensus parsing."""

from datetime import UTC, datetime

import pytest

from torscope.directory.consensus import ConsensusParser
from torscope.directory.models import ConsensusDocument

from .fixtures import (
    DATETIME_TEST_CASES,
    EXPECTED_CONSENSUS_VALUES,
    EXPECTED_ROUTER_1,
    EXPECTED_ROUTER_2,
    PROTOCOL_TEST_CASES,
    SAMPLE_CONSENSUS,
)


class TestConsensusParser:
    """Tests for ConsensusParser class."""

    def test_parse_sample_consensus(self):
        """Test parsing a complete sample consensus document."""
        consensus = ConsensusParser.parse(SAMPLE_CONSENSUS.encode("utf-8"), fetched_from="moria1")

        assert isinstance(consensus, ConsensusDocument)
        assert consensus.fetched_from == "moria1"

    def test_parse_preamble_fields(self):
        """Test parsing consensus preamble fields."""
        consensus = ConsensusParser.parse(SAMPLE_CONSENSUS.encode("utf-8"))

        assert consensus.version == EXPECTED_CONSENSUS_VALUES["version"]
        assert consensus.vote_status == EXPECTED_CONSENSUS_VALUES["vote_status"]
        assert consensus.consensus_method == EXPECTED_CONSENSUS_VALUES["consensus_method"]
        assert consensus.valid_after == EXPECTED_CONSENSUS_VALUES["valid_after"]
        assert consensus.fresh_until == EXPECTED_CONSENSUS_VALUES["fresh_until"]
        assert consensus.valid_until == EXPECTED_CONSENSUS_VALUES["valid_until"]
        assert consensus.voting_delay == EXPECTED_CONSENSUS_VALUES["voting_delay"]

    def test_parse_client_versions(self):
        """Test parsing client-versions field."""
        consensus = ConsensusParser.parse(SAMPLE_CONSENSUS.encode("utf-8"))

        assert consensus.client_versions == EXPECTED_CONSENSUS_VALUES["client_versions"]

    def test_parse_server_versions(self):
        """Test parsing server-versions field."""
        consensus = ConsensusParser.parse(SAMPLE_CONSENSUS.encode("utf-8"))

        assert consensus.server_versions == EXPECTED_CONSENSUS_VALUES["server_versions"]

    def test_parse_known_flags(self):
        """Test parsing known-flags field."""
        consensus = ConsensusParser.parse(SAMPLE_CONSENSUS.encode("utf-8"))

        assert consensus.known_flags == EXPECTED_CONSENSUS_VALUES["known_flags"]

    def test_parse_params(self):
        """Test parsing network params field."""
        consensus = ConsensusParser.parse(SAMPLE_CONSENSUS.encode("utf-8"))

        assert consensus.params == EXPECTED_CONSENSUS_VALUES["params"]
        assert consensus.params["circwindow"] == 1000
        assert consensus.params["refuseunknownexits"] == 1

    def test_parse_authorities(self):
        """Test parsing directory authorities."""
        consensus = ConsensusParser.parse(SAMPLE_CONSENSUS.encode("utf-8"))

        assert len(consensus.authorities) == EXPECTED_CONSENSUS_VALUES["num_authorities"]
        auth = consensus.authorities[0]
        assert auth.nickname == "moria1"
        assert auth.identity == "D586D18309DED4CD6D57C18FDB97EFA96D330566"
        assert auth.hostname == "128.31.0.34"
        assert auth.ip == "128.31.0.34"
        assert auth.dirport == 9131
        assert auth.orport == 9101

    def test_parse_routers(self):
        """Test parsing router entries."""
        consensus = ConsensusParser.parse(SAMPLE_CONSENSUS.encode("utf-8"))

        assert len(consensus.routers) == EXPECTED_CONSENSUS_VALUES["num_routers"]

    def test_parse_router_basic_fields(self):
        """Test parsing basic router fields (r line)."""
        consensus = ConsensusParser.parse(SAMPLE_CONSENSUS.encode("utf-8"))

        router1 = consensus.routers[0]
        assert router1.nickname == EXPECTED_ROUTER_1["nickname"]
        assert router1.identity == EXPECTED_ROUTER_1["identity"]
        assert router1.ip == EXPECTED_ROUTER_1["ip"]
        assert router1.orport == EXPECTED_ROUTER_1["orport"]
        assert router1.dirport == EXPECTED_ROUTER_1["dirport"]

    def test_parse_router_flags(self):
        """Test parsing router flags (s line)."""
        consensus = ConsensusParser.parse(SAMPLE_CONSENSUS.encode("utf-8"))

        router1 = consensus.routers[0]
        assert router1.flags == EXPECTED_ROUTER_1["flags"]
        assert router1.has_flag("Exit")
        assert router1.has_flag("Fast")

    def test_parse_router_bandwidth(self):
        """Test parsing router bandwidth (w line)."""
        consensus = ConsensusParser.parse(SAMPLE_CONSENSUS.encode("utf-8"))

        router1 = consensus.routers[0]
        assert router1.bandwidth == EXPECTED_ROUTER_1["bandwidth"]

        router2 = consensus.routers[1]
        assert router2.bandwidth == EXPECTED_ROUTER_2["bandwidth"]
        assert router2.measured == EXPECTED_ROUTER_2["measured"]

    def test_parse_router_ipv6(self):
        """Test parsing router IPv6 addresses (a line)."""
        consensus = ConsensusParser.parse(SAMPLE_CONSENSUS.encode("utf-8"))

        router2 = consensus.routers[1]
        assert router2.ipv6_addresses == EXPECTED_ROUTER_2["ipv6_addresses"]

    def test_parse_router_version(self):
        """Test parsing router version (v line)."""
        consensus = ConsensusParser.parse(SAMPLE_CONSENSUS.encode("utf-8"))

        router2 = consensus.routers[1]
        assert router2.version == EXPECTED_ROUTER_2["version"]

    def test_parse_router_protocols(self):
        """Test parsing router protocols (pr line)."""
        consensus = ConsensusParser.parse(SAMPLE_CONSENSUS.encode("utf-8"))

        router2 = consensus.routers[1]
        assert router2.protocols == EXPECTED_ROUTER_2["protocols"]

    def test_parse_router_exit_policy(self):
        """Test parsing router exit policy (p line)."""
        consensus = ConsensusParser.parse(SAMPLE_CONSENSUS.encode("utf-8"))

        router2 = consensus.routers[1]
        assert router2.exit_policy == EXPECTED_ROUTER_2["exit_policy"]

    def test_parse_router_microdesc_hash(self):
        """Test parsing router microdescriptor hash (m line)."""
        consensus = ConsensusParser.parse(SAMPLE_CONSENSUS.encode("utf-8"))

        router2 = consensus.routers[1]
        assert router2.microdesc_hash == EXPECTED_ROUTER_2["microdesc_hash"]

    def test_parse_bandwidth_weights(self):
        """Test parsing bandwidth-weights footer."""
        consensus = ConsensusParser.parse(SAMPLE_CONSENSUS.encode("utf-8"))

        assert consensus.bandwidth_weights["Wbd"] == 285
        assert consensus.bandwidth_weights["Wbe"] == 0
        assert consensus.bandwidth_weights["Wbg"] == 0
        assert consensus.bandwidth_weights["Wbm"] == 10000

    def test_parse_signatures(self):
        """Test parsing directory signatures."""
        consensus = ConsensusParser.parse(SAMPLE_CONSENSUS.encode("utf-8"))

        assert len(consensus.signatures) == EXPECTED_CONSENSUS_VALUES["num_signatures"]
        sig = consensus.signatures[0]
        assert sig.algorithm == "sha256"
        assert sig.identity == "D586D18309DED4CD6D57C18FDB97EFA96D330566"
        assert sig.signing_key_digest == "0123456789ABCDEF"
        assert "-----BEGIN SIGNATURE-----" in sig.signature
        assert "-----END SIGNATURE-----" in sig.signature

    def test_parse_empty_document(self):
        """Test parsing an empty document."""
        consensus = ConsensusParser.parse(b"")

        # Should create a minimal valid ConsensusDocument
        assert isinstance(consensus, ConsensusDocument)
        assert consensus.version == 3
        assert consensus.vote_status == "consensus"

    def test_parse_document_with_comments(self):
        """Test parsing document with comment lines."""
        doc_with_comments = """
# This is a comment
network-status-version 3
# Another comment
vote-status consensus
consensus-method 28
valid-after 2024-01-15 12:00:00
fresh-until 2024-01-15 13:00:00
valid-until 2024-01-15 15:00:00
voting-delay 300 300
known-flags Running Valid
"""
        consensus = ConsensusParser.parse(doc_with_comments.encode("utf-8"))

        assert consensus.version == 3
        assert consensus.vote_status == "consensus"
        assert consensus.consensus_method == 28

    def test_parse_document_with_blank_lines(self):
        """Test parsing document with blank lines."""
        doc_with_blanks = """
network-status-version 3

vote-status consensus

consensus-method 28
valid-after 2024-01-15 12:00:00
fresh-until 2024-01-15 13:00:00
valid-until 2024-01-15 15:00:00
voting-delay 300 300

known-flags Running Valid
"""
        consensus = ConsensusParser.parse(doc_with_blanks.encode("utf-8"))

        assert consensus.version == 3
        assert consensus.vote_status == "consensus"

    def test_parse_stores_raw_document(self):
        """Test that parser stores the raw document text."""
        consensus = ConsensusParser.parse(SAMPLE_CONSENSUS.encode("utf-8"))

        assert consensus.raw_document == SAMPLE_CONSENSUS

    def test_parse_sets_fetched_at(self):
        """Test that parser sets fetched_at timestamp."""
        before = datetime.now(UTC)
        consensus = ConsensusParser.parse(SAMPLE_CONSENSUS.encode("utf-8"))
        after = datetime.now(UTC)

        assert consensus.fetched_at is not None
        assert before <= consensus.fetched_at <= after

    def test_parse_multiple_routers_preserves_order(self):
        """Test that routers are parsed in order."""
        consensus = ConsensusParser.parse(SAMPLE_CONSENSUS.encode("utf-8"))

        assert len(consensus.routers) >= 2
        assert consensus.routers[0].nickname == "Test1"
        assert consensus.routers[1].nickname == "Test2"


class TestParseDatetime:
    """Tests for _parse_datetime helper method."""

    @pytest.mark.parametrize("date_str,expected", DATETIME_TEST_CASES)
    def test_parse_valid_datetime(self, date_str, expected):
        """Test parsing valid datetime strings."""
        result = ConsensusParser._parse_datetime(date_str)
        assert result == expected

    def test_parse_invalid_datetime_returns_current_time(self):
        """Test that invalid datetime returns current UTC time."""
        before = datetime.now(UTC)
        result = ConsensusParser._parse_datetime("invalid-date-string")
        after = datetime.now(UTC)

        # Should return a timestamp close to now
        assert before <= result <= after

    def test_parse_empty_string(self):
        """Test parsing empty string."""
        before = datetime.now(UTC)
        result = ConsensusParser._parse_datetime("")
        after = datetime.now(UTC)

        assert before <= result <= after


class TestParseProtocols:
    """Tests for _parse_protocols helper method."""

    @pytest.mark.parametrize("proto_str,expected", PROTOCOL_TEST_CASES)
    def test_parse_valid_protocols(self, proto_str, expected):
        """Test parsing valid protocol strings."""
        result = ConsensusParser._parse_protocols(proto_str)
        assert result == expected

    def test_parse_empty_string(self):
        """Test parsing empty protocol string."""
        result = ConsensusParser._parse_protocols("")
        assert result == {}

    def test_parse_single_protocol_single_version(self):
        """Test parsing single protocol with single version."""
        result = ConsensusParser._parse_protocols("Link=5")
        assert result == {"Link": [5]}

    def test_parse_protocol_range(self):
        """Test parsing protocol with version range."""
        result = ConsensusParser._parse_protocols("Link=1-5")
        assert result == {"Link": [1, 2, 3, 4, 5]}

    def test_parse_protocol_multiple_ranges(self):
        """Test parsing protocol with multiple version ranges."""
        result = ConsensusParser._parse_protocols("Link=1-2,5-7")
        assert result == {"Link": [1, 2, 5, 6, 7]}

    def test_parse_multiple_protocols(self):
        """Test parsing multiple protocols."""
        result = ConsensusParser._parse_protocols("Link=1-3 Cons=1-2 Desc=1")
        assert result == {"Link": [1, 2, 3], "Cons": [1, 2], "Desc": [1]}

    def test_parse_protocol_without_equals(self):
        """Test parsing malformed protocol without equals sign."""
        result = ConsensusParser._parse_protocols("InvalidProtocol")
        assert result == {}

    def test_parse_protocol_with_trailing_space(self):
        """Test parsing protocol string with trailing space."""
        result = ConsensusParser._parse_protocols("Link=1-3 ")
        assert result == {"Link": [1, 2, 3]}


class TestConsensusParserEdgeCases:
    """Tests for edge cases and error handling."""

    def test_parse_router_without_optional_fields(self):
        """Test parsing router with only required r line."""
        minimal_consensus = """network-status-version 3
vote-status consensus
consensus-method 28
valid-after 2024-01-15 12:00:00
fresh-until 2024-01-15 13:00:00
valid-until 2024-01-15 15:00:00
voting-delay 300 300
known-flags Running Valid
r MinimalRelay AAAA BBBB 2024-01-15 10:00:00 192.0.2.1 9001 9030
"""
        consensus = ConsensusParser.parse(minimal_consensus.encode("utf-8"))

        assert len(consensus.routers) == 1
        router = consensus.routers[0]
        assert router.nickname == "MinimalRelay"
        assert router.flags == []  # No s line
        assert router.bandwidth is None  # No w line
        assert router.version is None  # No v line

    def test_parse_router_with_zero_dirport(self):
        """Test parsing router with DirPort=0."""
        consensus_text = """network-status-version 3
vote-status consensus
consensus-method 28
valid-after 2024-01-15 12:00:00
fresh-until 2024-01-15 13:00:00
valid-until 2024-01-15 15:00:00
voting-delay 300 300
known-flags Running Valid
r NoDirPort AAAA BBBB 2024-01-15 10:00:00 192.0.2.1 9001 0
"""
        consensus = ConsensusParser.parse(consensus_text.encode("utf-8"))

        router = consensus.routers[0]
        assert router.dirport == 0

    def test_parse_unmeasured_bandwidth(self):
        """Test parsing router with Unmeasured=1 flag."""
        consensus_text = """network-status-version 3
vote-status consensus
consensus-method 28
valid-after 2024-01-15 12:00:00
fresh-until 2024-01-15 13:00:00
valid-until 2024-01-15 15:00:00
voting-delay 300 300
known-flags Running Valid
r TestRelay AAAA BBBB 2024-01-15 10:00:00 192.0.2.1 9001 9030
w Bandwidth=5000 Unmeasured=1
"""
        consensus = ConsensusParser.parse(consensus_text.encode("utf-8"))

        router = consensus.routers[0]
        assert router.bandwidth == 5000
        assert router.unmeasured is True

    def test_parse_multiple_ipv6_addresses(self):
        """Test parsing router with multiple IPv6 addresses."""
        consensus_text = """network-status-version 3
vote-status consensus
consensus-method 28
valid-after 2024-01-15 12:00:00
fresh-until 2024-01-15 13:00:00
valid-until 2024-01-15 15:00:00
voting-delay 300 300
known-flags Running Valid
r TestRelay AAAA BBBB 2024-01-15 10:00:00 192.0.2.1 9001 9030
a [2001:db8::1]:9001
a [2001:db8::2]:9001
"""
        consensus = ConsensusParser.parse(consensus_text.encode("utf-8"))

        router = consensus.routers[0]
        assert len(router.ipv6_addresses) == 2
        assert "[2001:db8::1]:9001" in router.ipv6_addresses
        assert "[2001:db8::2]:9001" in router.ipv6_addresses

    def test_parse_signature_without_algorithm(self):
        """Test parsing signature line without explicit algorithm."""
        consensus_text = """network-status-version 3
vote-status consensus
consensus-method 28
valid-after 2024-01-15 12:00:00
fresh-until 2024-01-15 13:00:00
valid-until 2024-01-15 15:00:00
voting-delay 300 300
known-flags Running Valid
directory-signature ABC123 DEF456
-----BEGIN SIGNATURE-----
testsig
-----END SIGNATURE-----
"""
        consensus = ConsensusParser.parse(consensus_text.encode("utf-8"))

        assert len(consensus.signatures) == 1
        sig = consensus.signatures[0]
        assert sig.algorithm == "sha1"  # Default algorithm
        assert sig.identity == "ABC123"
        assert sig.signing_key_digest == "DEF456"

    def test_parse_utf8_with_errors(self):
        """Test parsing document with invalid UTF-8 sequences."""
        # Create bytes with invalid UTF-8
        invalid_utf8 = b"network-status-version 3\nvote-status \xff\xfe consensus\n"

        # Should not raise exception, uses replace error handling
        consensus = ConsensusParser.parse(invalid_utf8)
        assert isinstance(consensus, ConsensusDocument)
