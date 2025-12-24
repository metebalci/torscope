"""Tests for extra-info descriptor parsing."""

from datetime import UTC, datetime

import pytest

from torscope.directory.extra_info import ExtraInfoParser
from torscope.directory.models import BandwidthHistory, ExtraInfoDescriptor


# =============================================================================
# Test Data
# =============================================================================

SAMPLE_EXTRA_INFO = """extra-info TestRelay AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
published 2024-01-15 12:00:00
write-history 2024-01-15 12:00:00 (900 s) 1000,2000,3000,4000
read-history 2024-01-15 12:00:00 (900 s) 500,1000,1500,2000
geoip-db-digest 1234567890ABCDEF1234567890ABCDEF12345678
geoip6-db-digest FEDCBA0987654321FEDCBA0987654321FEDCBA09
router-sig-ed25519 fakesig
router-signature
-----BEGIN SIGNATURE-----
fake
-----END SIGNATURE-----
"""

SAMPLE_EXTRA_INFO_WITH_STATS = """extra-info StatsRelay BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
published 2024-01-15 12:00:00
dirreq-stats-end 2024-01-14 12:00:00 (86400 s)
dirreq-v3-ips us=100,de=50,fr=25
dirreq-v3-reqs us=1000,de=500,fr=250
dirreq-v3-resp ok=1500,not-found=100,busy=50
entry-stats-end 2024-01-14 12:00:00 (86400 s)
entry-ips us=200,de=100,gb=50
exit-stats-end 2024-01-14 12:00:00 (86400 s)
exit-kibibytes-written 80=1000,443=5000,other=500
exit-kibibytes-read 80=2000,443=10000,other=1000
exit-streams-opened 80=100,443=500,other=50
router-signature
-----BEGIN SIGNATURE-----
fake
-----END SIGNATURE-----
"""

SAMPLE_EXTRA_INFO_WITH_CELLS = """extra-info CellRelay CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
published 2024-01-15 12:00:00
cell-stats-end 2024-01-14 12:00:00 (86400 s)
cell-processed-cells 1.5,2.5,3.5,4.5,5.5,6.5,7.5,8.5,9.5,10.5
cell-queued-cells 0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9,1.0
cell-time-in-queue 10,20,30,40,50,60,70,80,90,100
router-signature
-----BEGIN SIGNATURE-----
fake
-----END SIGNATURE-----
"""

SAMPLE_EXTRA_INFO_WITH_HIDSERV = """extra-info HidservRelay DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
published 2024-01-15 12:00:00
hidserv-stats-end 2024-01-14 12:00:00 (86400 s)
hidserv-rend-relayed-cells 12345 delta_f=2048 epsilon=0.30 bin_size=1024
hidserv-dir-onions-seen 678 delta_f=8 epsilon=0.30 bin_size=8
router-signature
-----BEGIN SIGNATURE-----
fake
-----END SIGNATURE-----
"""

SAMPLE_MULTIPLE_DESCRIPTORS = """extra-info Relay1 1111111111111111111111111111111111111111
published 2024-01-15 10:00:00
router-signature
-----BEGIN SIGNATURE-----
fake
-----END SIGNATURE-----

extra-info Relay2 2222222222222222222222222222222222222222
published 2024-01-15 11:00:00
router-signature
-----BEGIN SIGNATURE-----
fake
-----END SIGNATURE-----

extra-info Relay3 3333333333333333333333333333333333333333
published 2024-01-15 12:00:00
router-signature
-----BEGIN SIGNATURE-----
fake
-----END SIGNATURE-----
"""


# =============================================================================
# Tests for ExtraInfoParser.parse()
# =============================================================================


class TestExtraInfoParserParse:
    """Tests for ExtraInfoParser.parse()."""

    def test_parse_bytes(self):
        """Test parsing from bytes."""
        content = SAMPLE_EXTRA_INFO.encode("utf-8")
        descriptors = ExtraInfoParser.parse(content)

        assert len(descriptors) == 1
        assert descriptors[0].nickname == "TestRelay"

    def test_parse_handles_utf8_errors(self):
        """Test parsing handles invalid UTF-8 gracefully."""
        # Create bytes with invalid UTF-8
        content = b"extra-info Test AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        content += b"published 2024-01-15 12:00:00\n"
        content += b"\xff\xfe invalid utf-8\n"  # Invalid UTF-8

        # Should not raise, should parse what it can
        descriptors = ExtraInfoParser.parse(content)
        assert len(descriptors) == 1


class TestExtraInfoParserParseText:
    """Tests for ExtraInfoParser.parse_text()."""

    def test_parse_basic_descriptor(self):
        """Test parsing a basic extra-info descriptor."""
        descriptors = ExtraInfoParser.parse_text(SAMPLE_EXTRA_INFO)

        assert len(descriptors) == 1
        desc = descriptors[0]

        assert desc.nickname == "TestRelay"
        assert desc.fingerprint == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        assert desc.published.year == 2024
        assert desc.published.month == 1
        assert desc.published.day == 15

    def test_parse_write_history(self):
        """Test parsing write-history."""
        descriptors = ExtraInfoParser.parse_text(SAMPLE_EXTRA_INFO)
        desc = descriptors[0]

        assert desc.write_history is not None
        assert desc.write_history.interval_seconds == 900
        assert desc.write_history.values == [1000, 2000, 3000, 4000]

    def test_parse_read_history(self):
        """Test parsing read-history."""
        descriptors = ExtraInfoParser.parse_text(SAMPLE_EXTRA_INFO)
        desc = descriptors[0]

        assert desc.read_history is not None
        assert desc.read_history.interval_seconds == 900
        assert desc.read_history.values == [500, 1000, 1500, 2000]

    def test_parse_geoip_digests(self):
        """Test parsing geoip database digests."""
        descriptors = ExtraInfoParser.parse_text(SAMPLE_EXTRA_INFO)
        desc = descriptors[0]

        assert desc.geoip_db_digest == "1234567890ABCDEF1234567890ABCDEF12345678"
        assert desc.geoip6_db_digest == "FEDCBA0987654321FEDCBA0987654321FEDCBA09"

    def test_parse_dirreq_stats(self):
        """Test parsing directory request statistics."""
        descriptors = ExtraInfoParser.parse_text(SAMPLE_EXTRA_INFO_WITH_STATS)
        desc = descriptors[0]

        assert desc.dirreq_stats_end is not None
        assert desc.dirreq_v3_ips == {"us": 100, "de": 50, "fr": 25}
        assert desc.dirreq_v3_reqs == {"us": 1000, "de": 500, "fr": 250}
        assert desc.dirreq_v3_resp == {"ok": 1500, "not-found": 100, "busy": 50}

    def test_parse_entry_stats(self):
        """Test parsing entry (guard) statistics."""
        descriptors = ExtraInfoParser.parse_text(SAMPLE_EXTRA_INFO_WITH_STATS)
        desc = descriptors[0]

        assert desc.entry_stats_end is not None
        assert desc.entry_ips == {"us": 200, "de": 100, "gb": 50}

    def test_parse_exit_stats(self):
        """Test parsing exit statistics."""
        descriptors = ExtraInfoParser.parse_text(SAMPLE_EXTRA_INFO_WITH_STATS)
        desc = descriptors[0]

        assert desc.exit_stats_end is not None
        assert desc.exit_kibibytes_written == {"80": 1000, "443": 5000, "other": 500}
        assert desc.exit_kibibytes_read == {"80": 2000, "443": 10000, "other": 1000}
        assert desc.exit_streams_opened == {"80": 100, "443": 500, "other": 50}

    def test_parse_cell_stats(self):
        """Test parsing cell statistics."""
        descriptors = ExtraInfoParser.parse_text(SAMPLE_EXTRA_INFO_WITH_CELLS)
        desc = descriptors[0]

        assert desc.cell_stats_end is not None
        assert len(desc.cell_processed_cells) == 10
        assert desc.cell_processed_cells[0] == 1.5
        assert desc.cell_processed_cells[9] == 10.5
        assert len(desc.cell_queued_cells) == 10
        assert desc.cell_queued_cells[0] == 0.1
        assert len(desc.cell_time_in_queue) == 10
        assert desc.cell_time_in_queue[0] == 10

    def test_parse_hidserv_stats(self):
        """Test parsing hidden service statistics."""
        descriptors = ExtraInfoParser.parse_text(SAMPLE_EXTRA_INFO_WITH_HIDSERV)
        desc = descriptors[0]

        assert desc.hidserv_stats_end is not None
        assert desc.hidserv_rend_relayed_cells == 12345
        assert desc.hidserv_dir_onions_seen == 678

    def test_parse_multiple_descriptors(self):
        """Test parsing multiple descriptors."""
        descriptors = ExtraInfoParser.parse_text(SAMPLE_MULTIPLE_DESCRIPTORS)

        assert len(descriptors) == 3
        assert descriptors[0].nickname == "Relay1"
        assert descriptors[1].nickname == "Relay2"
        assert descriptors[2].nickname == "Relay3"

    def test_parse_empty_text(self):
        """Test parsing empty text returns empty list."""
        descriptors = ExtraInfoParser.parse_text("")
        assert descriptors == []

    def test_parse_whitespace_only(self):
        """Test parsing whitespace returns empty list."""
        descriptors = ExtraInfoParser.parse_text("   \n\n   \n")
        assert descriptors == []

    def test_parse_non_descriptor_text(self):
        """Test parsing non-descriptor text returns empty list."""
        descriptors = ExtraInfoParser.parse_text("This is not a descriptor.\nJust random text.")
        assert descriptors == []

    def test_parse_malformed_extra_info_line(self):
        """Test parsing malformed extra-info line."""
        # Missing fingerprint
        text = "extra-info JustNickname\npublished 2024-01-15 12:00:00\n"
        descriptors = ExtraInfoParser.parse_text(text)
        assert descriptors == []

    def test_parse_stores_raw_descriptor(self):
        """Test that raw descriptor is stored."""
        descriptors = ExtraInfoParser.parse_text(SAMPLE_EXTRA_INFO)
        desc = descriptors[0]

        assert desc.raw_descriptor is not None
        assert "TestRelay" in desc.raw_descriptor
        assert "write-history" in desc.raw_descriptor


# =============================================================================
# Tests for History Parsing
# =============================================================================


class TestHistoryParsing:
    """Tests for bandwidth history parsing."""

    def test_parse_history_with_values(self):
        """Test parsing history with values."""
        text = """extra-info TestRelay AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
published 2024-01-15 12:00:00
write-history 2024-01-15 12:00:00 (3600 s) 100,200,300
"""
        descriptors = ExtraInfoParser.parse_text(text)
        desc = descriptors[0]

        assert desc.write_history is not None
        assert desc.write_history.interval_seconds == 3600
        assert desc.write_history.values == [100, 200, 300]

    def test_parse_history_empty_values(self):
        """Test parsing history with no values."""
        text = """extra-info TestRelay AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
published 2024-01-15 12:00:00
write-history 2024-01-15 12:00:00 (3600 s)
"""
        descriptors = ExtraInfoParser.parse_text(text)
        desc = descriptors[0]

        assert desc.write_history is not None
        assert desc.write_history.interval_seconds == 3600
        assert desc.write_history.values == []

    def test_parse_history_invalid_format(self):
        """Test parsing malformed history returns None."""
        text = """extra-info TestRelay AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
published 2024-01-15 12:00:00
write-history not-a-valid-format
"""
        descriptors = ExtraInfoParser.parse_text(text)
        desc = descriptors[0]

        assert desc.write_history is None

    def test_parse_dirreq_history(self):
        """Test parsing dirreq-write-history and dirreq-read-history."""
        text = """extra-info TestRelay AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
published 2024-01-15 12:00:00
dirreq-write-history 2024-01-15 12:00:00 (900 s) 1000,2000
dirreq-read-history 2024-01-15 12:00:00 (900 s) 500,1000
"""
        descriptors = ExtraInfoParser.parse_text(text)
        desc = descriptors[0]

        assert desc.dirreq_write_history is not None
        assert desc.dirreq_write_history.values == [1000, 2000]
        assert desc.dirreq_read_history is not None
        assert desc.dirreq_read_history.values == [500, 1000]


# =============================================================================
# Tests for Key-Value Pair Parsing
# =============================================================================


class TestKeyValueParsing:
    """Tests for key=value pair parsing."""

    def test_parse_key_value_pairs(self):
        """Test parsing key=value pairs."""
        result = ExtraInfoParser._parse_key_value_pairs("us=100,de=50,fr=25")
        assert result == {"us": 100, "de": 50, "fr": 25}

    def test_parse_key_value_pairs_empty(self):
        """Test parsing empty key=value pairs."""
        result = ExtraInfoParser._parse_key_value_pairs("")
        assert result == {}

    def test_parse_key_value_pairs_whitespace(self):
        """Test parsing whitespace-only key=value pairs."""
        result = ExtraInfoParser._parse_key_value_pairs("   ")
        assert result == {}

    def test_parse_key_value_pairs_invalid_value(self):
        """Test parsing with non-integer value."""
        result = ExtraInfoParser._parse_key_value_pairs("us=100,de=notanumber,fr=25")
        # Should skip invalid values
        assert result == {"us": 100, "fr": 25}

    def test_parse_key_value_pairs_no_equals(self):
        """Test parsing pairs without equals sign."""
        result = ExtraInfoParser._parse_key_value_pairs("us100,de=50")
        # Should skip invalid pairs
        assert result == {"de": 50}


# =============================================================================
# Tests for DateTime Parsing
# =============================================================================


class TestDateTimeParsing:
    """Tests for datetime parsing."""

    def test_parse_datetime_valid(self):
        """Test parsing valid datetime."""
        result = ExtraInfoParser._parse_datetime("2024-01-15 12:30:45")

        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15
        assert result.hour == 12
        assert result.minute == 30
        assert result.second == 45
        assert result.tzinfo == UTC

    def test_parse_datetime_invalid(self):
        """Test parsing invalid datetime returns current time."""
        result = ExtraInfoParser._parse_datetime("not-a-date")

        # Should return a datetime (current time)
        assert isinstance(result, datetime)
        assert result.tzinfo == UTC

    def test_parse_stats_end_valid(self):
        """Test parsing stats-end line."""
        result = ExtraInfoParser._parse_stats_end("2024-01-14 12:00:00 (86400 s)")

        assert result is not None
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 14

    def test_parse_stats_end_invalid(self):
        """Test parsing invalid stats-end returns None."""
        result = ExtraInfoParser._parse_stats_end("invalid format")
        assert result is None


# =============================================================================
# Tests for List Parsing
# =============================================================================


class TestListParsing:
    """Tests for list parsing."""

    def test_parse_float_list(self):
        """Test parsing float list."""
        result = ExtraInfoParser._parse_float_list("1.5,2.5,3.5")
        assert result == [1.5, 2.5, 3.5]

    def test_parse_float_list_with_invalid(self):
        """Test parsing float list with invalid values."""
        result = ExtraInfoParser._parse_float_list("1.5,not-a-number,3.5")
        assert result == [1.5, 3.5]

    def test_parse_float_list_empty(self):
        """Test parsing empty float list."""
        result = ExtraInfoParser._parse_float_list("")
        assert result == []

    def test_parse_int_list(self):
        """Test parsing int list."""
        result = ExtraInfoParser._parse_int_list("10,20,30")
        assert result == [10, 20, 30]

    def test_parse_int_list_with_invalid(self):
        """Test parsing int list with invalid values."""
        result = ExtraInfoParser._parse_int_list("10,not-a-number,30")
        assert result == [10, 30]


# =============================================================================
# Tests for Obfuscated Integer Parsing
# =============================================================================


class TestObfuscatedIntParsing:
    """Tests for obfuscated integer parsing."""

    def test_parse_obfuscated_int_with_params(self):
        """Test parsing obfuscated int with Laplace parameters."""
        result = ExtraInfoParser._parse_obfuscated_int("12345 delta_f=2048 epsilon=0.30 bin_size=1024")
        assert result == 12345

    def test_parse_obfuscated_int_simple(self):
        """Test parsing simple obfuscated int."""
        result = ExtraInfoParser._parse_obfuscated_int("6789")
        assert result == 6789

    def test_parse_obfuscated_int_invalid(self):
        """Test parsing invalid obfuscated int."""
        result = ExtraInfoParser._parse_obfuscated_int("not-a-number")
        assert result is None

    def test_parse_obfuscated_int_empty(self):
        """Test parsing empty obfuscated int."""
        result = ExtraInfoParser._parse_obfuscated_int("")
        assert result is None


# =============================================================================
# Tests for BandwidthHistory Model
# =============================================================================


class TestBandwidthHistory:
    """Tests for BandwidthHistory model."""

    def test_total_bytes(self):
        """Test total_bytes property."""
        history = BandwidthHistory(
            timestamp=datetime.now(UTC),
            interval_seconds=900,
            values=[1000, 2000, 3000, 4000],
        )
        assert history.total_bytes == 10000

    def test_total_bytes_empty(self):
        """Test total_bytes with empty values."""
        history = BandwidthHistory(
            timestamp=datetime.now(UTC),
            interval_seconds=900,
            values=[],
        )
        assert history.total_bytes == 0

    def test_average_bytes_per_second(self):
        """Test average_bytes_per_second property."""
        history = BandwidthHistory(
            timestamp=datetime.now(UTC),
            interval_seconds=100,  # 100s per interval
            values=[1000, 2000],  # 2 intervals, total 3000 bytes
        )
        # 3000 bytes / (2 intervals * 100 seconds) = 15 bytes/sec
        assert history.average_bytes_per_second == 15.0

    def test_average_bytes_per_second_empty(self):
        """Test average_bytes_per_second with empty values."""
        history = BandwidthHistory(
            timestamp=datetime.now(UTC),
            interval_seconds=900,
            values=[],
        )
        assert history.average_bytes_per_second == 0.0

    def test_average_bytes_per_second_zero_interval(self):
        """Test average_bytes_per_second with zero interval."""
        history = BandwidthHistory(
            timestamp=datetime.now(UTC),
            interval_seconds=0,
            values=[1000, 2000],
        )
        assert history.average_bytes_per_second == 0.0


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases."""

    def test_descriptor_with_only_required_fields(self):
        """Test descriptor with only required fields."""
        text = "extra-info MinimalRelay EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE\n"
        descriptors = ExtraInfoParser.parse_text(text)

        assert len(descriptors) == 1
        desc = descriptors[0]
        assert desc.nickname == "MinimalRelay"
        assert desc.write_history is None
        assert desc.read_history is None
        assert desc.dirreq_v3_ips == {}

    def test_descriptor_with_uppercase_fingerprint(self):
        """Test that fingerprints are uppercased."""
        text = "extra-info TestRelay abcdefabcdefabcdefabcdefabcdefabcdefabcd\n"
        descriptors = ExtraInfoParser.parse_text(text)

        assert len(descriptors) == 1
        assert descriptors[0].fingerprint == "ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD"

    def test_parse_handles_exception(self):
        """Test parser handles exceptions gracefully."""
        # Create a descriptor that might cause issues during parsing
        text = "extra-info Test AAAA\nextra-info Valid BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n"
        descriptors = ExtraInfoParser.parse_text(text)

        # Should still parse the valid one
        assert len(descriptors) >= 1
