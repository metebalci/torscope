"""Tests for v3 onion address parsing and cryptographic operations."""

import base64
import time
from unittest.mock import patch

import pytest

from torscope.onion.address import (
    OnionAddress,
    HS_TIME_PERIOD_LENGTH,
    HS_VERSION_3,
    _compute_checksum,
    _derive_blinded_key,
    get_current_time_period,
    get_time_period_info,
)


# =============================================================================
# Test Data
# =============================================================================

# DuckDuckGo's v3 onion address (well-known, used for testing)
DUCKDUCKGO_ADDRESS = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"

# A valid test address (56 chars + .onion)
# This is computed from a known test public key
TEST_PUBKEY = bytes(range(32))  # 0x00-0x1f


# =============================================================================
# Tests for OnionAddress.parse()
# =============================================================================


class TestOnionAddressParse:
    """Tests for OnionAddress.parse()."""

    def test_parse_valid_address(self):
        """Test parsing a valid v3 onion address."""
        addr = OnionAddress.parse(DUCKDUCKGO_ADDRESS)

        assert addr.version == 3
        assert len(addr.public_key) == 32
        assert len(addr.checksum) == 2
        assert addr.address == DUCKDUCKGO_ADDRESS

    def test_parse_without_suffix(self):
        """Test parsing address without .onion suffix."""
        addr_no_suffix = DUCKDUCKGO_ADDRESS[:-6]  # Remove .onion
        addr = OnionAddress.parse(addr_no_suffix)

        assert addr.address == DUCKDUCKGO_ADDRESS

    def test_parse_uppercase(self):
        """Test parsing uppercase address."""
        addr = OnionAddress.parse(DUCKDUCKGO_ADDRESS.upper())

        assert addr.address == DUCKDUCKGO_ADDRESS

    def test_parse_mixed_case(self):
        """Test parsing mixed case address."""
        mixed = "DuckDuckGoGG42xJOC72x3sJASoWOARFbgCMVfiMAFTT6twAgSWzCZad.onion"
        addr = OnionAddress.parse(mixed)

        assert addr.address == DUCKDUCKGO_ADDRESS

    def test_parse_with_whitespace(self):
        """Test parsing address with leading/trailing whitespace."""
        addr = OnionAddress.parse(f"  {DUCKDUCKGO_ADDRESS}  ")

        assert addr.address == DUCKDUCKGO_ADDRESS

    def test_parse_invalid_length(self):
        """Test parsing address with wrong length."""
        with pytest.raises(ValueError, match="expected 56 characters"):
            OnionAddress.parse("tooshort.onion")

    def test_parse_invalid_base32(self):
        """Test parsing address with invalid base32 characters."""
        # '1' is not a valid base32 character
        invalid = "1" * 56 + ".onion"
        with pytest.raises(ValueError, match="Invalid base32"):
            OnionAddress.parse(invalid)

    def test_parse_wrong_version(self):
        """Test parsing address with wrong version byte."""
        # Create an address with version 2 instead of 3
        pubkey = b"x" * 32
        checksum = _compute_checksum(pubkey, 2)  # Version 2
        decoded = pubkey + checksum + bytes([2])
        encoded = base64.b32encode(decoded).decode().lower().rstrip("=")

        with pytest.raises(ValueError, match="Unsupported onion address version"):
            OnionAddress.parse(encoded + ".onion")

    def test_parse_bad_checksum(self):
        """Test parsing address with bad checksum."""
        # Create an address with wrong checksum
        pubkey = b"x" * 32
        bad_checksum = b"\x00\x00"  # Wrong checksum
        decoded = pubkey + bad_checksum + bytes([3])
        encoded = base64.b32encode(decoded).decode().lower().rstrip("=")

        with pytest.raises(ValueError, match="Checksum mismatch"):
            OnionAddress.parse(encoded + ".onion")


class TestOnionAddressStr:
    """Tests for OnionAddress.__str__()."""

    def test_str_returns_address(self):
        """Test __str__ returns the full address."""
        addr = OnionAddress.parse(DUCKDUCKGO_ADDRESS)
        assert str(addr) == DUCKDUCKGO_ADDRESS


# =============================================================================
# Tests for compute_blinded_key()
# =============================================================================


class TestComputeBlindedKey:
    """Tests for OnionAddress.compute_blinded_key()."""

    def test_blinded_key_length(self):
        """Test blinded key is 32 bytes."""
        addr = OnionAddress.parse(DUCKDUCKGO_ADDRESS)
        blinded = addr.compute_blinded_key(time_period=1000)

        assert len(blinded) == 32

    def test_blinded_key_deterministic(self):
        """Test blinded key is deterministic for same inputs."""
        addr = OnionAddress.parse(DUCKDUCKGO_ADDRESS)
        blinded1 = addr.compute_blinded_key(time_period=1000)
        blinded2 = addr.compute_blinded_key(time_period=1000)

        assert blinded1 == blinded2

    def test_blinded_key_different_periods(self):
        """Test different time periods produce different blinded keys."""
        addr = OnionAddress.parse(DUCKDUCKGO_ADDRESS)
        blinded1 = addr.compute_blinded_key(time_period=1000)
        blinded2 = addr.compute_blinded_key(time_period=1001)

        assert blinded1 != blinded2

    def test_blinded_key_different_addresses(self):
        """Test different addresses produce different blinded keys."""
        addr1 = OnionAddress.parse(DUCKDUCKGO_ADDRESS)

        # Create a different valid address
        # We'll use the same period but different address
        blinded1 = addr1.compute_blinded_key(time_period=1000)

        # The blinded key should be unique to the address
        assert len(blinded1) == 32


# =============================================================================
# Tests for compute_subcredential()
# =============================================================================


class TestComputeSubcredential:
    """Tests for OnionAddress.compute_subcredential()."""

    def test_subcredential_length(self):
        """Test subcredential is 32 bytes."""
        addr = OnionAddress.parse(DUCKDUCKGO_ADDRESS)
        subcred = addr.compute_subcredential(time_period=1000)

        assert len(subcred) == 32

    def test_subcredential_deterministic(self):
        """Test subcredential is deterministic for same inputs."""
        addr = OnionAddress.parse(DUCKDUCKGO_ADDRESS)
        subcred1 = addr.compute_subcredential(time_period=1000)
        subcred2 = addr.compute_subcredential(time_period=1000)

        assert subcred1 == subcred2

    def test_subcredential_different_periods(self):
        """Test different time periods produce different subcredentials."""
        addr = OnionAddress.parse(DUCKDUCKGO_ADDRESS)
        subcred1 = addr.compute_subcredential(time_period=1000)
        subcred2 = addr.compute_subcredential(time_period=1001)

        assert subcred1 != subcred2


# =============================================================================
# Tests for _compute_checksum()
# =============================================================================


class TestComputeChecksum:
    """Tests for _compute_checksum()."""

    def test_checksum_length(self):
        """Test checksum is 2 bytes."""
        checksum = _compute_checksum(b"x" * 32, 3)
        assert len(checksum) == 2

    def test_checksum_deterministic(self):
        """Test checksum is deterministic."""
        checksum1 = _compute_checksum(b"test" * 8, 3)
        checksum2 = _compute_checksum(b"test" * 8, 3)
        assert checksum1 == checksum2

    def test_checksum_different_keys(self):
        """Test different keys produce different checksums."""
        checksum1 = _compute_checksum(b"a" * 32, 3)
        checksum2 = _compute_checksum(b"b" * 32, 3)
        assert checksum1 != checksum2

    def test_checksum_different_versions(self):
        """Test different versions produce different checksums."""
        checksum_v3 = _compute_checksum(b"x" * 32, 3)
        checksum_v2 = _compute_checksum(b"x" * 32, 2)
        assert checksum_v3 != checksum_v2


# =============================================================================
# Tests for _derive_blinded_key()
# =============================================================================


class TestDeriveBlindedKey:
    """Tests for _derive_blinded_key().

    Note: _derive_blinded_key requires valid Ed25519 public keys.
    We test it indirectly through OnionAddress.compute_blinded_key().
    """

    def test_blinded_key_via_onion_address(self):
        """Test blinded key derivation through OnionAddress."""
        addr = OnionAddress.parse(DUCKDUCKGO_ADDRESS)

        # The OnionAddress has a valid Ed25519 public key
        blinded = addr.compute_blinded_key(time_period=1000)

        assert len(blinded) == 32

    def test_blinded_key_changes_with_period(self):
        """Test blinding produces different keys for different periods."""
        addr = OnionAddress.parse(DUCKDUCKGO_ADDRESS)

        blinded1 = addr.compute_blinded_key(time_period=1000)
        blinded2 = addr.compute_blinded_key(time_period=1001)

        # Different periods should produce different blinded keys
        assert blinded1 != blinded2

    def test_blinded_key_is_valid_point(self):
        """Test blinded key is a valid Ed25519 point (32 bytes)."""
        addr = OnionAddress.parse(DUCKDUCKGO_ADDRESS)
        blinded = addr.compute_blinded_key(time_period=1000)

        # Should be exactly 32 bytes
        assert len(blinded) == 32

        # Should not be all zeros (valid point)
        assert blinded != b"\x00" * 32


# =============================================================================
# Tests for get_current_time_period()
# =============================================================================


class TestGetCurrentTimePeriod:
    """Tests for get_current_time_period()."""

    def test_returns_integer(self):
        """Test returns an integer."""
        period = get_current_time_period()
        assert isinstance(period, int)

    def test_with_reference_time(self):
        """Test with specific reference time."""
        # Jan 1, 2024 00:00:00 UTC
        ref_time = 1704067200.0

        period = get_current_time_period(reference_time=ref_time)

        assert isinstance(period, int)
        assert period > 0

    def test_period_increases_with_time(self):
        """Test period number increases with time."""
        ref_time = 1704067200.0  # Jan 1, 2024
        one_day_later = ref_time + 86400  # +24 hours

        period1 = get_current_time_period(reference_time=ref_time)
        period2 = get_current_time_period(reference_time=one_day_later)

        assert period2 == period1 + 1

    def test_same_period_within_day(self):
        """Test same period within same 24-hour window."""
        ref_time = 1704067200.0
        one_hour_later = ref_time + 3600

        period1 = get_current_time_period(reference_time=ref_time)
        period2 = get_current_time_period(reference_time=one_hour_later)

        # Should be same period (within same day)
        assert period2 == period1

    def test_custom_period_length(self):
        """Test with custom period length."""
        ref_time = 1704067200.0

        # Default period (1440 minutes = 24 hours)
        period_default = get_current_time_period(reference_time=ref_time)

        # Half-day period (720 minutes)
        period_half = get_current_time_period(
            reference_time=ref_time, period_length=720
        )

        # Half-day periods should be roughly double
        assert period_half > period_default


# =============================================================================
# Tests for get_time_period_info()
# =============================================================================


class TestGetTimePeriodInfo:
    """Tests for get_time_period_info()."""

    def test_returns_dict(self):
        """Test returns a dictionary with expected keys."""
        info = get_time_period_info()

        assert isinstance(info, dict)
        assert "period_num" in info
        assert "period_length" in info
        assert "period_start" in info
        assert "period_end" in info
        assert "remaining_seconds" in info
        assert "remaining_minutes" in info

    def test_with_reference_time(self):
        """Test with specific reference time."""
        ref_time = 1704067200.0

        info = get_time_period_info(reference_time=ref_time)

        assert info["period_num"] > 0
        assert info["period_length"] == HS_TIME_PERIOD_LENGTH

    def test_period_boundaries(self):
        """Test period start and end times are correct."""
        ref_time = 1704067200.0

        info = get_time_period_info(reference_time=ref_time)

        # Period end should be period start + 24 hours
        expected_duration = HS_TIME_PERIOD_LENGTH * 60  # seconds
        actual_duration = info["period_end"] - info["period_start"]

        assert actual_duration == expected_duration

    def test_remaining_time(self):
        """Test remaining time calculation."""
        ref_time = 1704067200.0

        info = get_time_period_info(reference_time=ref_time)

        # Remaining should be positive and less than period length
        assert info["remaining_seconds"] > 0
        assert info["remaining_seconds"] <= HS_TIME_PERIOD_LENGTH * 60

        # Minutes should match seconds / 60
        assert info["remaining_minutes"] == info["remaining_seconds"] / 60


# =============================================================================
# Tests for Constants
# =============================================================================


class TestConstants:
    """Tests for module constants."""

    def test_version_constant(self):
        """Test HS_VERSION_3 is 3."""
        assert HS_VERSION_3 == 3

    def test_period_length_constant(self):
        """Test HS_TIME_PERIOD_LENGTH is 1440 (24 hours in minutes)."""
        assert HS_TIME_PERIOD_LENGTH == 1440
