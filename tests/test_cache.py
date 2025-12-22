"""Tests for cache module."""


import pytest

from torscope.cache import (
    _digest_to_filename,
    _filename_to_digest,
    _normalize_digest,
    clear_cache,
    get_cache_info,
    load_consensus,
    save_consensus,
)
from torscope.utils import pad_base64


class TestPadBase64:
    """Tests for pad_base64 utility function."""

    def test_no_padding_needed(self):
        """Test string that's already padded."""
        assert pad_base64("YWJj") == "YWJj"  # 4 chars, no padding needed

    def test_add_one_padding(self):
        """Test adding one = padding character."""
        assert pad_base64("YWI") == "YWI="  # 3 chars -> 1 padding

    def test_add_two_padding(self):
        """Test adding two = padding characters."""
        assert pad_base64("YQ") == "YQ=="  # 2 chars -> 2 padding

    def test_strip_existing_padding(self):
        """Test that existing padding is handled correctly."""
        assert pad_base64("YWI=") == "YWI="
        assert pad_base64("YQ==") == "YQ=="

    def test_empty_string(self):
        """Test empty string."""
        assert pad_base64("") == ""


class TestNormalizeDigest:
    """Tests for _normalize_digest function."""

    def test_normalize_unpadded_digest(self):
        """Test normalizing a digest without padding."""
        # 43 chars without padding
        digest = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789012345"
        result = _normalize_digest(digest)
        assert result.endswith("=")

    def test_normalize_already_padded(self):
        """Test that already-padded digest is unchanged."""
        digest = "ABCD"  # 4 chars, no padding needed
        result = _normalize_digest(digest)
        assert result == "ABCD"

    def test_normalize_strips_excess_padding(self):
        """Test that excess padding is handled."""
        digest = "ABC======="
        result = _normalize_digest(digest)
        assert result == "ABC="


class TestDigestFilenameConversion:
    """Tests for digest <-> filename conversion."""

    def test_roundtrip_valid_base64(self):
        """Test that valid base64 roundtrips correctly."""
        original = "dGVzdA=="  # "test" in base64
        filename = _digest_to_filename(original)
        recovered = _filename_to_digest(filename)

        # Both should decode to same bytes
        import base64

        assert base64.b64decode(original) == base64.b64decode(recovered)

    def test_filename_is_hex(self):
        """Test that filename is hex-encoded."""
        digest = "dGVzdA=="
        filename = _digest_to_filename(digest)

        # Should be hex + .json
        assert filename.endswith(".json")
        hex_part = filename[:-5]
        # Should be valid hex
        bytes.fromhex(hex_part)  # Raises ValueError if not valid hex


class TestConsensusCache:
    """Tests for consensus caching functions."""

    @pytest.fixture
    def temp_cache_dir(self, tmp_path, monkeypatch):
        """Set up a temporary cache directory."""
        cache_dir = tmp_path / ".torscope"
        monkeypatch.setattr("torscope.cache.CACHE_DIR", cache_dir)
        monkeypatch.setattr("torscope.cache.CONSENSUS_FILE", cache_dir / "consensus.bin")
        monkeypatch.setattr("torscope.cache.CONSENSUS_META", cache_dir / "consensus.json")
        monkeypatch.setattr("torscope.cache.MICRODESC_DIR", cache_dir / "microdesc")
        return cache_dir

    def test_save_and_load_consensus(self, temp_cache_dir):
        """Test saving and loading consensus content."""
        # Create minimal valid consensus content
        content = b"""network-status-version 3 microdesc
vote-status consensus
consensus-method 28
valid-after 2024-01-01 00:00:00
fresh-until 2024-01-01 01:00:00
valid-until 2024-01-01 03:00:00
voting-delay 300 300
"""
        source = "test_authority"

        # Save
        save_consensus(content, source, source_type="authority")

        # Check files exist
        assert (temp_cache_dir / "consensus.bin").exists()
        assert (temp_cache_dir / "consensus.json").exists()

    def test_get_cache_info(self, temp_cache_dir):
        """Test getting cache information."""
        content = b"test consensus content"
        source = "test_authority"

        save_consensus(content, source)
        info = get_cache_info()

        assert info is not None
        assert info["source"] == source

    def test_clear_cache(self, temp_cache_dir):
        """Test clearing the cache."""
        content = b"test consensus content"
        save_consensus(content, "test")

        assert (temp_cache_dir / "consensus.bin").exists()

        clear_cache()

        assert not (temp_cache_dir / "consensus.bin").exists()
        assert not (temp_cache_dir / "consensus.json").exists()

    def test_load_nonexistent_cache(self, temp_cache_dir):
        """Test loading when no cache exists."""
        result = load_consensus()
        assert result is None

    def test_cache_info_nonexistent(self, temp_cache_dir):
        """Test cache info when no cache exists."""
        result = get_cache_info()
        assert result is None
