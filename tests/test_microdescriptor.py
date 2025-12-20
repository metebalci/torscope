"""Tests for microdescriptor parser."""

from torscope.directory.microdescriptor import MicrodescriptorParser
from torscope.directory.models import Microdescriptor

# Sample microdescriptor for testing
SAMPLE_MICRODESCRIPTOR = """\
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALxl2nqz/EBdF45zGqVz5m8uLxWP0nSJ3u0Y4WvPdY1zxTZ7aIgZvxns
9F9LIzKl0D1Q/KWzq9Q3Q6nL5E3WqYZZ9SfD4f5T6H9aU3uL5FpE5L5e3r4CwO4v
7X3+5T7E8L+0Y3CwFZ8X+9D9O5E3L+4T9D4X8T+2Y8+3Y+5Z3Z2E5AgMBAAE=
-----END RSA PUBLIC KEY-----
ntor-onion-key 2DnqH+s1r5F3L4E5K6v7W8e9D0a1B2c3D4e5F6g7H8i=
a [2001:db8::1]:9001
p accept 80,443
p6 accept 80,443
id ed25519 AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdef
id rsa1024 XyZaBcDeFgHiJkLmNoPqRsTuVwXy
family $AAAA1234567890ABCDEF1234567890ABCDEF1234 $BBBB1234567890ABCDEF1234567890ABCDEF1234
"""

SAMPLE_MICRODESCRIPTOR_MINIMAL = """\
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALxl2nqz/EBdF45zGqVz5m8uLxWP0nSJ3u0Y4WvPdY1zxTZ7aIgZvxns
9F9LIzKl0D1Q/KWzq9Q3Q6nL5E3WqYZZ9SfD4f5T6H9aU3uL5FpE5L5e3r4CwO4v
7X3+5T7E8L+0Y3CwFZ8X+9D9O5E3L+4T9D4X8T+2Y8+3Y+5Z3Z2E5AgMBAAE=
-----END RSA PUBLIC KEY-----
"""

MULTIPLE_MICRODESCRIPTORS = """\
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALxl2nqz/EBdF45zGqVz5m8uLxWP0nSJ3u0Y4WvPdY1zxTZ7aIgZvxns
9F9LIzKl0D1Q/KWzq9Q3Q6nL5E3WqYZZ9SfD4f5T6H9aU3uL5FpE5L5e3r4CwO4v
7X3+5T7E8L+0Y3CwFZ8X+9D9O5E3L+4T9D4X8T+2Y8+3Y+5Z3Z2E5AgMBAAE=
-----END RSA PUBLIC KEY-----
ntor-onion-key FirstKey123456789012345678901234567890abc=
p accept 80
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMxl2nqz/EBdF45zGqVz5m8uLxWP0nSJ3u0Y4WvPdY1zxTZ7aIgZvxns
9F9LIzKl0D1Q/KWzq9Q3Q6nL5E3WqYZZ9SfD4f5T6H9aU3uL5FpE5L5e3r4CwO4v
7X3+5T7E8L+0Y3CwFZ8X+9D9O5E3L+4T9D4X8T+2Y8+3Y+5Z3Z2E5AgMBAAE=
-----END RSA PUBLIC KEY-----
ntor-onion-key SecondKey12345678901234567890123456789abc=
p reject 1-65535
"""


class TestMicrodescriptorParser:
    """Tests for MicrodescriptorParser."""

    def test_parse_single_microdescriptor(self):
        """Test parsing a single microdescriptor."""
        mds = MicrodescriptorParser.parse(SAMPLE_MICRODESCRIPTOR)
        assert len(mds) == 1
        md = mds[0]
        assert isinstance(md, Microdescriptor)

    def test_parse_onion_key_rsa(self):
        """Test parsing RSA onion key."""
        mds = MicrodescriptorParser.parse(SAMPLE_MICRODESCRIPTOR)
        md = mds[0]
        assert md.onion_key_rsa is not None
        assert "-----BEGIN RSA PUBLIC KEY-----" in md.onion_key_rsa
        assert "-----END RSA PUBLIC KEY-----" in md.onion_key_rsa

    def test_parse_ntor_onion_key(self):
        """Test parsing ntor onion key."""
        mds = MicrodescriptorParser.parse(SAMPLE_MICRODESCRIPTOR)
        md = mds[0]
        assert md.onion_key_ntor == "2DnqH+s1r5F3L4E5K6v7W8e9D0a1B2c3D4e5F6g7H8i="

    def test_parse_ipv6_address(self):
        """Test parsing IPv6 address."""
        mds = MicrodescriptorParser.parse(SAMPLE_MICRODESCRIPTOR)
        md = mds[0]
        assert "[2001:db8::1]:9001" in md.ipv6_addresses

    def test_parse_exit_policy_v4(self):
        """Test parsing IPv4 exit policy."""
        mds = MicrodescriptorParser.parse(SAMPLE_MICRODESCRIPTOR)
        md = mds[0]
        assert md.exit_policy_v4 == "accept 80,443"

    def test_parse_exit_policy_v6(self):
        """Test parsing IPv6 exit policy."""
        mds = MicrodescriptorParser.parse(SAMPLE_MICRODESCRIPTOR)
        md = mds[0]
        assert md.exit_policy_v6 == "accept 80,443"

    def test_parse_ed25519_identity(self):
        """Test parsing ed25519 identity."""
        mds = MicrodescriptorParser.parse(SAMPLE_MICRODESCRIPTOR)
        md = mds[0]
        assert md.ed25519_identity == "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdef"

    def test_parse_rsa1024_identity(self):
        """Test parsing rsa1024 identity."""
        mds = MicrodescriptorParser.parse(SAMPLE_MICRODESCRIPTOR)
        md = mds[0]
        assert md.rsa1024_identity == "XyZaBcDeFgHiJkLmNoPqRsTuVwXy"

    def test_parse_family(self):
        """Test parsing family members."""
        mds = MicrodescriptorParser.parse(SAMPLE_MICRODESCRIPTOR)
        md = mds[0]
        assert len(md.family_members) == 2
        assert "$AAAA1234567890ABCDEF1234567890ABCDEF1234" in md.family_members
        assert "$BBBB1234567890ABCDEF1234567890ABCDEF1234" in md.family_members

    def test_parse_minimal_microdescriptor(self):
        """Test parsing minimal microdescriptor with only required fields."""
        mds = MicrodescriptorParser.parse(SAMPLE_MICRODESCRIPTOR_MINIMAL)
        assert len(mds) == 1
        md = mds[0]
        assert md.onion_key_rsa is not None
        assert md.onion_key_ntor is None
        assert md.exit_policy_v4 is None
        assert md.exit_policy_v6 is None
        assert len(md.ipv6_addresses) == 0
        assert len(md.family_members) == 0

    def test_parse_multiple_microdescriptors(self):
        """Test parsing multiple microdescriptors in one document."""
        mds = MicrodescriptorParser.parse(MULTIPLE_MICRODESCRIPTORS)
        assert len(mds) == 2

        # First microdescriptor
        assert mds[0].onion_key_ntor == "FirstKey123456789012345678901234567890abc="
        assert mds[0].exit_policy_v4 == "accept 80"

        # Second microdescriptor
        assert mds[1].onion_key_ntor == "SecondKey12345678901234567890123456789abc="
        assert mds[1].exit_policy_v4 == "reject 1-65535"

    def test_parse_bytes_content(self):
        """Test parsing bytes content."""
        content = SAMPLE_MICRODESCRIPTOR.encode("utf-8")
        mds = MicrodescriptorParser.parse(content)
        assert len(mds) == 1

    def test_digest_is_computed(self):
        """Test that SHA256 digest is computed."""
        mds = MicrodescriptorParser.parse(SAMPLE_MICRODESCRIPTOR)
        md = mds[0]
        assert md.digest is not None
        # Base64-encoded SHA256 is 43 characters without padding (Tor convention)
        # or 44 characters with padding
        assert len(md.digest) in (43, 44)

    def test_raw_descriptor_stored(self):
        """Test that raw descriptor is stored."""
        mds = MicrodescriptorParser.parse(SAMPLE_MICRODESCRIPTOR)
        md = mds[0]
        assert md.raw_descriptor is not None
        assert "onion-key" in md.raw_descriptor

    def test_fetched_at_set(self):
        """Test that fetched_at timestamp is set."""
        mds = MicrodescriptorParser.parse(SAMPLE_MICRODESCRIPTOR)
        md = mds[0]
        assert md.fetched_at is not None

    def test_is_exit_property(self):
        """Test is_exit property."""
        mds = MicrodescriptorParser.parse(SAMPLE_MICRODESCRIPTOR)
        md = mds[0]
        assert md.is_exit is True  # has "accept" policy

        mds = MicrodescriptorParser.parse(MULTIPLE_MICRODESCRIPTORS)
        assert mds[0].is_exit is True  # accept 80
        assert mds[1].is_exit is False  # reject 1-65535

    def test_parse_empty_content(self):
        """Test parsing empty content."""
        mds = MicrodescriptorParser.parse("")
        assert len(mds) == 0

    def test_parse_family_ids(self):
        """Test parsing family-ids field."""
        content = """\
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALxl2nqz/EBdF45zGqVz5m8uLxWP0nSJ3u0Y4WvPdY1zxTZ7aIgZvxns
9F9LIzKl0D1Q/KWzq9Q3Q6nL5E3WqYZZ9SfD4f5T6H9aU3uL5FpE5L5e3r4CwO4v
7X3+5T7E8L+0Y3CwFZ8X+9D9O5E3L+4T9D4X8T+2Y8+3Y+5Z3Z2E5AgMBAAE=
-----END RSA PUBLIC KEY-----
family-ids abc123 def456 ghi789
"""
        mds = MicrodescriptorParser.parse(content)
        assert len(mds) == 1
        assert mds[0].family_ids == ["abc123", "def456", "ghi789"]

    def test_parse_multiple_ipv6_addresses(self):
        """Test parsing multiple IPv6 addresses."""
        content = """\
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALxl2nqz/EBdF45zGqVz5m8uLxWP0nSJ3u0Y4WvPdY1zxTZ7aIgZvxns
9F9LIzKl0D1Q/KWzq9Q3Q6nL5E3WqYZZ9SfD4f5T6H9aU3uL5FpE5L5e3r4CwO4v
7X3+5T7E8L+0Y3CwFZ8X+9D9O5E3L+4T9D4X8T+2Y8+3Y+5Z3Z2E5AgMBAAE=
-----END RSA PUBLIC KEY-----
a [2001:db8::1]:9001
a [2001:db8::2]:9002
"""
        mds = MicrodescriptorParser.parse(content)
        assert len(mds) == 1
        assert len(mds[0].ipv6_addresses) == 2
        assert "[2001:db8::1]:9001" in mds[0].ipv6_addresses
        assert "[2001:db8::2]:9002" in mds[0].ipv6_addresses
