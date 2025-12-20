"""Tests for server descriptor parsing."""

from torscope.directory.descriptor import ServerDescriptorParser
from torscope.directory.models import ServerDescriptor

# Sample server descriptor for testing
SAMPLE_DESCRIPTOR = b"""router TestRelay 192.0.2.1 9001 0 0
identity-ed25519
-----BEGIN ED25519 CERT-----
AQQABp1bAXe...
-----END ED25519 CERT-----
master-key-ed25519 AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFGH
platform Tor 0.4.8.10 on Linux
proto Cons=1-2 Desc=1-2 DirCache=2 HSDir=2 HSIntro=4-5 Link=1-5 Microdesc=1-2 Relay=1-4
published 2024-01-15 12:00:00
fingerprint ABCD 1234 EFGH 5678 IJKL 9012 MNOP 3456 QRST 7890
uptime 86400
bandwidth 1000000 2000000 500000
extra-info-digest ABC123 DEF456
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALZpAOmKd...
-----END RSA PUBLIC KEY-----
signing-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAN1k2B3...
-----END RSA PUBLIC KEY-----
ntor-onion-key AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD
contact admin@example.com
family $AAAA $BBBB $CCCC
reject *:25
reject *:119
reject *:135-139
accept *:*
router-sig-ed25519 AbCdE...
router-signature
-----BEGIN SIGNATURE-----
ZWx...
-----END SIGNATURE-----
"""


class TestServerDescriptorParser:
    """Tests for ServerDescriptorParser."""

    def test_parse_basic_descriptor(self):
        """Test parsing a basic server descriptor."""
        descriptors = ServerDescriptorParser.parse(SAMPLE_DESCRIPTOR)
        assert len(descriptors) == 1

        desc = descriptors[0]
        assert desc.nickname == "TestRelay"
        assert desc.ip == "192.0.2.1"
        assert desc.orport == 9001
        assert desc.dirport == 0

    def test_parse_fingerprint(self):
        """Test fingerprint parsing."""
        descriptors = ServerDescriptorParser.parse(SAMPLE_DESCRIPTOR)
        desc = descriptors[0]
        # Fingerprint should be joined without spaces
        assert desc.fingerprint == "ABCD1234EFGH5678IJKL9012MNOP3456QRST7890"

    def test_parse_bandwidth(self):
        """Test bandwidth parsing."""
        descriptors = ServerDescriptorParser.parse(SAMPLE_DESCRIPTOR)
        desc = descriptors[0]
        assert desc.bandwidth_avg == 1000000
        assert desc.bandwidth_burst == 2000000
        assert desc.bandwidth_observed == 500000

    def test_parse_uptime(self):
        """Test uptime parsing."""
        descriptors = ServerDescriptorParser.parse(SAMPLE_DESCRIPTOR)
        desc = descriptors[0]
        assert desc.uptime == 86400
        assert desc.uptime_days == 1.0

    def test_parse_contact(self):
        """Test contact parsing."""
        descriptors = ServerDescriptorParser.parse(SAMPLE_DESCRIPTOR)
        desc = descriptors[0]
        assert desc.contact == "admin@example.com"

    def test_parse_family(self):
        """Test family parsing."""
        descriptors = ServerDescriptorParser.parse(SAMPLE_DESCRIPTOR)
        desc = descriptors[0]
        assert desc.family == ["$AAAA", "$BBBB", "$CCCC"]

    def test_parse_exit_policy(self):
        """Test exit policy parsing."""
        descriptors = ServerDescriptorParser.parse(SAMPLE_DESCRIPTOR)
        desc = descriptors[0]
        assert len(desc.exit_policy) == 4
        assert "reject *:25" in desc.exit_policy
        assert "accept *:*" in desc.exit_policy

    def test_parse_ntor_key(self):
        """Test ntor onion key parsing."""
        descriptors = ServerDescriptorParser.parse(SAMPLE_DESCRIPTOR)
        desc = descriptors[0]
        assert desc.ntor_onion_key == "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD"

    def test_parse_platform(self):
        """Test platform parsing."""
        descriptors = ServerDescriptorParser.parse(SAMPLE_DESCRIPTOR)
        desc = descriptors[0]
        assert desc.platform == "Tor 0.4.8.10 on Linux"
        assert desc.tor_version == "0.4.8.10"

    def test_parse_protocols(self):
        """Test protocol parsing."""
        descriptors = ServerDescriptorParser.parse(SAMPLE_DESCRIPTOR)
        desc = descriptors[0]
        assert desc.protocols is not None
        assert "Cons" in desc.protocols
        assert desc.protocols["Cons"] == [1, 2]
        assert "Link" in desc.protocols
        assert desc.protocols["Link"] == [1, 2, 3, 4, 5]

    def test_parse_empty(self):
        """Test parsing empty content."""
        descriptors = ServerDescriptorParser.parse(b"")
        assert descriptors == []

    def test_parse_invalid(self):
        """Test parsing invalid content."""
        descriptors = ServerDescriptorParser.parse(b"not a descriptor")
        assert descriptors == []

    def test_bandwidth_mbps_property(self):
        """Test bandwidth_mbps property."""
        desc = ServerDescriptor(
            nickname="test",
            fingerprint="ABC123",
            published=None,  # type: ignore
            ip="192.0.2.1",
            orport=9001,
            bandwidth_observed=5_000_000,
        )
        assert desc.bandwidth_mbps == 5.0

    def test_uptime_days_property_none(self):
        """Test uptime_days when uptime is None."""
        desc = ServerDescriptor(
            nickname="test",
            fingerprint="ABC123",
            published=None,  # type: ignore
            ip="192.0.2.1",
            orport=9001,
        )
        assert desc.uptime_days is None
