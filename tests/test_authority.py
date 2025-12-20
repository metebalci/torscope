"""Tests for directory authority module."""

from torscope.directory.authority import (
    DirectoryAuthority,
    get_authorities,
    get_authority_by_nickname,
    get_random_authority,
)


class TestDirectoryAuthority:
    """Tests for DirectoryAuthority dataclass."""

    def test_http_url_property(self):
        """Test HTTP URL generation."""
        auth = DirectoryAuthority(
            nickname="test",
            ip="192.0.2.1",
            dirport=9131,
            orport=9101,
            v3ident="ABC123",
        )
        assert auth.http_url == "http://192.0.2.1:9131"

    def test_address_property(self):
        """Test address string formatting."""
        auth = DirectoryAuthority(
            nickname="test",
            ip="192.0.2.1",
            dirport=9131,
            orport=9101,
            v3ident="ABC123",
        )
        assert auth.address == "192.0.2.1:9131"

    def test_ipv6_address_optional(self):
        """Test IPv6 address is optional."""
        auth = DirectoryAuthority(
            nickname="test",
            ip="192.0.2.1",
            dirport=9131,
            orport=9101,
            v3ident="ABC123",
        )
        assert auth.ipv6_address is None

        auth_with_ipv6 = DirectoryAuthority(
            nickname="test",
            ip="192.0.2.1",
            dirport=9131,
            orport=9101,
            v3ident="ABC123",
            ipv6_address="[2001:db8::1]:9131",
        )
        assert auth_with_ipv6.ipv6_address == "[2001:db8::1]:9131"


class TestDirectoryAuthorityList:
    """Tests for get_authorities() function."""

    def test_has_nine_authorities(self):
        """Test that we have exactly 9 directory authorities."""
        assert len(get_authorities()) == 9

    def test_all_authorities_have_required_fields(self):
        """Test all authorities have required fields populated."""
        for auth in get_authorities():
            assert auth.nickname
            assert auth.ip
            assert auth.dirport > 0
            assert auth.orport > 0
            assert auth.v3ident
            assert len(auth.v3ident) == 40  # SHA-1 hex fingerprint

    def test_all_authorities_have_unique_nicknames(self):
        """Test all authorities have unique nicknames."""
        nicknames = [auth.nickname for auth in get_authorities()]
        assert len(nicknames) == len(set(nicknames))

    def test_all_authorities_have_unique_v3idents(self):
        """Test all authorities have unique v3 identity fingerprints."""
        v3idents = [auth.v3ident for auth in get_authorities()]
        assert len(v3idents) == len(set(v3idents))

    def test_known_authority_moria1(self):
        """Test moria1 authority exists and has valid fields."""
        moria1 = next(
            (auth for auth in get_authorities() if auth.nickname == "moria1"),
            None,
        )
        assert moria1 is not None
        assert moria1.ip  # has IP
        assert moria1.dirport > 0
        assert moria1.orport > 0
        assert len(moria1.v3ident) == 40  # hex fingerprint

    def test_known_authority_tor26(self):
        """Test tor26 authority exists and has valid fields."""
        tor26 = next(
            (auth for auth in get_authorities() if auth.nickname == "tor26"),
            None,
        )
        assert tor26 is not None
        assert tor26.ip  # has IP
        assert tor26.dirport > 0
        assert tor26.orport > 0

    def test_authorities_with_ipv6(self):
        """Test that some authorities have IPv6 addresses."""
        ipv6_authorities = [auth for auth in get_authorities() if auth.ipv6_address is not None]
        # gabelmoo and maatuska have IPv6 addresses
        assert len(ipv6_authorities) >= 2

        # Check specific IPv6 addresses
        gabelmoo = next(
            (auth for auth in get_authorities() if auth.nickname == "gabelmoo"),
            None,
        )
        assert gabelmoo is not None
        assert gabelmoo.ipv6_address == "[2001:638:a000:4140::ffff:189]:443"


class TestGetAuthorityByNickname:
    """Tests for get_authority_by_nickname function."""

    def test_get_existing_authority_lowercase(self):
        """Test getting an authority by lowercase nickname."""
        auth = get_authority_by_nickname("moria1")
        assert auth is not None
        assert auth.nickname == "moria1"

    def test_get_existing_authority_uppercase(self):
        """Test getting an authority by uppercase nickname (case-insensitive)."""
        auth = get_authority_by_nickname("MORIA1")
        assert auth is not None
        assert auth.nickname == "moria1"

    def test_get_existing_authority_mixedcase(self):
        """Test getting an authority by mixed-case nickname."""
        auth = get_authority_by_nickname("MoRiA1")
        assert auth is not None
        assert auth.nickname == "moria1"

    def test_get_nonexistent_authority(self):
        """Test getting a non-existent authority returns None."""
        auth = get_authority_by_nickname("nonexistent")
        assert auth is None

    def test_get_all_authorities_by_nickname(self):
        """Test that all authorities can be retrieved by nickname."""
        expected_nicknames = [
            "moria1",
            "tor26",
            "dizum",
            "gabelmoo",
            "dannenberg",
            "maatuska",
            "Faravahar",
            "longclaw",
            "bastet",
        ]

        for nickname in expected_nicknames:
            auth = get_authority_by_nickname(nickname)
            assert auth is not None
            assert auth.nickname.lower() == nickname.lower()


class TestGetRandomAuthority:
    """Tests for get_random_authority function."""

    def test_returns_valid_authority(self):
        """Test that get_random_authority returns a valid authority."""
        auth = get_random_authority()
        assert auth is not None
        assert auth in get_authorities()

    def test_returns_different_authorities(self):
        """Test that get_random_authority can return different authorities."""
        # Get 20 random authorities, should get some variation
        authorities = [get_random_authority() for _ in range(20)]
        unique_authorities = {auth.nickname for auth in authorities}

        # With 9 authorities and 20 selections, we should get at least 2 different ones
        # This test could theoretically fail due to randomness, but probability is very low
        assert len(unique_authorities) >= 2

    def test_returns_authority_from_list(self):
        """Test that random authority is always from the official list."""
        for _ in range(10):
            auth = get_random_authority()
            assert auth in get_authorities()
