"""Tests for exit policy parsing and matching."""

from torscope.directory.exit_policy import ExitPolicy, check_exit_policy, parse_port_list


class TestParsePortList:
    """Tests for parse_port_list function."""

    def test_single_port(self):
        """Test parsing a single port."""
        assert parse_port_list("80") == {80}

    def test_multiple_ports(self):
        """Test parsing multiple ports."""
        assert parse_port_list("80,443,8080") == {80, 443, 8080}

    def test_port_range(self):
        """Test parsing a port range."""
        assert parse_port_list("20-23") == {20, 21, 22, 23}

    def test_mixed_ports_and_ranges(self):
        """Test parsing mixed ports and ranges."""
        result = parse_port_list("22,80,443,8000-8002")
        assert result == {22, 80, 443, 8000, 8001, 8002}

    def test_empty_string(self):
        """Test parsing empty string."""
        assert parse_port_list("") == set()

    def test_whitespace(self):
        """Test parsing with whitespace."""
        assert parse_port_list("80, 443, 8080") == {80, 443, 8080}

    def test_invalid_port(self):
        """Test parsing invalid port is ignored."""
        assert parse_port_list("80,abc,443") == {80, 443}


class TestExitPolicy:
    """Tests for ExitPolicy class."""

    def test_accept_policy_allows_listed_port(self):
        """Test accept policy allows ports in list."""
        policy = ExitPolicy("accept 80,443")
        assert policy.allows_port(80) is True
        assert policy.allows_port(443) is True

    def test_accept_policy_denies_unlisted_port(self):
        """Test accept policy denies ports not in list."""
        policy = ExitPolicy("accept 80,443")
        assert policy.allows_port(22) is False
        assert policy.allows_port(8080) is False

    def test_reject_policy_denies_listed_port(self):
        """Test reject policy denies ports in list."""
        policy = ExitPolicy("reject 25,119")
        assert policy.allows_port(25) is False
        assert policy.allows_port(119) is False

    def test_reject_policy_allows_unlisted_port(self):
        """Test reject policy allows ports not in list."""
        policy = ExitPolicy("reject 25,119")
        assert policy.allows_port(80) is True
        assert policy.allows_port(443) is True

    def test_accept_range(self):
        """Test accept policy with port range."""
        policy = ExitPolicy("accept 80-90")
        assert policy.allows_port(80) is True
        assert policy.allows_port(85) is True
        assert policy.allows_port(90) is True
        assert policy.allows_port(79) is False
        assert policy.allows_port(91) is False

    def test_reject_all(self):
        """Test reject all ports."""
        policy = ExitPolicy("reject 1-65535")
        assert policy.allows_port(80) is False
        assert policy.allows_port(443) is False
        assert policy.allows_port(1) is False
        assert policy.allows_port(65535) is False

    def test_accept_all(self):
        """Test accept all ports."""
        policy = ExitPolicy("accept 1-65535")
        assert policy.allows_port(80) is True
        assert policy.allows_port(443) is True
        assert policy.allows_port(1) is True
        assert policy.allows_port(65535) is True

    def test_empty_policy(self):
        """Test empty policy denies all."""
        policy = ExitPolicy("")
        assert policy.allows_port(80) is False

    def test_none_policy(self):
        """Test None policy denies all."""
        policy = ExitPolicy(None)
        assert policy.allows_port(80) is False

    def test_repr(self):
        """Test string representation."""
        policy = ExitPolicy("accept 80,443")
        assert repr(policy) == "ExitPolicy('accept 80,443')"


class TestCheckExitPolicy:
    """Tests for check_exit_policy convenience function."""

    def test_accept(self):
        """Test accept policy."""
        assert check_exit_policy("accept 80,443", 80) is True
        assert check_exit_policy("accept 80,443", 22) is False

    def test_reject(self):
        """Test reject policy."""
        assert check_exit_policy("reject 25", 25) is False
        assert check_exit_policy("reject 25", 80) is True

    def test_none(self):
        """Test None policy."""
        assert check_exit_policy(None, 80) is False
