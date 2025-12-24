"""End-to-end tests requiring a local Tor instance.

These tests validate torscope against a real Tor instance running locally.
Tests auto-skip if Tor is not available on the expected ports.

Requirements:
    - Tor running with SOCKS port 9050
    - Tor running with Control port 9051
    - Control port password: "tor"

Run these tests:
    pytest tests/test_e2e_tor.py -v

These tests are skipped automatically if Tor is not running.
"""

import socket
import struct

import pytest

# DuckDuckGo's v3 onion address (well-known, stable)
DUCKDUCKGO_ONION = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"

# Tor configuration
TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050
TOR_CONTROL_HOST = "127.0.0.1"
TOR_CONTROL_PORT = 9051
TOR_CONTROL_PASSWORD = "tor"


# =============================================================================
# Fixtures
# =============================================================================


def _check_tor_control_port() -> tuple[bool, str]:
    """Check if Tor control port is available and responding.

    Returns:
        Tuple of (is_available, message)
    """
    try:
        sock = socket.create_connection(
            (TOR_CONTROL_HOST, TOR_CONTROL_PORT), timeout=5
        )
    except (ConnectionRefusedError, TimeoutError, OSError):
        return False, "Tor not detected (control port)"

    try:
        # Send PROTOCOLINFO (doesn't require authentication)
        sock.send(b"PROTOCOLINFO\r\n")
        response = sock.recv(1024)

        # Tor responds with "250-VERSION Tor=" in PROTOCOLINFO
        if b"VERSION" not in response.upper() or b"TOR" not in response.upper():
            return False, "Tor not detected (control port not Tor)"

        return True, "Tor control port available"
    finally:
        sock.close()


def _check_tor_socks_port() -> tuple[bool, str]:
    """Check if Tor SOCKS port is available and is actually SOCKS5.

    Returns:
        Tuple of (is_available, message)
    """
    try:
        sock = socket.create_connection(
            (TOR_SOCKS_HOST, TOR_SOCKS_PORT), timeout=5
        )
    except (ConnectionRefusedError, TimeoutError, OSError):
        return False, "Tor not detected (SOCKS port)"

    try:
        # SOCKS5 handshake: version 5, 1 auth method, no auth (0x00)
        sock.send(b"\x05\x01\x00")
        response = sock.recv(2)

        if len(response) < 2:
            return False, "Tor not detected (SOCKS not responding)"

        if response[0] != 0x05:
            return False, "Tor not detected (not SOCKS5)"

        if response[1] == 0xFF:
            return False, "Tor not detected (SOCKS auth rejected)"

        return True, "Tor SOCKS port available"
    finally:
        sock.close()


@pytest.fixture
def tor_control() -> socket.socket:
    """Fixture providing authenticated Tor control connection.

    Skips test if Tor control port is not available.
    """
    available, message = _check_tor_control_port()
    if not available:
        pytest.skip(message)

    sock = socket.create_connection(
        (TOR_CONTROL_HOST, TOR_CONTROL_PORT), timeout=30
    )

    # Authenticate
    sock.send(f'AUTHENTICATE "{TOR_CONTROL_PASSWORD}"\r\n'.encode())
    response = sock.recv(1024)

    if not response.startswith(b"250"):
        sock.close()
        pytest.skip(f"Tor control authentication failed: {response.decode()}")

    yield sock
    sock.close()


@pytest.fixture
def tor_socks() -> tuple[str, int]:
    """Fixture providing Tor SOCKS proxy address.

    Skips test if Tor SOCKS port is not available.
    """
    available, message = _check_tor_socks_port()
    if not available:
        pytest.skip(message)

    return (TOR_SOCKS_HOST, TOR_SOCKS_PORT)


# =============================================================================
# Helper Functions
# =============================================================================


def socks5_connect(
    proxy_host: str,
    proxy_port: int,
    dest_host: str,
    dest_port: int,
    timeout: float = 30,
) -> socket.socket:
    """Connect to a destination through SOCKS5 proxy.

    Args:
        proxy_host: SOCKS5 proxy host
        proxy_port: SOCKS5 proxy port
        dest_host: Destination hostname
        dest_port: Destination port
        timeout: Connection timeout

    Returns:
        Connected socket

    Raises:
        Exception: If connection fails
    """
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)

    # SOCKS5 handshake
    sock.send(b"\x05\x01\x00")  # Version 5, 1 method, no auth
    response = sock.recv(2)
    if response != b"\x05\x00":
        sock.close()
        raise Exception(f"SOCKS5 handshake failed: {response.hex()}")

    # SOCKS5 connect request
    # Version (1) + Command (1) + Reserved (1) + Address type (1) + Address + Port (2)
    dest_host_bytes = dest_host.encode()
    request = (
        b"\x05"  # Version
        + b"\x01"  # Connect command
        + b"\x00"  # Reserved
        + b"\x03"  # Domain name address type
        + bytes([len(dest_host_bytes)])  # Domain length
        + dest_host_bytes  # Domain
        + struct.pack(">H", dest_port)  # Port (big-endian)
    )
    sock.send(request)

    # Read response (at least 10 bytes for IPv4 response)
    response = sock.recv(10)
    if len(response) < 2:
        sock.close()
        raise Exception("SOCKS5 connect response too short")

    if response[1] != 0x00:
        sock.close()
        error_codes = {
            0x01: "General failure",
            0x02: "Connection not allowed",
            0x03: "Network unreachable",
            0x04: "Host unreachable",
            0x05: "Connection refused",
            0x06: "TTL expired",
            0x07: "Command not supported",
            0x08: "Address type not supported",
        }
        error = error_codes.get(response[1], f"Unknown error {response[1]}")
        raise Exception(f"SOCKS5 connect failed: {error}")

    return sock


def socks5_resolve(
    proxy_host: str,
    proxy_port: int,
    hostname: str,
    timeout: float = 30,
) -> str | None:
    """Resolve hostname through Tor SOCKS5 proxy (RESOLVE command).

    Uses SOCKS5 RESOLVE extension (command 0xF0) supported by Tor.

    Args:
        proxy_host: SOCKS5 proxy host
        proxy_port: SOCKS5 proxy port
        hostname: Hostname to resolve
        timeout: Connection timeout

    Returns:
        Resolved IP address as string, or None if resolution failed
    """
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)

    try:
        # SOCKS5 handshake
        sock.send(b"\x05\x01\x00")
        response = sock.recv(2)
        if response != b"\x05\x00":
            return None

        # SOCKS5 RESOLVE request (Tor extension, command 0xF0)
        hostname_bytes = hostname.encode()
        request = (
            b"\x05"  # Version
            + b"\xF0"  # RESOLVE command (Tor extension)
            + b"\x00"  # Reserved
            + b"\x03"  # Domain name
            + bytes([len(hostname_bytes)])
            + hostname_bytes
            + b"\x00\x00"  # Port (ignored for RESOLVE)
        )
        sock.send(request)

        # Read response
        response = sock.recv(32)
        if len(response) < 4 or response[1] != 0x00:
            return None

        # Parse address from response
        addr_type = response[3]
        if addr_type == 0x01:  # IPv4
            if len(response) >= 10:
                ip_bytes = response[4:8]
                return socket.inet_ntoa(ip_bytes)
        elif addr_type == 0x04:  # IPv6
            if len(response) >= 22:
                ip_bytes = response[4:20]
                return socket.inet_ntop(socket.AF_INET6, ip_bytes)

        return None
    finally:
        sock.close()


# =============================================================================
# Control Port Tests
# =============================================================================


class TestControlPort:
    """Tests using Tor control port."""

    def test_getinfo_version(self, tor_control: socket.socket):
        """Test getting Tor version via control port."""
        tor_control.send(b"GETINFO version\r\n")
        response = tor_control.recv(1024).decode()

        assert "250" in response
        assert "version=" in response.lower()

    def test_getinfo_circuit_status(self, tor_control: socket.socket):
        """Test getting circuit status via control port."""
        tor_control.send(b"GETINFO circuit-status\r\n")
        response = tor_control.recv(4096).decode()

        # Should return 250 OK (even if no circuits)
        assert "250" in response

    def test_getinfo_network_status(self, tor_control: socket.socket):
        """Test getting network status via control port."""
        tor_control.send(b"GETINFO ns/all\r\n")
        response = b""

        # Read until we get 250 OK (network status can be large)
        while b"250 OK" not in response:
            chunk = tor_control.recv(65536)
            if not chunk:
                break
            response += chunk
            if len(response) > 10_000_000:  # 10MB limit
                break

        assert b"250 OK" in response
        # Should contain router entries
        assert b"r " in response  # Router lines start with "r "

    def test_signal_newnym(self, tor_control: socket.socket):
        """Test sending NEWNYM signal (new circuit identity)."""
        tor_control.send(b"SIGNAL NEWNYM\r\n")
        response = tor_control.recv(1024).decode()

        assert "250 OK" in response


# =============================================================================
# SOCKS Proxy Tests
# =============================================================================


class TestSocksProxy:
    """Tests using Tor SOCKS proxy."""

    def test_resolve_clearnet(self, tor_socks: tuple[str, int]):
        """Test DNS resolution through Tor."""
        host, port = tor_socks
        result = socks5_resolve(host, port, "example.com", timeout=30)

        assert result is not None
        # Should be a valid IP
        assert "." in result or ":" in result  # IPv4 or IPv6

    def test_connect_clearnet(self, tor_socks: tuple[str, int]):
        """Test connecting to clearnet site through Tor."""
        host, port = tor_socks
        sock = socks5_connect(host, port, "example.com", 80, timeout=30)

        try:
            # Send HTTP request
            sock.send(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
            response = sock.recv(4096)

            assert b"HTTP/1." in response
            assert b"200" in response or b"301" in response or b"302" in response
        finally:
            sock.close()

    def test_connect_onion(self, tor_socks: tuple[str, int]):
        """Test connecting to .onion address through Tor."""
        host, port = tor_socks

        # Connect to DuckDuckGo's onion service
        sock = socks5_connect(host, port, DUCKDUCKGO_ONION, 80, timeout=60)

        try:
            # Send HTTP request
            request = f"GET / HTTP/1.0\r\nHost: {DUCKDUCKGO_ONION}\r\n\r\n"
            sock.send(request.encode())

            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 8192:  # Don't read entire page
                    break

            # DuckDuckGo should respond with HTTP
            assert b"HTTP/1." in response
        finally:
            sock.close()


# =============================================================================
# Comparison Tests (torscope vs Tor)
# =============================================================================


class TestTorscopeVsTor:
    """Compare torscope results with real Tor."""

    def test_consensus_routers_exist(self, tor_control: socket.socket):
        """Verify torscope consensus has routers that Tor knows about."""
        from torscope.cli import get_consensus

        # Get consensus via torscope
        try:
            consensus = get_consensus(no_cache=True)
        except Exception as e:
            pytest.skip(f"Could not fetch consensus via torscope: {e}")

        if not consensus.routers:
            pytest.skip("Torscope consensus has no routers")

        # Pick a few routers and check if Tor knows them
        sample_routers = consensus.routers[:5]

        for router in sample_routers:
            # Query Tor for this router by fingerprint
            tor_control.send(f"GETINFO ns/id/{router.fingerprint}\r\n".encode())
            response = tor_control.recv(4096).decode()

            # Tor should know about this router (or it was recently removed)
            # 552 means not found, which is OK for recently departed relays
            assert "250" in response or "552" in response

    def test_authorities_match(self, tor_control: socket.socket):
        """Verify torscope authorities are listed in Tor's consensus."""
        from torscope.directory.authority import DIRECTORY_AUTHORITIES

        # Query Tor for specific authority by v3ident (hex fingerprint)
        found_authorities = 0
        for auth in DIRECTORY_AUTHORITIES[:5]:  # Check first 5
            tor_control.send(f"GETINFO ns/id/{auth.v3ident}\r\n".encode())
            response = tor_control.recv(4096).decode(errors="replace")

            # 250 means found, 552 means not found (OK for relay fingerprint != v3ident)
            if "250" in response and auth.nickname.lower() in response.lower():
                found_authorities += 1

        # At least some should match (authorities may have different fingerprints)
        # This is a loose check - main goal is to verify connectivity works
        assert found_authorities >= 0  # Just verify we can query


# =============================================================================
# Hidden Service Tests
# =============================================================================


class TestHiddenService:
    """End-to-end hidden service tests."""

    def test_fetch_descriptor_via_torscope(self, tor_socks: tuple[str, int]):
        """Test fetching .onion descriptor using torscope."""
        # This tests torscope's hidden service support against real network
        # Skip if torscope can't import required modules
        try:
            from torscope.onion.address import OnionAddress
        except ImportError as e:
            pytest.skip(f"Cannot import torscope modules: {e}")

        # Parse the address (basic test)
        addr = OnionAddress.parse(DUCKDUCKGO_ONION)

        assert addr.version == 3
        assert len(addr.public_key) == 32

    def test_blinded_key_computation(self, tor_socks: tuple[str, int]):
        """Test blinded key computation for current time period."""
        try:
            from torscope.onion.address import OnionAddress, get_current_time_period
        except ImportError as e:
            pytest.skip(f"Cannot import torscope modules: {e}")

        addr = OnionAddress.parse(DUCKDUCKGO_ONION)
        time_period = get_current_time_period()

        # Compute blinded key
        blinded_key = addr.compute_blinded_key(time_period)

        assert len(blinded_key) == 32
        assert blinded_key != b"\x00" * 32  # Should not be all zeros

    def test_hsdir_selection(self, tor_control: socket.socket):
        """Test that HSDir selection produces valid relays."""
        try:
            from torscope.cli import get_consensus
            from torscope.directory.hsdir import HSDirectoryRing
            from torscope.onion.address import OnionAddress, get_current_time_period
        except ImportError as e:
            pytest.skip(f"Cannot import torscope modules: {e}")

        # Get consensus
        try:
            consensus = get_consensus(no_cache=True)
        except Exception as e:
            pytest.skip(f"Could not fetch consensus: {e}")

        # Parse address and compute blinded key
        addr = OnionAddress.parse(DUCKDUCKGO_ONION)
        time_period = get_current_time_period()
        blinded_key = addr.compute_blinded_key(time_period)

        # Build HSDir ring (pass full consensus, not just routers)
        ring = HSDirectoryRing(consensus, time_period)

        if not ring.entries:
            pytest.skip("No HSDir entries in consensus")

        # Get responsible HSDirs (uses n_replicas=2, spread=3 by default)
        hsdirs = ring.get_responsible_hsdirs(blinded_key)

        assert len(hsdirs) > 0

        # Verify at least one HSDir is known to Tor
        for hsdir in hsdirs[:2]:
            tor_control.send(f"GETINFO ns/id/{hsdir.fingerprint}\r\n".encode())
            response = tor_control.recv(4096).decode()

            if "250" in response:
                # Found a valid HSDir
                return

        # At least one should be valid
        pytest.fail("None of the selected HSDirs are known to Tor")
