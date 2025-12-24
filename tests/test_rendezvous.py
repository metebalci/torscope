"""Tests for hidden service rendezvous protocol."""

import base64
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from torscope.directory.hs_descriptor import IntroductionPoint
from torscope.directory.models import ConsensusDocument, RouterStatusEntry
from torscope.onion.relay import RelayCell, RelayCommand, IntroduceAckStatus
from torscope.onion.rendezvous import (
    RendezvousError,
    RendezvousResult,
    build_circuit_to_router,
    complete_rendezvous,
    establish_rendezvous,
    get_router_ntor_key,
    rendezvous_connect,
    select_rendezvous_point,
    send_introduce,
)


# =============================================================================
# Test Helpers
# =============================================================================


def make_router(
    nickname: str,
    identity_hex: str,
    flags: list[str] | None = None,
    bandwidth: int = 1000000,
    ip: str = "192.0.2.1",
    orport: int = 9001,
    microdesc_hash: str | None = None,
    ed25519_identity: str | None = None,
) -> RouterStatusEntry:
    """Create a RouterStatusEntry for testing."""
    fp_bytes = bytes.fromhex(identity_hex)
    identity_b64 = base64.b64encode(fp_bytes).decode("ascii").rstrip("=")

    return RouterStatusEntry(
        nickname=nickname,
        identity=identity_b64,
        digest="AAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        published=datetime(2024, 1, 1, 0, 0, 0),
        ip=ip,
        orport=orport,
        dirport=9030,
        flags=flags or ["Fast", "Running", "Stable", "Valid"],
        bandwidth=bandwidth,
        microdesc_hash=microdesc_hash or f"hash_{identity_hex[:8]}",
        ed25519_identity=ed25519_identity,
    )


def make_consensus(routers: list[RouterStatusEntry]) -> MagicMock:
    """Create a mock ConsensusDocument."""
    mock = MagicMock(spec=ConsensusDocument)
    mock.routers = routers
    return mock


def make_intro_point(
    ip_address: str = "192.0.2.1",
    port: int = 9001,
    fingerprint: str = "AA" * 20,
    auth_key: bytes | None = None,
    enc_key: bytes | None = None,
    onion_key_ntor: bytes | None = None,
) -> IntroductionPoint:
    """Create an IntroductionPoint for testing."""
    link_specifiers = [
        (0, bytes([int(x) for x in ip_address.split(".")]) + port.to_bytes(2, "big")),
        (2, bytes.fromhex(fingerprint)),
    ]
    return IntroductionPoint(
        link_specifiers=link_specifiers,
        auth_key=auth_key or b"a" * 32,
        enc_key=enc_key or b"e" * 32,
        onion_key_ntor=onion_key_ntor or b"n" * 32,
    )


# =============================================================================
# Tests
# =============================================================================


class TestRendezvousResult:
    """Tests for RendezvousResult dataclass."""

    def test_create_result(self):
        """Test creating a RendezvousResult."""
        mock_circuit = MagicMock()
        mock_conn = MagicMock()

        result = RendezvousResult(circuit=mock_circuit, connection=mock_conn)

        assert result.circuit is mock_circuit
        assert result.connection is mock_conn


class TestRendezvousError:
    """Tests for RendezvousError exception."""

    def test_raise_error(self):
        """Test raising RendezvousError."""
        with pytest.raises(RendezvousError, match="test error"):
            raise RendezvousError("test error")

    def test_error_is_exception(self):
        """Test RendezvousError is an Exception."""
        error = RendezvousError("test")
        assert isinstance(error, Exception)


class TestSelectRendezvousPoint:
    """Tests for select_rendezvous_point()."""

    def test_selects_fast_stable_router(self):
        """Test selects router with Fast and Stable flags."""
        # Only one valid candidate so selection is deterministic
        routers = [
            make_router("fast_stable", "AA" * 20, ["Fast", "Stable", "Running"]),
            make_router("fast_only", "BB" * 20, ["Fast", "Running"]),
            make_router("stable_only", "CC" * 20, ["Stable", "Running"]),
        ]
        consensus = make_consensus(routers)

        result = select_rendezvous_point(consensus)

        # Only fast_stable has both flags
        assert result.nickname == "fast_stable"

    def test_excludes_authorities(self):
        """Test excludes directory authorities."""
        # Only one non-authority candidate
        routers = [
            make_router("authority", "AA" * 20, ["Fast", "Stable", "Authority"]),
            make_router("relay", "BB" * 20, ["Fast", "Stable", "Running"]),
        ]
        consensus = make_consensus(routers)

        result = select_rendezvous_point(consensus)

        # Authority should be excluded
        assert result.nickname == "relay"

    def test_raises_when_no_candidates(self):
        """Test raises when no suitable candidates."""
        routers = [
            make_router("slow", "AA" * 20, ["Running"]),  # No Fast/Stable
        ]
        consensus = make_consensus(routers)

        with pytest.raises(RendezvousError, match="No suitable rendezvous points"):
            select_rendezvous_point(consensus)

    def test_bandwidth_weighted_selection_returns_candidate(self):
        """Test selection returns a valid candidate (bandwidth-weighted)."""
        routers = [
            make_router("low_bw", "AA" * 20, ["Fast", "Stable"], bandwidth=100),
            make_router("high_bw", "BB" * 20, ["Fast", "Stable"], bandwidth=1000000),
        ]
        consensus = make_consensus(routers)

        # Run multiple times - should always return a valid router
        for _ in range(10):
            result = select_rendezvous_point(consensus)
            assert result.nickname in ["low_bw", "high_bw"]

    def test_zero_bandwidth_returns_candidate(self):
        """Test returns a valid candidate when all bandwidth is zero."""
        routers = [
            make_router("r1", "AA" * 20, ["Fast", "Stable"], bandwidth=0),
            make_router("r2", "BB" * 20, ["Fast", "Stable"], bandwidth=0),
        ]
        consensus = make_consensus(routers)

        result = select_rendezvous_point(consensus)

        assert result in routers


class TestGetRouterNtorKey:
    """Tests for get_router_ntor_key()."""

    def test_returns_ntor_key(self):
        """Test returns ntor key from microdesc."""
        router = make_router("test", "AA" * 20)
        expected_key = b"k" * 32

        with patch("torscope.onion.rendezvous.get_ntor_key") as mock:
            mock.return_value = (expected_key, "source", "type", False)

            result = get_router_ntor_key(router)

        assert result == expected_key

    def test_raises_when_no_key(self):
        """Test raises when ntor key unavailable."""
        router = make_router("test", "AA" * 20)

        with patch("torscope.onion.rendezvous.get_ntor_key") as mock:
            mock.return_value = None

            with pytest.raises(RendezvousError, match="Failed to get ntor key"):
                get_router_ntor_key(router)


class TestBuildCircuitToRouter:
    """Tests for build_circuit_to_router()."""

    def test_builds_circuit_successfully(self):
        """Test successful circuit building."""
        target = make_router("exit", "AA" * 20)
        guard = make_router("guard", "BB" * 20)
        middle = make_router("middle", "CC" * 20)
        routers = [guard, middle, target]
        consensus = make_consensus(routers)

        mock_conn = MagicMock()
        mock_conn.handshake.return_value = True
        mock_circuit = MagicMock()
        mock_circuit.extend_to.return_value = True

        with patch("torscope.onion.rendezvous.PathSelector") as mock_selector_class:
            mock_path = MagicMock()
            mock_path.routers = routers
            mock_selector_class.return_value.select_path.return_value = mock_path

            with patch("torscope.onion.rendezvous.get_router_ntor_key") as mock_ntor:
                mock_ntor.return_value = b"k" * 32

                with patch("torscope.onion.rendezvous.RelayConnection") as mock_conn_class:
                    mock_conn_class.return_value = mock_conn

                    with patch("torscope.onion.rendezvous.Circuit") as mock_circuit_class:
                        mock_circuit_class.create.return_value = mock_circuit

                        circuit, conn = build_circuit_to_router(consensus, target)

                        assert circuit is mock_circuit
                        assert conn is mock_conn

    def test_raises_on_path_selection_failure(self):
        """Test raises when path selection fails."""
        target = make_router("exit", "AA" * 20)
        consensus = make_consensus([target])

        with patch("torscope.onion.rendezvous.PathSelector") as mock_selector_class:
            mock_selector_class.return_value.select_path.side_effect = ValueError("No path")

            with pytest.raises(RendezvousError, match="Failed to select path"):
                build_circuit_to_router(consensus, target)

    def test_closes_connection_on_failure(self):
        """Test closes connection on circuit building failure."""
        target = make_router("exit", "AA" * 20)
        consensus = make_consensus([target])

        mock_conn = MagicMock()
        mock_conn.handshake.return_value = False  # Handshake fails

        with patch("torscope.onion.rendezvous.PathSelector") as mock_selector_class:
            mock_path = MagicMock()
            mock_path.routers = [target]
            mock_selector_class.return_value.select_path.return_value = mock_path

            with patch("torscope.onion.rendezvous.get_router_ntor_key") as mock_ntor:
                mock_ntor.return_value = b"k" * 32

                with patch("torscope.onion.rendezvous.RelayConnection") as mock_conn_class:
                    mock_conn_class.return_value = mock_conn

                    with pytest.raises(RendezvousError):
                        build_circuit_to_router(consensus, target)

                    mock_conn.close.assert_called_once()


class TestEstablishRendezvous:
    """Tests for establish_rendezvous()."""

    def test_successful_establishment(self):
        """Test successful rendezvous establishment."""
        mock_circuit = MagicMock()
        mock_response = MagicMock()
        mock_response.relay_command = RelayCommand.RENDEZVOUS_ESTABLISHED
        mock_circuit.recv_relay.return_value = mock_response

        with patch("torscope.onion.rendezvous.generate_rendezvous_cookie") as mock_cookie:
            mock_cookie.return_value = b"c" * 20

            cookie = establish_rendezvous(mock_circuit)

        assert cookie == b"c" * 20
        mock_circuit.send_relay.assert_called_once()

    def test_raises_on_no_response(self):
        """Test raises when no response received."""
        mock_circuit = MagicMock()
        mock_circuit.recv_relay.return_value = None

        with patch("torscope.onion.rendezvous.generate_rendezvous_cookie") as mock_cookie:
            mock_cookie.return_value = b"c" * 20

            with pytest.raises(RendezvousError, match="No response"):
                establish_rendezvous(mock_circuit)

    def test_raises_on_unexpected_response(self):
        """Test raises on unexpected command response."""
        mock_circuit = MagicMock()
        mock_response = MagicMock()
        # Use a real RelayCommand that has the .name attribute
        mock_response.relay_command = RelayCommand.END
        mock_circuit.recv_relay.return_value = mock_response

        with patch("torscope.onion.rendezvous.generate_rendezvous_cookie") as mock_cookie:
            mock_cookie.return_value = b"c" * 20

            with pytest.raises(RendezvousError, match="Unexpected response"):
                establish_rendezvous(mock_circuit)


class TestSendIntroduce:
    """Tests for send_introduce()."""

    def test_raises_on_missing_auth_key(self):
        """Test raises when intro point missing auth_key."""
        mock_circuit = MagicMock()
        intro_point = IntroductionPoint(
            link_specifiers=[],
            auth_key=None,  # Missing
            enc_key=b"e" * 32,
        )

        with pytest.raises(RendezvousError, match="missing auth_key"):
            send_introduce(
                circuit=mock_circuit,
                intro_point=intro_point,
                rendezvous_cookie=b"c" * 20,
                rendezvous_point=make_router("rp", "AA" * 20),
                rendezvous_ntor_key=b"n" * 32,
                subcredential=b"s" * 32,
            )

    def test_raises_on_missing_enc_key(self):
        """Test raises when intro point missing enc_key."""
        mock_circuit = MagicMock()
        intro_point = IntroductionPoint(
            link_specifiers=[],
            auth_key=b"a" * 32,
            enc_key=None,  # Missing
        )

        with pytest.raises(RendezvousError, match="missing enc_key"):
            send_introduce(
                circuit=mock_circuit,
                intro_point=intro_point,
                rendezvous_cookie=b"c" * 20,
                rendezvous_point=make_router("rp", "AA" * 20),
                rendezvous_ntor_key=b"n" * 32,
                subcredential=b"s" * 32,
            )

    def test_successful_introduce(self):
        """Test successful INTRODUCE1 sending."""
        mock_circuit = MagicMock()
        mock_response = MagicMock()
        mock_response.relay_command = RelayCommand.INTRODUCE_ACK
        mock_response.data = bytes([0, 0])  # SUCCESS status
        mock_circuit.recv_relay.return_value = mock_response

        intro_point = make_intro_point()
        rp = make_router("rp", "AA" * 20)

        with patch("torscope.onion.rendezvous.HsNtorClientState") as mock_ntor_class:
            mock_ntor = MagicMock()
            mock_ntor.client_pubkey = b"p" * 32
            mock_ntor.encrypt_introduce_data.return_value = b"encrypted"
            mock_ntor.compute_introduce_mac.return_value = b"m" * 32
            mock_ntor_class.create.return_value = mock_ntor

            with patch("torscope.onion.rendezvous.parse_introduce_ack") as mock_parse:
                mock_parse.return_value = (IntroduceAckStatus.SUCCESS, True)

                result = send_introduce(
                    circuit=mock_circuit,
                    intro_point=intro_point,
                    rendezvous_cookie=b"c" * 20,
                    rendezvous_point=rp,
                    rendezvous_ntor_key=b"n" * 32,
                    subcredential=b"s" * 32,
                )

                assert result is mock_ntor

    def test_raises_on_introduce_failure(self):
        """Test raises when INTRODUCE_ACK indicates failure."""
        mock_circuit = MagicMock()
        mock_response = MagicMock()
        mock_response.relay_command = RelayCommand.INTRODUCE_ACK
        mock_response.data = bytes([0, 2])  # BAD_MESSAGE_FORMAT
        mock_circuit.recv_relay.return_value = mock_response

        intro_point = make_intro_point()
        rp = make_router("rp", "AA" * 20)

        with patch("torscope.onion.rendezvous.HsNtorClientState") as mock_ntor_class:
            mock_ntor = MagicMock()
            mock_ntor.client_pubkey = b"p" * 32
            mock_ntor.encrypt_introduce_data.return_value = b"encrypted"
            mock_ntor.compute_introduce_mac.return_value = b"m" * 32
            mock_ntor_class.create.return_value = mock_ntor

            with patch("torscope.onion.rendezvous.parse_introduce_ack") as mock_parse:
                mock_parse.return_value = (IntroduceAckStatus.BAD_MESSAGE_FORMAT, False)

                with pytest.raises(RendezvousError, match="INTRODUCE_ACK failed"):
                    send_introduce(
                        circuit=mock_circuit,
                        intro_point=intro_point,
                        rendezvous_cookie=b"c" * 20,
                        rendezvous_point=rp,
                        rendezvous_ntor_key=b"n" * 32,
                        subcredential=b"s" * 32,
                    )


class TestCompleteRendezvous:
    """Tests for complete_rendezvous()."""

    def test_successful_completion(self):
        """Test successful rendezvous completion."""
        mock_circuit = MagicMock()
        mock_circuit.is_open = True
        mock_circuit._crypto_layers = []

        mock_response = MagicMock()
        mock_response.relay_command = RelayCommand.RENDEZVOUS2
        mock_response.data = b"x" * 64  # server_pk + auth
        mock_circuit.recv_relay.return_value = mock_response

        mock_ntor = MagicMock()
        mock_ntor.complete_rendezvous.return_value = b"k" * 128  # Key material

        with patch("torscope.onion.rendezvous.parse_rendezvous2") as mock_parse:
            mock_parse.return_value = (b"s" * 32, b"a" * 32)  # server_pk, auth

            with patch("torscope.onion.rendezvous.HsCircuitKeys") as mock_keys_class:
                mock_keys = MagicMock()
                mock_keys.key_forward = b"kf" * 16
                mock_keys.key_backward = b"kb" * 16
                mock_keys.digest_forward = b"df" * 16
                mock_keys.digest_backward = b"db" * 16
                mock_keys_class.from_key_material.return_value = mock_keys

                with patch("torscope.onion.rendezvous.RelayCrypto") as mock_crypto:
                    mock_crypto.create_hs.return_value = MagicMock()

                    complete_rendezvous(mock_circuit, mock_ntor)

                    # Verify crypto layer was added
                    assert len(mock_circuit._crypto_layers) == 1

    def test_raises_on_circuit_destroyed(self):
        """Test raises when circuit destroyed while waiting."""
        mock_circuit = MagicMock()
        mock_circuit.is_open = False
        mock_circuit.recv_relay.return_value = None

        mock_ntor = MagicMock()

        with pytest.raises(RendezvousError, match="destroyed"):
            complete_rendezvous(mock_circuit, mock_ntor, timeout=0.1)

    def test_raises_on_wrong_command(self):
        """Test raises on unexpected command."""
        mock_circuit = MagicMock()
        mock_circuit.is_open = True

        mock_response = MagicMock()
        # Use a real RelayCommand that has the .name attribute
        mock_response.relay_command = RelayCommand.END
        mock_circuit.recv_relay.return_value = mock_response

        mock_ntor = MagicMock()

        with pytest.raises(RendezvousError, match="Expected RENDEZVOUS2"):
            complete_rendezvous(mock_circuit, mock_ntor)

    def test_raises_on_handshake_failure(self):
        """Test raises when hs-ntor verification fails."""
        mock_circuit = MagicMock()
        mock_circuit.is_open = True

        mock_response = MagicMock()
        mock_response.relay_command = RelayCommand.RENDEZVOUS2
        mock_response.data = b"x" * 64
        mock_circuit.recv_relay.return_value = mock_response

        mock_ntor = MagicMock()
        mock_ntor.complete_rendezvous.return_value = None  # Verification failed

        with patch("torscope.onion.rendezvous.parse_rendezvous2") as mock_parse:
            mock_parse.return_value = (b"s" * 32, b"a" * 32)

            with pytest.raises(RendezvousError, match="handshake verification failed"):
                complete_rendezvous(mock_circuit, mock_ntor)


class TestRendezvousConnect:
    """Tests for rendezvous_connect()."""

    def test_raises_on_no_intro_points(self):
        """Test raises when no introduction points."""
        consensus = make_consensus([])
        onion_address = MagicMock()
        onion_address.address = "test" * 14 + ".onion"

        with pytest.raises(RendezvousError, match="No introduction points"):
            rendezvous_connect(
                consensus=consensus,
                onion_address=onion_address,
                introduction_points=[],
                subcredential=b"s" * 32,
            )

    def test_raises_on_rp_circuit_failure(self):
        """Test raises when RP circuit building fails repeatedly."""
        routers = [make_router("r1", "AA" * 20, ["Fast", "Stable"])]
        consensus = make_consensus(routers)
        onion_address = MagicMock()
        onion_address.address = "test" * 14 + ".onion"
        intro_points = [make_intro_point()]

        with patch("torscope.onion.rendezvous.select_rendezvous_point") as mock_select:
            mock_select.return_value = routers[0]

            with patch("torscope.onion.rendezvous.get_router_ntor_key") as mock_ntor:
                mock_ntor.side_effect = RendezvousError("No key")

                with pytest.raises(RendezvousError, match="Failed to build rendezvous circuit"):
                    rendezvous_connect(
                        consensus=consensus,
                        onion_address=onion_address,
                        introduction_points=intro_points,
                        subcredential=b"s" * 32,
                    )
