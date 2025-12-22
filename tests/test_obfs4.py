"""Tests for obfs4 pluggable transport implementation."""

import base64
import os

import pytest

from torscope.directory.bridge import parse_bridge_line
from torscope.onion.obfs4 import HandshakeError, Obfs4ServerCert, Obfs4Transport
from torscope.onion.obfs4.elligator import (
    elligator2_decode,
    elligator2_encode,
    generate_encodable_keypair,
)
from torscope.onion.obfs4.framing import FrameReader, Obfs4Framing, TYPE_PAYLOAD


class TestElligator2:
    """Tests for Elligator2 encoding/decoding."""

    def test_encode_decode_roundtrip(self) -> None:
        """Verify encode/decode roundtrip for encodable keys."""
        # Generate an encodable keypair
        _priv, pub, rep = generate_encodable_keypair()

        # Verify decode gives back the public key
        decoded = elligator2_decode(rep)
        assert decoded == pub

    def test_encode_returns_none_for_non_encodable(self) -> None:
        """Verify encode returns None for some keys (expected ~50% non-encodable)."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        non_encodable_count = 0
        trials = 20

        for _ in range(trials):
            pk = X25519PrivateKey.generate()
            pub = pk.public_key().public_bytes_raw()
            rep = elligator2_encode(pub)
            if rep is None:
                non_encodable_count += 1

        # Should have some non-encodable keys (between 20% and 80% expected)
        assert non_encodable_count > 0, "Expected some non-encodable keys"
        assert non_encodable_count < trials, "Expected some encodable keys"

    def test_decode_validates_length(self) -> None:
        """Verify decode validates input length."""
        with pytest.raises(ValueError, match="32 bytes"):
            elligator2_decode(b"short")

    def test_encode_validates_length(self) -> None:
        """Verify encode validates input length."""
        with pytest.raises(ValueError, match="32 bytes"):
            elligator2_encode(b"short")

    def test_multiple_roundtrips(self) -> None:
        """Verify multiple roundtrips work correctly."""
        for _ in range(5):
            _priv, pub, rep = generate_encodable_keypair()
            decoded = elligator2_decode(rep)
            assert decoded == pub


class TestObfs4ServerCert:
    """Tests for obfs4 server certificate parsing."""

    def test_parse_valid_cert(self) -> None:
        """Parse a valid certificate."""
        # Create a valid 52-byte cert (20 node_id + 32 public_key)
        node_id = b"A" * 20
        public_key = b"B" * 32
        raw = node_id + public_key
        cert_b64 = base64.b64encode(raw).decode().rstrip("=")

        cert = Obfs4ServerCert.from_string(cert_b64)
        assert cert.node_id == node_id
        assert cert.public_key == public_key

    def test_parse_invalid_length(self) -> None:
        """Reject certificate with wrong length."""
        # Only 32 bytes instead of 52
        raw = b"A" * 32
        cert_b64 = base64.b64encode(raw).decode().rstrip("=")

        with pytest.raises(HandshakeError, match="Invalid cert length"):
            Obfs4ServerCert.from_string(cert_b64)

    def test_parse_invalid_base64(self) -> None:
        """Reject invalid base64."""
        with pytest.raises(HandshakeError, match="Invalid cert base64"):
            Obfs4ServerCert.from_string("not!valid!base64!!!")

    def test_parse_with_padding(self) -> None:
        """Parse certificate with various padding scenarios."""
        node_id = os.urandom(20)
        public_key = os.urandom(32)
        raw = node_id + public_key

        # Standard base64 with padding
        cert_with_padding = base64.b64encode(raw).decode()
        cert1 = Obfs4ServerCert.from_string(cert_with_padding)
        assert cert1.node_id == node_id
        assert cert1.public_key == public_key

        # Without padding (common in obfs4 bridge lines)
        cert_no_padding = cert_with_padding.rstrip("=")
        cert2 = Obfs4ServerCert.from_string(cert_no_padding)
        assert cert2.node_id == node_id
        assert cert2.public_key == public_key


class TestObfs4Framing:
    """Tests for obfs4 frame encryption/decryption."""

    def create_test_framing(self) -> Obfs4Framing:
        """Create framing instance with test keys."""
        # 144 bytes of key material
        key_material = os.urandom(144)
        return Obfs4Framing.from_key_material(key_material, is_client=True)

    def test_encrypt_decrypt_roundtrip(self) -> None:
        """Verify encrypt/decrypt roundtrip."""
        key_material = os.urandom(144)

        # Create client and server framing
        client = Obfs4Framing.from_key_material(key_material, is_client=True)
        server = Obfs4Framing.from_key_material(key_material, is_client=False)

        # Client encrypts, server decrypts
        payload = b"Hello, obfs4!"
        frame = client.encrypt_frame(payload)

        frame_type, decrypted, consumed = server.decrypt_frame(frame)
        assert frame_type == TYPE_PAYLOAD
        assert decrypted == payload
        assert consumed == len(frame)

    def test_encrypt_with_padding(self) -> None:
        """Verify encryption with padding."""
        framing = self.create_test_framing()
        payload = b"test"
        frame = framing.encrypt_frame(payload, pad_length=100)

        # Frame should be larger due to padding
        assert len(frame) > len(payload) + 100

    def test_multiple_frames(self) -> None:
        """Verify multiple frames encrypt/decrypt correctly."""
        key_material = os.urandom(144)
        client = Obfs4Framing.from_key_material(key_material, is_client=True)
        server = Obfs4Framing.from_key_material(key_material, is_client=False)

        payloads = [b"first", b"second", b"third"]

        for payload in payloads:
            frame = client.encrypt_frame(payload)
            frame_type, decrypted, _ = server.decrypt_frame(frame)
            assert decrypted == payload


class TestFrameReader:
    """Tests for buffered frame reading."""

    def test_read_complete_frame(self) -> None:
        """Read a complete frame from buffer."""
        key_material = os.urandom(144)
        client = Obfs4Framing.from_key_material(key_material, is_client=True)
        server = Obfs4Framing.from_key_material(key_material, is_client=False)

        reader = FrameReader(server)

        frame = client.encrypt_frame(b"test payload")
        reader.feed(frame)

        result = reader.read_frame()
        assert result is not None
        frame_type, payload = result
        assert payload == b"test payload"

    def test_partial_frame(self) -> None:
        """Handle partial frame (incomplete data)."""
        key_material = os.urandom(144)
        client = Obfs4Framing.from_key_material(key_material, is_client=True)
        server = Obfs4Framing.from_key_material(key_material, is_client=False)

        reader = FrameReader(server)

        frame = client.encrypt_frame(b"test")
        # Feed only part of the frame
        reader.feed(frame[:10])

        result = reader.read_frame()
        assert result is None

        # Feed the rest
        reader.feed(frame[10:])
        result = reader.read_frame()
        assert result is not None
        _, payload = result
        assert payload == b"test"


class TestBridgeParsing:
    """Tests for obfs4 bridge line parsing."""

    def test_parse_obfs4_bridge(self) -> None:
        """Parse an obfs4 bridge line."""
        # Create a valid cert
        raw_cert = os.urandom(52)
        cert_b64 = base64.b64encode(raw_cert).decode().rstrip("=")

        line = f"obfs4 192.0.2.1:443 4352E58420E68F5E40BF7C74FADDCCD9D1349413 cert={cert_b64} iat-mode=0"
        bridge = parse_bridge_line(line)

        assert bridge.transport == "obfs4"
        assert bridge.ip == "192.0.2.1"
        assert bridge.port == 443
        assert bridge.transport_params["cert"] == cert_b64
        assert bridge.transport_params["iat-mode"] == "0"

    def test_parse_obfs4_without_iat_mode(self) -> None:
        """Parse obfs4 bridge line without iat-mode."""
        raw_cert = os.urandom(52)
        cert_b64 = base64.b64encode(raw_cert).decode().rstrip("=")

        line = f"obfs4 192.0.2.1:443 4352E58420E68F5E40BF7C74FADDCCD9D1349413 cert={cert_b64}"
        bridge = parse_bridge_line(line)

        assert bridge.transport == "obfs4"
        assert bridge.transport_params["cert"] == cert_b64
        assert "iat-mode" not in bridge.transport_params


class TestObfs4Transport:
    """Tests for Obfs4Transport class."""

    def test_transport_creation(self) -> None:
        """Create an Obfs4Transport instance."""
        raw_cert = os.urandom(52)
        cert_b64 = base64.b64encode(raw_cert).decode().rstrip("=")

        transport = Obfs4Transport(
            host="192.0.2.1",
            port=443,
            cert=cert_b64,
            iat_mode=0,
            timeout=30.0,
        )

        assert transport.host == "192.0.2.1"
        assert transport.port == 443
        assert transport.cert == cert_b64
        assert transport.iat_mode == 0

    def test_transport_invalid_cert(self) -> None:
        """Transport with invalid cert fails on connect."""
        transport = Obfs4Transport(
            host="192.0.2.1",
            port=443,
            cert="invalid",
            iat_mode=0,
        )

        # This should fail when trying to parse the cert
        from torscope.onion.transport import TransportError

        with pytest.raises(TransportError, match="Invalid obfs4 cert"):
            transport.connect()
