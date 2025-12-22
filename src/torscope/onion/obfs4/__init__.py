"""
obfs4 pluggable transport implementation.

obfs4 is a traffic obfuscation protocol that makes Tor traffic
indistinguishable from random data, helping bypass censorship.

Usage:
    from torscope.onion.obfs4 import Obfs4Transport

    transport = Obfs4Transport(
        host="192.0.2.1",
        port=443,
        cert="AbCdEf...",
        iat_mode=0,
    )
    tls_socket = transport.connect()
"""

from torscope.onion.obfs4.handshake import HandshakeError, Obfs4ServerCert
from torscope.onion.obfs4.transport import Obfs4Transport

__all__ = [
    "Obfs4Transport",
    "Obfs4ServerCert",
    "HandshakeError",
]
