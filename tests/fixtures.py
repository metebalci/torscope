"""
Test fixtures for torman tests.

This module contains sample data for testing consensus parsing,
router entries, and other directory protocol components.
"""

from datetime import datetime

# Sample minimal consensus document for testing
SAMPLE_CONSENSUS = """network-status-version 3
vote-status consensus
consensus-method 28
valid-after 2024-01-15 12:00:00
fresh-until 2024-01-15 13:00:00
valid-until 2024-01-15 15:00:00
voting-delay 300 300
client-versions 0.4.7.13,0.4.7.14,0.4.8.1
server-versions 0.4.7.13,0.4.7.14,0.4.8.1
known-flags Authority Exit Fast Guard HSDir Running Stable V2Dir Valid
params circwindow=1000 refuseunknownexits=1
dir-source moria1 D586D18309DED4CD6D57C18FDB97EFA96D330566 128.31.0.34 128.31.0.34 9131 9101
r Test1 AAAAAAAAAAAAAAAAAAAAAAAAAAAA 2024-01-15 10:00:00 192.0.2.1 9001 9030
s Exit Fast Running Stable Valid
w Bandwidth=5000
r Test2 BBBBBBBBBBBBBBBBBBBBBBBBBBBB 2024-01-15 10:05:00 192.0.2.2 9001 0
a [2001:db8::1]:9001
s Guard Fast Running Stable Valid
v Tor 0.4.8.1
pr Link=1-5 Cons=1-2
w Bandwidth=10000 Measured=9500
p accept 80,443
m sha256=dGVzdA==
bandwidth-weights Wbd=285 Wbe=0 Wbg=0 Wbm=10000
directory-signature sha256 D586D18309DED4CD6D57C18FDB97EFA96D330566 0123456789ABCDEF
-----BEGIN SIGNATURE-----
dGVzdHNpZ25hdHVyZQ==
-----END SIGNATURE-----
"""

# Sample router entry (r line format)
SAMPLE_ROUTER_LINE = (
    "r TestRelay AAAAAAAAAAAAAAAAAAAAAAAAAAAA BBBBBBBBBBBBBBBBBBBBBBBBBBBB "
    "2024-01-15 10:00:00 192.0.2.100 9001 9030"
)

# Sample authority entry (dir-source line format)
SAMPLE_AUTHORITY_LINE = (
    "dir-source moria1 D586D18309DED4CD6D57C18FDB97EFA96D330566 "
    "128.31.0.34 128.31.0.34 9131 9101"
)

# Expected parsed values from SAMPLE_CONSENSUS
EXPECTED_CONSENSUS_VALUES = {
    "version": 3,
    "vote_status": "consensus",
    "consensus_method": 28,
    "valid_after": datetime(2024, 1, 15, 12, 0, 0),
    "fresh_until": datetime(2024, 1, 15, 13, 0, 0),
    "valid_until": datetime(2024, 1, 15, 15, 0, 0),
    "voting_delay": (300, 300),
    "client_versions": ["0.4.7.13", "0.4.7.14", "0.4.8.1"],
    "server_versions": ["0.4.7.13", "0.4.7.14", "0.4.8.1"],
    "known_flags": [
        "Authority",
        "Exit",
        "Fast",
        "Guard",
        "HSDir",
        "Running",
        "Stable",
        "V2Dir",
        "Valid",
    ],
    "params": {"circwindow": 1000, "refuseunknownexits": 1},
    "num_authorities": 1,
    "num_routers": 2,
    "num_signatures": 1,
}

# Expected router entries from SAMPLE_CONSENSUS
EXPECTED_ROUTER_1 = {
    "nickname": "Test1",
    "identity": "AAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "ip": "192.0.2.1",
    "orport": 9001,
    "dirport": 9030,
    "flags": ["Exit", "Fast", "Running", "Stable", "Valid"],
    "bandwidth": 5000,
}

EXPECTED_ROUTER_2 = {
    "nickname": "Test2",
    "identity": "BBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    "digest": "BBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    "ip": "192.0.2.2",
    "orport": 9001,
    "dirport": 0,
    "ipv6_addresses": ["[2001:db8::1]:9001"],
    "flags": ["Guard", "Fast", "Running", "Stable", "Valid"],
    "version": "Tor 0.4.8.1",
    "protocols": {"Link": [1, 2, 3, 4, 5], "Cons": [1, 2]},
    "bandwidth": 10000,
    "measured": 9500,
    "exit_policy": "accept 80,443",
    "microdesc_hash": "sha256=dGVzdA==",
}

# Protocol parsing test cases
PROTOCOL_TEST_CASES = [
    ("Link=1-5", {"Link": [1, 2, 3, 4, 5]}),
    ("Link=1-3 Cons=1-2", {"Link": [1, 2, 3], "Cons": [1, 2]}),
    ("Link=1,3,5", {"Link": [1, 3, 5]}),
    ("Link=1-2,5-6", {"Link": [1, 2, 5, 6]}),
    ("HSDir=2 HSIntro=4-5", {"HSDir": [2], "HSIntro": [4, 5]}),
]

# Datetime parsing test cases
DATETIME_TEST_CASES = [
    ("2024-01-15 12:00:00", datetime(2024, 1, 15, 12, 0, 0)),
    ("2023-12-31 23:59:59", datetime(2023, 12, 31, 23, 59, 59)),
    ("2024-06-01 00:00:00", datetime(2024, 6, 1, 0, 0, 0)),
]
