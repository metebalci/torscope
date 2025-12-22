# Overview

torscope is a tool for exploring the [Tor network](https://en.wikipedia.org/wiki/Tor_(network)).

It implements the Tor directory protocol and OR (Onion Router) protocol, allowing you to explore relay information, create circuits, and study the Tor specification in practice.

# Features

## Implemented

### Directory Protocol
- List all Tor directory authorities and fallback directories
- Fetch and parse network consensus documents (v3)
- View detailed relay information and server descriptors
- Fetch extra-info descriptors (bandwidth history, statistics)
- Filter relays by flags (Guard, Exit, Fast, Stable, etc.)
- Microdescriptor fetching and parsing
- Exit policy matching and port filtering
- Consensus signature verification
- Consensus caching to disk (.torscope/ directory)
- Directory fetching over circuits (BEGIN_DIR)

### OR Protocol - Link Layer
- TLS connections to Tor relays (TLS 1.2+)
- Link protocol handshake (VERSIONS, CERTS, AUTH_CHALLENGE, NETINFO)
- Link protocol versions 4 and 5

### OR Protocol - Circuit Layer
- Circuit creation with CREATE2/CREATED2 (ntor handshake)
- One-hop circuits with CREATE_FAST/CREATED_FAST
- Circuit extension with RELAY_EXTEND2/EXTENDED2
- Multi-hop circuits (1-3 hops)
- Layered encryption/decryption (AES-128-CTR)
- Circuit padding negotiation (PADDING_NEGOTIATE/PADDING_NEGOTIATED)

### OR Protocol - Handshakes
- ntor handshake (Curve25519 + HMAC-SHA256)
- ntor-v3 handshake (Curve25519 + SHA3-256 + SHAKE-256)
- hs-ntor handshake for hidden services

### OR Protocol - Streams
- Stream creation (RELAY_BEGIN/CONNECTED)
- Data transfer (RELAY_DATA)
- Stream termination (RELAY_END)
- DNS resolution (RELAY_RESOLVE/RESOLVED)
- Directory streams (RELAY_BEGIN_DIR)

### Path Selection
- Bandwidth-weighted random selection
- Guard/middle/exit role assignment
- Family and subnet exclusion
- Port-based exit filtering

### Hidden Services (v3)
- Onion address parsing and validation
- Blinded key derivation (SHAKE-256)
- HSDir hashring selection
- Descriptor fetching from HSDir
- Outer descriptor parsing and signature verification

### Cryptography
- Curve25519 key exchange
- AES-128-CTR and AES-256-CTR encryption
- SHA-1, SHA-256, SHA3-256 hashing
- SHAKE-256 key derivation
- RSA and Ed25519 signature verification

## Not Implemented

### Protocol Features
- Flow control (SENDME cells) - not needed for small transfers
- XOFF/XON congestion control
- Conflux (multi-path circuits)
- AUTHENTICATE cell (relay authentication)
- Pluggable transports
- Bridge relay support

### Hidden Services
- Inner descriptor decryption (introduction point extraction)
- Full rendezvous protocol (INTRODUCE1, RENDEZVOUS2)
- Client authorization for private services
- Onion service publication (server-side)

### Other
- Running as a Tor relay
- Control protocol (stem-like interface)
- Connection pooling/reuse
- REST API

# Installation

```bash
pip install torscope
```

# Usage

## Example Onion Addresses

- torscope75efu4gls3m24xezterv7nhj36ibnjlrocqeslclwbxgs7yd.onion
- 2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion
- duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion
- dwnewsgngmhlplxy6o2twtfgjnrnjxbegbwqx6wnotdhkzt562tszfid.onion

# License

torscope Tor Network Exploration Tool

Copyright (C) 2025-2026 Mete Balci

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

# References

- [Tor Specification](https://spec.torproject.org/tor-spec/index.html)
- [Tor Directory Specification](https://spec.torproject.org/dir-spec/index.html)
