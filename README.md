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

### Bridge Relays
- Bridge line parsing (direct and pluggable transport formats)
- Direct bridge connections (no obfuscation)
- WebTunnel pluggable transport (HTTPS/WebSocket tunneling)
- Circuit building through bridges with CREATE_FAST

### Hidden Services (v3)
- Onion address parsing and validation
- Blinded key derivation (SHAKE-256)
- HSDir hashring selection
- Descriptor fetching from HSDir
- Outer descriptor parsing and signature verification
- Inner descriptor decryption (introduction point extraction)
- Client authorization for private services (x25519 auth keys)
- Full rendezvous protocol (ESTABLISH_RENDEZVOUS, INTRODUCE1, RENDEZVOUS2)
- hs-ntor handshake (Curve25519 + SHA3-256 + SHAKE-256)

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
- Pluggable transports: obfs4, Snowflake (WebTunnel is supported)

### Other
- REST API

## Won't Implement

- Running as a Tor relay
- Control protocol (stem-like interface)
- Connection pooling/reuse
- Onion service publication (server-side)

# Installation

```bash
pip install torscope
```

# Usage

```bash
# List directory authorities
torscope authorities

# List routers with specific flags
torscope routers --flags Guard,Exit

# Show router details
torscope router moria1

# Build a 3-hop circuit
torscope circuit

# Resolve hostname through Tor
torscope resolve example.com

# Connect to a website through Tor
torscope open-stream example.com:80 --http-get

# Access a hidden service
torscope hidden-service duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion

# Connect to a hidden service
torscope open-stream duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:80 --http-get

# Access a private hidden service with client authorization
torscope hidden-service private.onion --auth-key-file ~/.tor/onion_auth/private.auth_private
torscope open-stream private.onion:80 --auth-key-file ~/.tor/onion_auth/private.auth_private

# Build circuit through a direct bridge (no transport)
torscope circuit --bridge "192.0.2.1:443 4352E58420E68F5E40BF7C74FADDCCD9D1349413"

# Build circuit through a WebTunnel bridge
torscope circuit --bridge "webtunnel 192.0.2.1:443 FINGERPRINT url=https://example.com/secret-path"

# Open stream through a bridge
torscope open-stream example.com:80 --bridge "192.0.2.1:443 FINGERPRINT" --http-get
```

## Verbosity Flags

```bash
-e, --explain   # Brief explanations of what's happening
-v              # Protocol-level information
-vv             # Raw debug information (implies -v)
```

## Example Onion Addresses

- duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion
- 2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion
- torscope75efu4gls3m24xezterv7nhj36ibnjlrocqeslclwbxgs7yd.onion

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
