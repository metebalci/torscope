# Features

Detailed protocol support for torscope.

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
- VPADDING cells (variable-length link padding)

### OR Protocol - Circuit Layer
- Circuit creation with CREATE2/CREATED2 (ntor handshake)
- One-hop circuits with CREATE_FAST/CREATED_FAST
- Circuit extension with RELAY_EXTEND2/EXTENDED2 via RELAY_EARLY
- Multi-hop circuits (1-3 hops)
- Layered encryption/decryption (AES-128-CTR)
- Circuit teardown (DESTROY) with reason codes
- Circuit padding negotiation (PADDING_NEGOTIATE/PADDING_NEGOTIATED)
- DROP cells (long-range dummy traffic)

### OR Protocol - Handshakes
- ntor handshake (Curve25519 + HMAC-SHA256)
- ntor-v3 handshake (Curve25519 + SHA3-256 + SHAKE-256)
- hs-ntor handshake for hidden services

### OR Protocol - Streams
- Stream creation (RELAY_BEGIN/CONNECTED)
- BEGIN flags for IPv6 preferences (ipv6-ok, ipv4-not-ok, ipv6-preferred)
- Data transfer (RELAY_DATA)
- Stream termination (RELAY_END) with reason codes
- DNS resolution (RELAY_RESOLVE/RESOLVED)
- Directory streams (RELAY_BEGIN_DIR)
- Flow control (SENDME cells) with authenticated SENDME v1

### Path Selection
- Bandwidth-weighted random selection
- Guard/middle/exit role assignment
- Family and subnet exclusion
- Port-based exit filtering

### Bridge Relays
- Bridge line parsing (direct and pluggable transport formats)
- Direct bridge connections (no obfuscation)
- WebTunnel pluggable transport (HTTPS/WebSocket tunneling)
- obfs4 pluggable transport (traffic obfuscation with Elligator2)
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
- Proof-of-Work for hidden service DoS protection (Proposal 327, Equi-X)

### Cryptography
- Curve25519 key exchange
- AES-128-CTR and AES-256-CTR encryption
- SHA-1, SHA-256, SHA3-256 hashing
- SHAKE-256 key derivation
- RSA and Ed25519 signature verification

### REST API
- FastAPI-based HTTP server (`torscope serve`)
- Directory endpoints: authorities, fallbacks, routers, consensus
- Router details and extra-info descriptors
- Hidden service HSDir lookup
- GeoIP integration for router locations (MaxMind GeoLite2)

### WebSocket API
- Real-time circuit building events
- Step-by-step visualization (path selection, connection, hop creation)
- Automatic retry on connection failures

### Web Interface
- Circuit visualization on interactive world map (Leaflet.js)
- Color-coded circuit nodes (Client, Guard, Middle, Exit, Target)
- Router map with flag-based coloring (Guard, Exit, Guard+Exit, Middle)
- Directory server map (Authorities, Fallbacks, V2Dir Caches)
- HSDir visualization for .onion addresses

## Won't Implement

- Running as a Tor relay
- Control protocol (stem-like interface)
- Connection pooling/reuse
- Onion service publication (server-side)
- Pluggable transports: meek, Snowflake (require external dependencies like WebRTC/CDN)
- XOFF/XON congestion control (sender-side mechanism, not needed for receiving)
- RTT-based congestion control (Proposal 324, sender-side performance optimization)
- Conflux (multi-path circuits, performance optimization)
- AUTHENTICATE cell (relay-to-relay authentication, not needed for clients)
- TAP handshake (obsolete RSA-based CREATE/CREATED)
- Legacy EXTEND/EXTENDED (obsolete, using EXTEND2)
- AUTHORIZE cell (reserved, not needed for clients)
- TRUNCATE/TRUNCATED cells (circuit truncation, not useful for short-lived connections)
