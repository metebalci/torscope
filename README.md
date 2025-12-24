> **Note:** This project was written by [Claude](https://claude.ai), an AI assistant by Anthropic, under human guidance using [Claude Code](https://claude.ai/code).

# Overview

torscope is a tool for exploring the [Tor network](https://en.wikipedia.org/wiki/Tor_(network)).

It implements the Tor directory protocol and OR (Onion Router) protocol, allowing you to explore relay information, create circuits, and study the Tor specification in practice.

# Features

- Explore Tor directory (authorities, relays, consensus)
- Build circuits through the network (1-3 hops)
- Connect to clearnet and .onion sites
- Bridge support (direct, WebTunnel, obfs4)
- Hidden service access with client authorization
- DNS resolution through Tor
- Web interface with real-time circuit visualization on a world map
- REST API for programmatic access

See [FEATURES.md](FEATURES.md) for detailed protocol support.

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

# Connect with IPv6 preferences
torscope open-stream example.com:80 --http-get --ipv6-ok --ipv6-preferred

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

# Build circuit through an obfs4 bridge
torscope circuit --bridge "obfs4 192.0.2.1:443 FINGERPRINT cert=ABC...xyz iat-mode=0"

# Open stream through a bridge
torscope open-stream example.com:80 --bridge "192.0.2.1:443 FINGERPRINT" --http-get

# Open stream through an obfs4 bridge
torscope open-stream example.com:80 --bridge "obfs4 192.0.2.1:443 FINGERPRINT cert=... iat-mode=0" --http-get
```

## Web Interface

Start the web server to visualize circuits on a map:

```bash
# Start the API server
torscope serve

# Start on a specific port
torscope serve --port 3000

# Bind to localhost only
torscope serve --host 127.0.0.1

# With GeoIP database for router locations
torscope serve --geoip-db /path/to/GeoLite2-City.mmdb
```

Then open http://localhost:8000 in your browser. The web interface allows you to:

- Build circuits and visualize the path on a world map
- View all Tor routers with color-coded markers (Guard, Exit, Middle)
- View directory servers (Authorities, Fallbacks, Caches)
- See responsible HSDirs when connecting to .onion addresses

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
