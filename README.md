# Overview

torscope is a tool for exploring the [Tor network](https://en.wikipedia.org/wiki/Tor_(network)).

It implements the Tor directory protocol and OR (Onion Router) protocol, allowing you to explore relay information, create circuits, and study the Tor specification in practice.

# Features

- **Directory Protocol**
  - List all Tor directory authorities and fallback directories
  - Fetch and parse network consensus documents
  - View detailed relay information and server descriptors
  - Fetch extra-info statistics for relays
  - Filter relays by flags (Guard, Exit, Fast, etc.)

- **OR Protocol**
  - Establish TLS connections to Tor relays
  - Perform link protocol handshake (VERSIONS, CERTS, AUTH_CHALLENGE, NETINFO)
  - Create circuits using the ntor handshake (Curve25519 key exchange)
  - Derive encryption keys for circuit communication

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
