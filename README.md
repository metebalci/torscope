# torscope

A tool for exploring and getting information about the Tor network.

## Overview

`torscope` is a Python command-line tool for fetching and analyzing information about the Tor network. It implements the Tor directory protocol and OR (Onion Router) protocol, allowing you to explore relay information, create circuits, and study the Tor specification in practice.

## Features

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

## Installation

```bash
pip install torscope
```

## Usage



## License

torscope Tor Network Information Tool

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

## References

- [Tor Specification](https://spec.torproject.org/tor-spec/index.html)
- [Tor Directory Specification](https://spec.torproject.org/dir-spec/index.html)
- [ntor Handshake (Proposal 216)](https://spec.torproject.org/proposals/216-ntor-handshake.html)
