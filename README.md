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

For development:

```bash
pip install -e ".[dev]"
```

## Quick Start

```bash
# List all directory authorities
torscope authorities

# List fallback directories
torscope fallbacks

# List all relays
torscope relays

# List Guard relays only
torscope relays --flags Guard

# View details for a specific relay
torscope relay moria1

# View extra-info statistics for a relay
torscope extra-info moria1

# Test OR protocol connection to a relay
torscope connect moria1

# Create a circuit (ntor handshake) with a relay
torscope circuit moria1
```

## Commands

| Command | Description |
|---------|-------------|
| `version` | Display torscope version |
| `authorities` | List all 9 directory authorities |
| `fallbacks` | List fallback directories (~200) |
| `relays` | List relays from network consensus |
| `relay <name>` | Show detailed info for a specific relay |
| `extra-info <name>` | Show extra-info statistics for a relay |
| `connect <name>` | Test OR protocol connection (TLS + link handshake) |
| `circuit <name>` | Test circuit creation (ntor handshake) |

## Example Output

### Circuit Creation
```
$ torscope circuit moria1
Fetching descriptor for moria1...

Creating circuit to moria1 (128.31.0.39:9201)...
  TLS connection established
  Link protocol: v5
  Circuit ID: 0xbb985328
  ntor handshake successful!
  Circuit state: OPEN

  Derived keys:
    Kf: 3c639f2d33e08d19...
    Kb: 0cb35e627f489571...

  Circuit created successfully!
  Circuit destroyed
```

## Development

### Setup

1. Clone the repository
2. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

### Running Tests

```bash
pytest
```

With coverage:

```bash
pytest --cov=torscope --cov-report=html
```

### Code Formatting and Linting

Format code with Black:
```bash
black src tests
```

Lint with Ruff:
```bash
ruff check src tests
```

Type check with mypy:
```bash
mypy src
```

## Architecture

```
src/torscope/
├── cli.py                 # Command-line interface
├── cache.py               # Consensus caching
├── directory/             # Directory protocol
│   ├── authority.py       # Directory authorities
│   ├── fallback.py        # Fallback directories
│   ├── client.py          # HTTP client for fetching
│   ├── consensus.py       # Consensus parser
│   ├── descriptor.py      # Server descriptor parser
│   ├── extra_info.py      # Extra-info parser
│   └── models.py          # Data models
└── onion/                 # OR protocol
    ├── cell.py            # Cell format (VERSIONS, NETINFO, CREATE2, etc.)
    ├── connection.py      # TLS connection and link handshake
    ├── circuit.py         # Circuit management
    └── ntor.py            # ntor handshake (Curve25519)
```

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
