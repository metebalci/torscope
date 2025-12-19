# torscope

A tool for exploring and getting information about the Tor network.

## Overview

`torscope` is a Python command-line tool for fetching and analyzing information about the Tor network. It allows you to explore the Tor directory protocol, view relay information, and study the Tor specification in practice.

## Features

- List all Tor directory authorities
- Fetch and parse network consensus documents
- View detailed relay information
- Filter relays by flags (Guard, Exit, Fast, etc.)
- Explore the Tor network directory protocol

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
torscope -c authorities

# Fetch network consensus
torscope -c fetch_consensus

# List Guard relays
torscope -c "list_relays --flags Guard --limit 20"

# Interactive mode
torscope
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
