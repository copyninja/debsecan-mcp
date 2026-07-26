# Agent Instructions for debvulns

## Project Overview

This is a Python MCP server for Debian security vulnerability analysis.

## Running Tests

```bash
# Run all tests with tox
uv run tox

# Run specific test file
uv run tox -- -k test_main

# Run specific test by name
uv run tox -- -k "test_list_vulnerabilities"

# Run with coverage (via tox)
uv run tox
```

## Code Quality

```bash
# Run linting
uv run tox -e lint

# Format code
uv run tox -e format

# Run type checking
uv run tox -e typing
```

## Building

```bash
uv build
```

## Key Files

- `src/debvulns/main.py` - Main MCP server with tools
- `src/debvulns/vulnerability.py` - Vulnerability data fetching and parsing
- `src/debvulns/package.py` - Package detection
- `src/debvulns/epss.py` - EPSS score fetching
- `tests/` - Test files

## Dev Environment Setup

The project requires `python3-apt` (provides `apt_pkg`) to correctly classify
packages by origin (Debian vs third-party). uv uses its own managed Python
whose site-packages do not include `/usr/lib/python3/dist-packages/` where
`apt_pkg` lives.

**After cloning or recreating the venv**, run:

```bash
bash setup-dev-venv.sh
```

This script creates the venv with system-site-packages access, patches
`pyvenv.cfg`, and adds a `.pth` file fallback so `apt_pkg` is always importable.

Without this step the non-Debian origin detection falls back to dpkg-query and
all packages default to `is_debian_origin = True` (third-party packages like
Grafana are not filtered from the Debian Security Tracker scan).

> **Note**: `uv run tox` does NOT require this — tests mock `apt_pkg`.
