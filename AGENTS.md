# Agent Instructions for debsecan-mcp

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

- `src/debsecan_mcp/main.py` - Main MCP server with tools
- `src/debsecan_mcp/vulnerability.py` - Vulnerability data fetching and parsing
- `src/debsecan_mcp/package.py` - Package detection
- `src/debsecan_mcp/epss.py` - EPSS score fetching
- `tests/` - Test files
