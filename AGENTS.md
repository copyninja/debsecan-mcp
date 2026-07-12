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
