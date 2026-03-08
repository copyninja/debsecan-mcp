# debsecan-mcp

[![Tests](https://github.com/copyninja/debsecan-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/copyninja/debsecan-mcp/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/copyninja/debsecan-mcp/branch/main/graph/badge.svg)](https://codecov.io/gh/copyninja/debsecan-mcp)
[![Built with opencode](https://img.shields.io/badge/Built%20with-opencode-5B4BFF.svg)](https://opencode.ai)

A Model Context Protocol (MCP) server for Debian security vulnerability
analysis. This server integrates with AI assistants (like Claude) to provide
vulnerability scanning capabilities for Debian systems.

## Features

- **List Vulnerabilities**: Scan all installed packages on your Debian system
  for known vulnerabilities
- **CVE Research**: Get detailed information about specific CVEs including EPSS
  scores
- **Automatic Suite Detection**: Automatically detects your Debian suite
  (bookworm, trixie, sid, etc.)
- **EPSS Integration**: Enriches vulnerability data with Exploit Prediction
  Scoring System (EPSS) scores

## Installation

```bash
pip install -e .
```

## Usage

### Running the MCP Server

```bash
debsecan-mcp
```

Or with a specific Debian suite:

```bash
DEBSECAN_SUITE=bookworm debsecan-mcp
```

### Command Line Options

```bash
debsecan-mcp --help
```

Options:
- `--transport {stdio,sse,streamable-http}` - Transport mode (default: stdio)
- `--mount-path PATH` - Mount path for HTTP transports (default: /mcp)
- `--host HOST` - Host to bind to for HTTP transport (default: 0.0.0.0)
- `--port PORT` - Port to bind to for HTTP transport (default: 8000)

### Transport Modes

#### STDIO Mode (Default)

Used for direct integration with AI assistants like Claude Desktop or VSCode.

```bash
debsecan-mcp --transport stdio
```

#### HTTP Modes

For HTTP-based access, use `sse` or `streamable-http`:

```bash
# SSE mode
debsecan-mcp --transport sse --port 8080 --mount-path /mcp

# Streamable HTTP mode
debsecan-mcp --transport streamable-http --port 8080 --mount-path /mcp
```

Note: HTTP modes require running behind a web server. See [HTTP Server Setup](#http-server-setup) below.

### HTTP Server Setup

The HTTP transport modes need to be served by a WSGI/ASGI server. Example with uvicorn:

```bash
# Install uvicorn
pip install uvicorn

# Run with stdio transport and wrap with uvicorn
uvicorn debsecan_mcp.main:mcp_app --app-dir src --host 0.0.0.0 --port 8000 --path /mcp
```

Or use the built-in development server:

```bash
# SSE mode
debsecan-mcp --transport sse --host 0.0.0.0 --port 8000 --mount-path /mcp
```

### Available Tools

#### `list_vulnerabilities`

Lists all vulnerabilities affecting the currently installed packages on the
system. Categorises them by severity (critical, high, medium, low, negligible)
and EPSS score.

#### `research_cves`

Provides detailed information for a list of CVE IDs, including:
- Package name
- Urgency level
- EPSS score and percentile
- Whether a fix is available
- Remote exploitability
- Description

## Adding to VSCode

To use this MCP server with VSCode and AI assistants:

1. Open VSCode Settings (JSON):
   - On macOS: `Cmd + Shift + P` → "Preferences: Open Settings (JSON)"
   - On Linux/Windows: `Ctrl + Shift + P` → "Preferences: Open Settings (JSON)"

2. Add the MCP server configuration:

```json
{
  "mcpServers": {
    "debsecan": {
      "command": "debsecan-mcp",
      "args": [],
      "env": {
        "DEBSECAN_SUITE": "bookworm"
      }
    }
  }
}
```

3. Replace `bookworm` with your Debian suite codename (e.g., `trixie`, `sid`, `GENERIC`)

4. Restart VSCode or reload the window

## Adding to opencode

### Option 1: STDIO Mode (Default)

For local usage with opencode, use the default stdio transport:

```json
{
  "mcpServers": {
    "debsecan": {
      "command": "debsecan-mcp",
      "args": ["--transport", "stdio"],
      "env": {
        "DEBSECAN_SUITE": "bookworm"
      }
    }
  }
}
```

### Option 2: HTTP Mode

For remote or containerized setups, you can run the MCP server over HTTP:

1. Start the server:
```bash
debsecan-mcp --transport streamable-http --port 8080 --mount-path /mcp
```

2. Configure opencode to connect via HTTP:
```json
{
  "mcpServers": {
    "debsecan": {
      "url": "http://localhost:8080/mcp"
    }
  }
}
```

Note: HTTP mode requires the MCP client to support HTTP transport.


## How It Works

1. **Package Discovery**: Uses `python-apt` to enumerate all installed packages on the system
2. **Vulnerability Data**: Fetches compressed vulnerability data from the [Debian Security Tracker](https://security-tracker.debian.org/)
3. **EPSS Enrichment**: Downloads EPSS scores from [CISA](https://www.cisa.gov/epss) to prioritize vulnerabilities
4. **Analysis**: Compares installed package versions against vulnerability data using APT version comparison

## Requirements

- Python 3.11+
- Debian-based distribution (Debian, Ubuntu, etc.)
- Network access to download vulnerability data
