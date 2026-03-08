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


## How It Works

1. **Package Discovery**: Uses `python-apt` to enumerate all installed packages on the system
2. **Vulnerability Data**: Fetches compressed vulnerability data from the [Debian Security Tracker](https://security-tracker.debian.org/)
3. **EPSS Enrichment**: Downloads EPSS scores from [CISA](https://www.cisa.gov/epss) to prioritize vulnerabilities
4. **Analysis**: Compares installed package versions against vulnerability data using APT version comparison

## Requirements

- Python 3.11+
- Debian-based distribution (Debian, Ubuntu, etc.)
- Network access to download vulnerability data
