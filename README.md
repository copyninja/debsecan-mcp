> [!WARNING]
> **This package has been renamed to [`debvulns`](https://pypi.org/project/debvulns/).**
> `debsecan-mcp 0.1.5` is the final release under this name. Please update your dependency:
> ```
> pip install debvulns
> ```

# debvulns

[![Tests](https://github.com/copyninja/debsecan-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/copyninja/debsecan-mcp/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/copyninja/debsecan-mcp/branch/main/graph/badge.svg)](https://codecov.io/gh/copyninja/debsecan-mcp)
[![Built with opencode](https://img.shields.io/badge/Built%20with-opencode-5B4BFF.svg)](https://opencode.ai)

Debian vulnerability analysis toolkit — MCP server, standalone CLI, and Prometheus exporter.
Integrates with AI assistants (like Claude) and monitoring stacks (Prometheus + Grafana) to
track, prioritize, and alert on package vulnerabilities across Debian systems.

> [!NOTE]
> This project was previously published on PyPI as `debsecan-mcp`. The final release under
> that name is `0.1.5`. All future development happens here as `debvulns`.

## Features

- **MCP Server** (`debvulns-mcp`): Integrates with Claude Desktop, VSCode, and opencode for
  AI-assisted vulnerability analysis
- **Standalone CLI** (`debvulns`): Scan and report vulnerabilities from the command line in
  JSON or CSV format
- **Prometheus Exporter** (`debvulns-exporter`): Expose vulnerability metrics for Grafana
  dashboards and alerting
- **List Vulnerabilities**: Scan all installed packages for known vulnerabilities
- **CVE Research**: Get detailed information about specific CVEs including EPSS scores
- **Automatic Suite Detection**: Automatically detects your Debian suite
  (bookworm, trixie, sid, etc.)
- **EPSS Integration**: Enriches vulnerability data with Exploit Prediction
  Scoring System (EPSS) scores

## Installation

```bash
pip install debvulns
```

Or from source:

```bash
pip install -e .
```

## Usage

### Standalone CLI Tool (`debvulns`)

The package includes a standalone CLI tool `debvulns` that allows you to scan for
vulnerabilities directly from the command line without running the MCP server.

On first run, `debvulns` downloads the vulnerabilities and EPSS data and caches them locally
(defaulting to `/var/cache/debvulns` or falling back to `~/.cache/debvulns` if the default
path is unwritable). The cache is refreshed automatically if it is older than 24 hours.

#### Running the CLI Tool

```bash
debvulns
```

#### Command Line Options

```bash
debvulns --help
```

Options:
- `-s, --severity {critical,high,medium,low,negligible}` - Filter vulnerabilities by severity.
  By default, lists all vulnerabilities grouped by severity.
- `-f, --format {json,csv}` - Output format (default: `json`).
- `--sort-by {package,cve}` - Sort vulnerabilities by package name or CVE ID.
- `--suite SUITE` - Debian suite name (e.g., `bookworm`, `sid`). Automatically detected by
  default.
- `--cache-dir PATH` - Directory to cache fetched and parsed data
  (default: `/var/cache/debvulns`).
- `--no-cache` - Do not use cached data, force downloading and parsing.
- `--vuln-url URL` - Custom URL or local path for Debian Security Tracker data.
- `--epss-url URL` - Custom URL or local path for EPSS scores data.
- `-v, --verbose` - Enable verbose debug logging (sent to stderr).

#### Examples

**Filter high severity vulnerabilities, sort by CVE, and output in CSV format:**
```bash
debvulns --severity high --sort-by cve --format csv
```

**Run for a specific suite without using cached data:**
```bash
debvulns --suite trixie --no-cache
```

---

### Prometheus Exporter (`debvulns-exporter`)

`debvulns-exporter` is a long-running HTTP server that exposes vulnerability metrics in the
[Prometheus exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/).
It runs a periodic background scan and serves the latest results on `/metrics` without
blocking the scrape.

#### Running the Exporter

```bash
debvulns-exporter
```

This starts the exporter on the default port **9222** and begins an initial vulnerability
scan. The `/metrics` endpoint returns `503` until the first scan completes.

#### Command Line Options

```bash
debvulns-exporter --help
```

Options:
- `--port PORT` - TCP port to expose `/metrics` on (default: `9222`).
- `--suite SUITE` - Debian suite codename (e.g. `bookworm`, `sid`). Auto-detected by default.
- `--refresh-interval SECS` - Seconds between full vulnerability scans
  (default: `86400` = 24 h, minimum: `3600` = 1 h).
- `--cache-dir DIR` - Directory for warm-start disk cache of downloaded data
  (default: `/var/cache/debvulns-exporter`).
- `--no-cache` - Disable disk caching; always re-download on every refresh.
- `--vuln-url URL` - Override the Debian Security Tracker vulnerability data URL.
- `--epss-url URL` - Override the EPSS CSV data URL.
- `-v, --verbose` - Enable debug-level logging to stderr.

#### Health Endpoints

| Path | Description |
|------|-------------|
| `/metrics` | Prometheus metrics (returns `503` until the first scan completes) |
| `/-/healthy` | Always returns `200 OK` — indicates the process is alive |
| `/-/ready` | Returns `200 Ready` once the first scan has succeeded, `503` otherwise |

#### Exposed Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `debvulns_exporter_info` | Info | `version`, `suite` | Exporter metadata |
| `debvulns_scan_status` | Gauge | — | `1` if the last scan succeeded, `0` otherwise |
| `debvulns_last_scan_timestamp_seconds` | Gauge | — | Unix epoch of the last scan |
| `debvulns_scan_duration_seconds` | Gauge | — | Duration of the last scan in seconds |
| `debvulns_installed_packages_count` | Gauge | — | Total installed Debian packages |
| `debvulns_vulnerabilities_total` | Gauge | `severity`, `fix_available`, `remote` | Aggregate vulnerability count |
| `debvulns_vulnerability_info` | Gauge | `cve`, `package`, `urgency`, `severity`, `fix_available`, `remote` | One series per active (CVE, package) pair |
| `debvulns_package_info` | Gauge | `package`, `installed_version` | Installed version of each vulnerable package |
| `debvulns_vulnerability_fix_info` | Gauge | `cve`, `package`, `fix_version` | Fix version for each (CVE, package) pair |
| `debvulns_vulnerability_epss_score` | Gauge | `cve`, `package` | EPSS probability score |
| `debvulns_vulnerability_epss_percentile` | Gauge | `cve`, `package` | EPSS percentile rank |

#### Running as a systemd Service

A ready-to-use systemd unit file is provided at
[`contrib/systemd/debvulns-exporter.service`](contrib/systemd/debvulns-exporter.service).

**Setup steps:**

1. Create a dedicated system user:
   ```bash
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin debvulns
   ```

2. Install the systemd unit:
   ```bash
   sudo cp contrib/systemd/debvulns-exporter.service /etc/systemd/system/
   sudo systemctl daemon-reload
   ```

3. Enable and start the service:
   ```bash
   sudo systemctl enable --now debvulns-exporter
   ```

4. Check service status and logs:
   ```bash
   sudo systemctl status debvulns-exporter
   sudo journalctl -u debvulns-exporter -f
   ```

The unit runs as the `debvulns` user, applies security hardening
(`ProtectSystem=strict`, `ProtectHome=true`, `NoNewPrivileges=true`), and writes its disk
cache to `/var/cache/debvulns-exporter`.

> [!NOTE]
> Because `ProtectHome=true` is set, the Python runtime and virtual environment must be
> installed outside `/home` (e.g. via `pip install debvulns` system-wide, or by setting
> `UV_PYTHON_INSTALL_DIR=/opt/app/python` when using `uv`).

#### Grafana Dashboard

A pre-built Grafana dashboard JSON is provided at
[`contrib/grafana/debvulns-dashboard.json`](contrib/grafana/debvulns-dashboard.json).

To import it:

1. In Grafana, go to **Dashboards → Import**.
2. Upload `contrib/grafana/debvulns-dashboard.json` or paste its contents.
3. Select your Prometheus data source and click **Import**.

The dashboard includes panels for:
- Total vulnerability counts by severity
- Scan health and last-scan timestamp
- Per-package vulnerability breakdown
- EPSS score distribution

---

### MCP Server (`debvulns-mcp`)

#### Running the MCP Server

```bash
debvulns-mcp
```

Or with a specific Debian suite:

```bash
DEBSECAN_SUITE=bookworm debvulns-mcp
```

#### Command Line Options

```bash
debvulns-mcp --help
```

Options:
- `--transport {stdio,sse,streamable-http}` - Transport mode (default: stdio)
- `--mount-path PATH` - Mount path for HTTP transports (default: /mcp)
- `--host HOST` - Host to bind to for HTTP transport (default: 0.0.0.0)
- `--port PORT` - Port to bind to for HTTP transport (default: 8000)

#### Transport Modes

##### STDIO Mode (Default)

Used for direct integration with AI assistants like Claude Desktop or VSCode.

```bash
debvulns-mcp --transport stdio
```

##### HTTP Modes

For HTTP-based access, use `sse` or `streamable-http`:

```bash
# SSE mode
debvulns-mcp --transport sse --port 8080 --mount-path /mcp

# Streamable HTTP mode
debvulns-mcp --transport streamable-http --port 8080 --mount-path /mcp
```

Note: HTTP modes require running behind a web server. See [HTTP Server Setup](#http-server-setup) below.

#### HTTP Server Setup

The HTTP transport modes need to be served by a WSGI/ASGI server. Example with uvicorn:

```bash
# Install uvicorn
pip install uvicorn

# Run with stdio transport and wrap with uvicorn
uvicorn debvulns.main:mcp_app --app-dir src --host 0.0.0.0 --port 8000 --path /mcp
```

Or use the built-in development server:

```bash
# SSE mode
debvulns-mcp --transport sse --host 0.0.0.0 --port 8000 --mount-path /mcp
```

#### Available MCP Tools

##### `list_vulnerabilities`

Lists all vulnerabilities affecting the currently installed packages on the
system. Categorises them by severity (critical, high, medium, low, negligible)
and EPSS score.

##### `research_cves`

Provides detailed information for a list of CVE IDs, including:
- Package name
- Urgency level
- EPSS score and percentile
- Whether a fix is available
- Remote exploitability
- Description

---

## Adding to VSCode

To use this MCP server with VSCode and AI assistants:

1. Open VSCode Settings (JSON):
   - On macOS: `Cmd + Shift + P` → "Preferences: Open Settings (JSON)"
   - On Linux/Windows: `Ctrl + Shift + P` → "Preferences: Open Settings (JSON)"

2. Add the MCP server configuration:

```json
{
  "mcpServers": {
    "debvulns": {
      "command": "debvulns-mcp",
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
    "debvulns": {
      "command": "debvulns-mcp",
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
debvulns-mcp --transport streamable-http --port 8080 --mount-path /mcp
```

2. Configure opencode to connect via HTTP:
```json
{
  "mcpServers": {
    "debvulns": {
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
