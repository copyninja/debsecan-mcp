"""HTTP server and Prometheus metric definitions for the debvulns exporter.

Metric registration
-------------------
All Gauge / Info objects are created once at module level (using a
dedicated CollectorRegistry to avoid polluting the default global one).

Scrape path
-----------
On each GET /metrics request the handler:
  1. Reads the latest ScanResult from the Cache (zero I/O).
  2. Clears all labelled gauges to drop stale series.
  3. Repopulates every metric from the snapshot.
  4. Streams the text exposition.

If the cache is empty (first scan not yet done) the handler returns 503
for /metrics and /-/ready; /-/healthy always returns 200.
"""

from __future__ import annotations

import http.server
import importlib.metadata
import logging
import socketserver
import threading
from typing import Any

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Gauge,
    Info,
    generate_latest,
)

from .cache import Cache, ScanResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_version() -> str:
    try:
        return importlib.metadata.version("debsecan-mcp")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _remote_label(remote: bool | None) -> str:
    if remote is True:
        return "true"
    if remote is False:
        return "false"
    return "unknown"


def _bool_label(value: bool) -> str:
    return "true" if value else "false"


def _fix_version(v: Any) -> str:
    """Return the fix version string, or empty string if unavailable."""
    if v.unstable_version:
        return str(v.unstable_version)
    if v.other_versions:
        return str(v.other_versions[0])
    return ""


# ---------------------------------------------------------------------------
# Metric registry (isolated — not the default prometheus_client registry)
# ---------------------------------------------------------------------------

REGISTRY = CollectorRegistry()

# Static / health metrics
_EXPORTER_INFO = Info(
    "debvulns_exporter",
    "Metadata about the exporter configuration.",
    registry=REGISTRY,
)
_SCAN_STATUS = Gauge(
    "debvulns_scan_status",
    "1 if the last vulnerability scan completed successfully, 0 otherwise.",
    registry=REGISTRY,
)
_LAST_SCAN_TS = Gauge(
    "debvulns_last_scan_timestamp_seconds",
    "Unix epoch timestamp of when the last scan was executed.",
    registry=REGISTRY,
)
_SCAN_DURATION = Gauge(
    "debvulns_scan_duration_seconds",
    "Duration of the last vulnerability scan in seconds.",
    registry=REGISTRY,
)
_PKG_COUNT = Gauge(
    "debvulns_installed_packages_count",
    "Total number of Debian packages currently installed on the host.",
    registry=REGISTRY,
)

# Aggregated metrics
_VULNS_TOTAL = Gauge(
    "debvulns_vulnerabilities_total",
    "Aggregate count of vulnerabilities currently affecting the system.",
    ["severity", "fix_available", "remote"],
    registry=REGISTRY,
)

# Per-(cve, package) metrics
_VULN_INFO = Gauge(
    "debvulns_vulnerability_info",
    "Core fact metric — one series per active (cve, package) pair.",
    ["cve", "package", "urgency", "severity", "fix_available", "remote"],
    registry=REGISTRY,
)
_PKG_INFO = Gauge(
    "debvulns_package_info",
    "Installed version for each vulnerable package (one series per package).",
    ["package", "installed_version"],
    registry=REGISTRY,
)
_FIX_INFO = Gauge(
    "debvulns_vulnerability_fix_info",
    "Fix version for each active (cve, package) pair.",
    ["cve", "package", "fix_version"],
    registry=REGISTRY,
)
_EPSS_SCORE = Gauge(
    "debvulns_vulnerability_epss_score",
    "The EPSS probability score for the detected vulnerability.",
    ["cve", "package"],
    registry=REGISTRY,
)
_EPSS_PERCENTILE = Gauge(
    "debvulns_vulnerability_epss_percentile",
    "The EPSS percentile rank of the detected vulnerability.",
    ["cve", "package"],
    registry=REGISTRY,
)


# ---------------------------------------------------------------------------
# Metric population
# ---------------------------------------------------------------------------

def _update_metrics(result: ScanResult, suite: str) -> None:
    """Repopulate all Prometheus metrics from a ScanResult snapshot."""

    # --- Scalar / health gauges -------------------------------------------
    _EXPORTER_INFO.info({"version": _get_version(), "suite": suite})
    _SCAN_STATUS.set(1 if result.scan_ok else 0)
    _LAST_SCAN_TS.set(result.scan_timestamp)
    _SCAN_DURATION.set(result.scan_duration)
    _PKG_COUNT.set(len(result.installed_packages))

    # --- Clear labelled gauges to remove stale series ---------------------
    _VULNS_TOTAL.clear()
    _VULN_INFO.clear()
    _PKG_INFO.clear()
    _FIX_INFO.clear()
    _EPSS_SCORE.clear()
    _EPSS_PERCENTILE.clear()

    if not result.scan_ok or not result.categorized:
        return

    # --- Aggregated counts ------------------------------------------------
    agg: dict[tuple[str, str, str], int] = {}
    for severity, vulns in result.categorized.items():
        for v in vulns:
            key = (severity, _bool_label(v.fix_available), _remote_label(v.remote))
            agg[key] = agg.get(key, 0) + 1

    for (severity, fix_avail, remote), count in agg.items():
        _VULNS_TOTAL.labels(
            severity=severity,
            fix_available=fix_avail,
            remote=remote,
        ).set(count)

    # --- Per-(cve, package) metrics ---------------------------------------
    seen_packages: set[str] = set()

    for severity, vulns in result.categorized.items():
        for v in vulns:
            pkg_name = getattr(v, "installed_package", v.package) or v.package
            installed_ver = str(getattr(v, "installed_version", "") or "")
            remote_lbl = _remote_label(v.remote)
            fix_lbl = _bool_label(v.fix_available)

            _VULN_INFO.labels(
                cve=v.bug_id,
                package=pkg_name,
                urgency=v.urgency or "",
                severity=severity,
                fix_available=fix_lbl,
                remote=remote_lbl,
            ).set(1)

            _FIX_INFO.labels(
                cve=v.bug_id,
                package=pkg_name,
                fix_version=_fix_version(v),
            ).set(1)

            _EPSS_SCORE.labels(cve=v.bug_id, package=pkg_name).set(
                v.epss_score
            )
            _EPSS_PERCENTILE.labels(cve=v.bug_id, package=pkg_name).set(
                v.epss_percentile
            )

            # One series per package (not per CVE)
            if pkg_name not in seen_packages:
                seen_packages.add(pkg_name)
                _PKG_INFO.labels(
                    package=pkg_name,
                    installed_version=installed_ver,
                ).set(1)


# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------

class _MetricsHandler(http.server.BaseHTTPRequestHandler):
    """Minimal HTTP handler serving /metrics and health endpoints."""

    # Injected by ExporterServer before the server starts
    cache: Cache
    suite: str

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: N802
        logger.debug("HTTP %s", fmt % args)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/-/healthy":
            self._send_text(200, "OK\n")
        elif self.path == "/-/ready":
            result = self.cache.get()
            if result is None:
                self._send_text(503, "Not ready — waiting for first scan\n")
            else:
                self._send_text(200, "Ready\n")
        elif self.path == "/metrics":
            result = self.cache.get()
            if result is None:
                self._send_text(503, "Not ready — waiting for first scan\n")
                return
            _update_metrics(result, self.suite)
            output = generate_latest(REGISTRY)
            self.send_response(200)
            self.send_header("Content-Type", CONTENT_TYPE_LATEST)
            self.send_header("Content-Length", str(len(output)))
            self.end_headers()
            self.wfile.write(output)
        else:
            self._send_text(404, "Not found\n")

    def _send_text(self, code: int, body: str) -> None:
        encoded = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


# ---------------------------------------------------------------------------
# Exporter server
# ---------------------------------------------------------------------------

class ExporterServer:
    """Wraps a TCPServer and runs it in its own daemon thread."""

    def __init__(self, cache: Cache, port: int, suite: str) -> None:
        self._cache = cache
        self._port = port
        self._suite = suite
        self._server: socketserver.TCPServer | None = None

    def serve_forever(self) -> None:
        """Start the HTTP server and block until interrupted."""

        # Build a handler class with the cache and suite injected as class
        # attributes (avoids global state while keeping BaseHTTPRequestHandler's
        # interface intact).
        cache = self._cache
        suite = self._suite

        class Handler(_MetricsHandler):
            pass

        Handler.cache = cache  # type: ignore[attr-defined]
        Handler.suite = suite  # type: ignore[attr-defined]

        socketserver.TCPServer.allow_reuse_address = True
        with socketserver.TCPServer(("", self._port), Handler) as server:
            self._server = server
            logger.info("Metrics server listening on :%d", self._port)
            server.serve_forever()

    def shutdown(self) -> None:
        """Stop the server (called from signal handlers or tests)."""
        if self._server:
            threading.Thread(target=self._server.shutdown, daemon=True).start()
