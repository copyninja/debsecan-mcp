"""Entry-point for the debsecan Prometheus exporter.

Wires the RefreshThread (background cache refresh) and ExporterServer
(HTTP metrics endpoint) together and starts the server.

Usage
-----
    debvulns-exporter [options]

    Options:
      --port PORT               HTTP listen port (default: 9222)
      --suite SUITE             Debian suite name; auto-detected by default
      --refresh-interval SECS   Seconds between full scans (default: 86400)
      --cache-dir DIR           Directory for warm-start disk cache
      --vuln-url URL            Override vulnerability data source URL
      --epss-url URL            Override EPSS data source URL
      -v / --verbose            Enable debug logging
"""

from __future__ import annotations

import argparse
import logging
import sys

from .cache import Cache
from .exporter import ExporterServer
from .main import detect_suite
from .refresher import RefreshThread

logger = logging.getLogger(__name__)

# Minimum allowed refresh interval to avoid hammering upstream data sources
_MIN_REFRESH_INTERVAL = 3600  # 1 hour


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="debvulns-exporter",
        description="Prometheus exporter for Debian security vulnerabilities.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=9222,
        metavar="PORT",
        help="TCP port to expose /metrics on (default: 9222)",
    )
    parser.add_argument(
        "--suite",
        default=None,
        metavar="SUITE",
        help="Debian suite codename (e.g. bookworm, sid). Auto-detected by default.",
    )
    parser.add_argument(
        "--refresh-interval",
        type=int,
        default=86400,
        dest="refresh_interval",
        metavar="SECS",
        help=(
            "Seconds between full vulnerability scans (default: 86400 = 24 h). "
            f"Minimum: {_MIN_REFRESH_INTERVAL} s."
        ),
    )
    parser.add_argument(
        "--cache-dir",
        default="/var/cache/debvulns",
        dest="cache_dir",
        metavar="DIR",
        help=(
            "Directory used for warm-start disk cache of downloaded data "
            "(default: /var/cache/debvulns). Disable with --no-cache."
        ),
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        dest="no_cache",
        help="Disable disk caching; always re-download on every refresh.",
    )
    parser.add_argument(
        "--vuln-url",
        default=None,
        dest="vuln_url",
        metavar="URL",
        help="Override the Debian Security Tracker vulnerability data URL.",
    )
    parser.add_argument(
        "--epss-url",
        default=None,
        dest="epss_url",
        metavar="URL",
        help="Override the EPSS CSV data URL.",
    )
    parser.add_argument(
        "--osv-cache-max-age",
        type=int,
        default=604800,
        dest="osv_cache_max_age",
        metavar="SECS",
        help=(
            "Maximum age in seconds for the OSV results cache before "
            "re-querying OSV.dev (default: 604800 = 7 days). "
            "Ignored when --no-cache is set."
        ),
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug-level logging to stderr.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
        force=True,
    )

    # Validate refresh interval
    if args.refresh_interval < _MIN_REFRESH_INTERVAL:
        logger.error(
            "--refresh-interval %d s is below the minimum of %d s.",
            args.refresh_interval,
            _MIN_REFRESH_INTERVAL,
        )
        sys.exit(1)

    # Detect Debian suite
    try:
        suite = args.suite or detect_suite()
    except Exception as exc:
        logger.error("Failed to detect Debian suite: %s", exc)
        sys.exit(1)

    logger.info("debvulns-exporter starting — suite=%s port=%d", suite, args.port)

    cache_dir = None if args.no_cache else args.cache_dir

    # --- Shared cache -------------------------------------------------------
    shared_cache = Cache()

    # --- Refresh thread (daemon) --------------------------------------------
    refresher = RefreshThread(
        cache=shared_cache,
        suite=suite,
        refresh_interval=float(args.refresh_interval),
        vuln_url=args.vuln_url,
        epss_url=args.epss_url,
        cache_dir=cache_dir,
        osv_cache_max_age=float(args.osv_cache_max_age),
    )
    refresher.start()
    logger.info(
        "Cache-refresh thread started (refresh_interval=%d s)",
        args.refresh_interval,
    )

    # --- HTTP server (blocks main thread) -----------------------------------
    server = ExporterServer(cache=shared_cache, port=args.port, suite=suite)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Interrupted — shutting down")
        server.shutdown()
