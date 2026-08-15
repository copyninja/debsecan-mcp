"""Background cache-refresh thread for the Prometheus exporter.

The RefreshThread runs the full scan pipeline once at startup, writes
results into the shared Cache, then sleeps and repeats.

Retry / sleep policy
--------------------
* **Boot phase** (before the first successful scan): exponential backoff
  starting at BACKOFF_BASE seconds, doubling each attempt, capped at
  BACKOFF_MAX, with ±BACKOFF_JITTER relative noise to spread retries.
* **Steady state** (after the first success): fixed ``refresh_interval``
  sleep between scans.

Disk caching (optional)
-----------------------
If ``cache_dir`` is provided, downloads are written to ``<name>.tmp``
first and then atomically renamed to ``<name>`` via ``os.replace``.
This prevents the HTTP server from ever reading a partially-written file.
The in-memory Cache is always the primary source; disk files are only
used as a warm-start to skip the network download when they are fresh.

Cache freshness thresholds
--------------------------
* EPSS + Debian vulnerability data: ``refresh_interval`` seconds (default 24 h).
* OSV results (non-Debian packages): ``osv_cache_max_age`` seconds (default 7 days).
  OSV data for a given installed package version changes infrequently, so a
  longer TTL avoids unnecessary API traffic to OSV.dev.
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
import os
import random
import tempfile
import threading
import time

from . import epss, osv, package, vulnerability
from .cache import Cache, ScanResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Backoff constants (boot phase only)
# ---------------------------------------------------------------------------
BACKOFF_BASE: float = 30.0      # first retry delay in seconds
BACKOFF_MAX: float = 1800.0     # hard cap (30 min)
BACKOFF_JITTER: float = 0.10    # ± fraction applied to computed delay


def _backoff_delay(attempt: int) -> float:
    """Return a jittered exponential delay for the given attempt number (0-based)."""
    delay = min(BACKOFF_BASE * (2 ** attempt), BACKOFF_MAX)
    jitter = delay * BACKOFF_JITTER
    return delay + random.uniform(-jitter, jitter)


# ---------------------------------------------------------------------------
# Serialisation helpers (reused from cli.py pattern)
# ---------------------------------------------------------------------------

def _serialize_vulnerabilities(
    feed: dict[str, list[vulnerability.Vulnerability]],
) -> dict:
    return {
        pkg: [
            {
                "bug_id": v.bug_id,
                "package": v.package,
                "description": v.description,
                "unstable_version": (
                    str(v.unstable_version) if v.unstable_version else ""
                ),
                "other_versions": [str(ov) for ov in v.other_versions],
                "is_binary": v.is_binary,
                "urgency": v.urgency,
                "remote": v.remote,
                "fix_available": v.fix_available,
            }
            for v in vulns
        ]
        for pkg, vulns in feed.items()
    }


def _deserialize_vulnerabilities(
    data: dict,
) -> dict[str, list[vulnerability.Vulnerability]]:
    feed: dict[str, list[vulnerability.Vulnerability]] = {}
    for pkg, vulns in data.items():
        feed[pkg] = [
            vulnerability.Vulnerability(
                bug_id=v["bug_id"],
                package=v["package"],
                description=v["description"],
                unstable_version=v["unstable_version"],
                other_versions=v["other_versions"],
                is_binary=v["is_binary"],
                urgency=v["urgency"],
                remote=v["remote"],
                fix_available=v["fix_available"],
            )
            for v in vulns
        ]
    return feed


def _is_fresh(path: str, max_age: float) -> bool:
    """Return True if *path* exists and is younger than *max_age* seconds."""
    if not os.path.exists(path):
        return False
    return (time.time() - os.path.getmtime(path)) < max_age


def _atomic_write_json(data: object, dest_path: str) -> None:
    """Write *data* as JSON to *dest_path* atomically via a temp file."""
    dir_name = os.path.dirname(dest_path)
    # Write to a named temp file in the same directory so os.replace is atomic
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh)
        os.replace(tmp_path, dest_path)
    except Exception:
        # Clean up temp file on failure; propagate the exception
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Async scan pipeline
# ---------------------------------------------------------------------------

async def _run_scan(
    suite: str,
    vuln_url: str | None,
    epss_url: str | None,
    cache_dir: str | None,
    refresh_interval: float,
    osv_cache_max_age: float = 604800.0,
) -> ScanResult:
    """Run the full scan pipeline and return a populated ScanResult."""
    t0 = time.monotonic()

    # --- 1. Vulnerability data -------------------------------------------
    vuln_cache_path = (
        os.path.join(cache_dir, f"vulnerabilities_{suite}.json") if cache_dir else None
    )
    vuln_feed: dict[str, list[vulnerability.Vulnerability]] | None = None

    if vuln_cache_path and _is_fresh(vuln_cache_path, refresh_interval):
        logger.debug("Loading vulnerability data from disk cache: %s", vuln_cache_path)
        try:
            with open(vuln_cache_path) as fh:
                vuln_feed = _deserialize_vulnerabilities(json.load(fh))
        except Exception as exc:
            logger.warning("Failed to read vulnerability cache: %s", exc)

    if vuln_feed is None:
        logger.info("Fetching vulnerability data for suite %s", suite)
        vuln_feed = await vulnerability.fetch_data(suite, vuln_url)
        if vuln_cache_path and cache_dir:
            try:
                os.makedirs(cache_dir, exist_ok=True)
                _atomic_write_json(
                    _serialize_vulnerabilities(vuln_feed),
                    vuln_cache_path,
                )
                logger.debug("Saved vulnerability data to %s", vuln_cache_path)
            except Exception as exc:
                logger.warning("Failed to write vulnerability cache: %s", exc)

    # --- 2. EPSS data -------------------------------------------------------
    epss_cache_path = (
        os.path.join(cache_dir, "epss.json") if cache_dir else None
    )
    epss_data: dict[str, dict[str, float]] | None = None

    if epss_cache_path and _is_fresh(epss_cache_path, refresh_interval):
        logger.debug("Loading EPSS data from disk cache: %s", epss_cache_path)
        try:
            with open(epss_cache_path) as fh:
                epss_data = json.load(fh)
        except Exception as exc:
            logger.warning("Failed to read EPSS cache: %s", exc)

    if epss_data is None:
        logger.info("Downloading EPSS data")
        try:
            epss_data = await epss.download_epss(epss_url)
            if epss_cache_path and cache_dir:
                try:
                    os.makedirs(cache_dir, exist_ok=True)
                    _atomic_write_json(epss_data, epss_cache_path)
                    logger.debug("Saved EPSS data to %s", epss_cache_path)
                except Exception as exc:
                    logger.warning("Failed to write EPSS cache: %s", exc)
        except Exception as exc:
            # Partial failure: EPSS unavailable, continue without scores.
            # scan_ok will remain False (set by caller) to signal degraded state.
            logger.warning(
                "EPSS download failed, proceeding without EPSS scores: %s",
                exc,
            )
            epss_data = {}

    # --- 3. Installed packages ----------------------------------------------
    logger.info("Reading installed packages")
    installed_packages = package.get_installed_packages()

    # Split by origin: only Debian-sourced packages go through the Debian feed.
    debian_pkgs = [p for p in installed_packages if p.is_debian_origin]
    non_debian_pkgs = [p for p in installed_packages if not p.is_debian_origin]

    if non_debian_pkgs:
        logger.info(
            "Skipping %d non-Debian package(s) from Debian feed scan: %s",
            len(non_debian_pkgs),
            [p.name for p in non_debian_pkgs],
        )

    # --- 4. Match vulnerabilities against Debian-origin packages only -------
    detected: list[vulnerability.Vulnerability] = []
    for pkg in debian_pkgs:
        relevant = vuln_feed.get(pkg.source) or vuln_feed.get(pkg.name, [])
        for v in relevant:
            if v.is_vulnerable(pkg):
                epss_info = epss_data.get(v.bug_id, {"score": 0.0, "percentile": 0.0})
                v_copy = copy.copy(v)
                v_copy.epss_score = epss_info["score"]
                v_copy.epss_percentile = epss_info["percentile"]
                v_copy.installed_package = pkg.name
                v_copy.installed_version = pkg.version
                detected.append(v_copy)

    # --- 5. Deduplicate (cve, package) pairs --------------------------------
    unique: dict[tuple[str, str], vulnerability.Vulnerability] = {}
    for v in detected:
        key = (v.bug_id, v.installed_package)  # type: ignore[arg-type]
        if key not in unique:
            unique[key] = v

    # --- 5b. OSV cross-check for non-Debian packages ------------------------
    if non_debian_pkgs:
        osv_cache_path = (
            os.path.join(cache_dir, "osv_results.json") if cache_dir else None
        )
        osv_results: list[dict] = []

        if osv_cache_path and _is_fresh(osv_cache_path, osv_cache_max_age):
            logger.debug("Loading OSV results from disk cache: %s", osv_cache_path)
            try:
                with open(osv_cache_path) as fh:
                    osv_results = json.load(fh)
            except Exception as exc:
                logger.warning("Failed to read OSV cache: %s", exc)
                osv_results = []

        if not osv_results:
            try:
                osv_results = await osv.check_non_debian_packages(
                    non_debian_pkgs, vuln_feed, epss_data
                )
                if osv_cache_path and cache_dir:
                    try:
                        os.makedirs(cache_dir, exist_ok=True)
                        _atomic_write_json(osv_results, osv_cache_path)
                        logger.debug("Saved OSV results to %s", osv_cache_path)
                    except Exception as exc:
                        logger.warning("Failed to write OSV cache: %s", exc)
            except Exception as exc:
                logger.error("OSV cross-check failed in refresh pipeline: %s", exc)

        for entry in osv_results:
            cve_id = entry["cve"]
            pkg_name = entry["package"]
            key = (cve_id, pkg_name)
            if key not in unique:
                v_osv = vulnerability.Vulnerability(
                    bug_id=cve_id,
                    package=pkg_name,
                    description=entry["description"],
                    unstable_version="",
                    other_versions=[],
                    is_binary=False,
                    urgency=entry["urgency"],
                    remote=None,
                    fix_available=True,
                )
                v_osv.epss_score = entry["epss_score"]
                v_osv.epss_percentile = entry["epss_percentile"]
                v_osv.installed_package = pkg_name
                v_osv.installed_version = None
                unique[key] = v_osv

    # --- 6. Categorise -------------------------------------------------------
    categorized = vulnerability.categorise_vulnerabilities(list(unique.values()))

    duration = time.monotonic() - t0
    logger.info(
        "Scan complete in %.2f s — %d unique (cve, pkg) pairs "
        "across %d installed packages",
        duration,
        len(unique),
        len(installed_packages),
    )

    return ScanResult(
        categorized=categorized,
        installed_packages=installed_packages,
        scan_timestamp=time.time(),
        scan_duration=duration,
        scan_ok=True,
    )


# ---------------------------------------------------------------------------
# Refresh thread
# ---------------------------------------------------------------------------

class RefreshThread(threading.Thread):
    """Daemon thread that periodically refreshes the vulnerability cache.

    On the first run uses exponential backoff on failure.  After the first
    successful scan it switches to a fixed ``refresh_interval`` sleep.
    """

    def __init__(
        self,
        cache: Cache,
        suite: str,
        refresh_interval: float,
        vuln_url: str | None = None,
        epss_url: str | None = None,
        cache_dir: str | None = None,
        osv_cache_max_age: float = 604800.0,
    ) -> None:
        super().__init__(daemon=True, name="cache-refresher")
        self._cache = cache
        self._suite = suite
        self._interval = refresh_interval
        self._vuln_url = vuln_url
        self._epss_url = epss_url
        self._cache_dir = cache_dir
        self._osv_cache_max_age = osv_cache_max_age
        self._first_success = False

    def _next_sleep(self, attempt: int) -> float:
        """Return the sleep duration for the next cycle."""
        if self._first_success:
            return self._interval
        return _backoff_delay(attempt)

    def run(self) -> None:  # noqa: C901
        attempt = 0
        while True:
            t_start = time.monotonic()
            result: ScanResult | None = None
            try:
                result = asyncio.run(
                    _run_scan(
                        suite=self._suite,
                        vuln_url=self._vuln_url,
                        epss_url=self._epss_url,
                        cache_dir=self._cache_dir,
                        refresh_interval=self._interval,
                        osv_cache_max_age=self._osv_cache_max_age,
                    )
                )
                self._first_success = True
                attempt = 0  # reset backoff counter after any success
                self._cache.update(result)
            except Exception:
                logger.exception("Scan pipeline failed (attempt %d)", attempt + 1)
                attempt += 1
                # On failure: update cache with a failed ScanResult so the
                # exporter can flip debsecan_scan_status → 0 while keeping
                # the previous good metrics intact (cache.get() still returns
                # the last good ScanResult; we only push a failure marker if
                # the cache is still empty — first boot failure).
                if self._cache.get() is None:
                    # Nothing in cache yet — push a failure marker so
                    # /-/ready returns 503 but scan_status is still visible.
                    self._cache.update(
                        ScanResult(
                            scan_timestamp=time.time(),
                            scan_ok=False,
                        )
                    )

            elapsed = time.monotonic() - t_start
            sleep_for = max(0.0, self._next_sleep(attempt) - elapsed)
            logger.info(
                "Next refresh in %.0f s (attempt=%d, first_success=%s)",
                sleep_for,
                attempt,
                self._first_success,
            )
            time.sleep(sleep_for)
