"""Shared in-memory cache for the Prometheus exporter.

The Cache class owns an RLock that is held *only* for the pointer swap
(a single assignment), never during network I/O. This keeps the critical
section sub-millisecond and ensures HTTP scrapes are never blocked by a
slow network refresh.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from .package import Package
from .vulnerability import Vulnerability


@dataclass
class ScanResult:
    """Snapshot produced by one full scan pipeline run."""

    # severity → list of matched, categorised vulnerabilities
    categorized: dict[str, list[Vulnerability]] = field(default_factory=dict)

    # All installed packages at the time of the scan
    installed_packages: list[Package] = field(default_factory=list)

    # Unix epoch timestamp when the scan completed
    scan_timestamp: float = 0.0

    # Wall-clock seconds the scan took
    scan_duration: float = 0.0

    # True = scan succeeded; False = scan failed (may still carry stale data)
    scan_ok: bool = False


class Cache:
    """Thread-safe container for the latest ScanResult.

    - ``update()``  — called only by the RefreshThread; holds the lock for
                      a single pointer assignment.
    - ``get()``     — called on every /metrics scrape; returns ``None``
                      until the first scan has completed (signals 503).
    """

    def __init__(self) -> None:
        self._lock: threading.RLock = threading.RLock()
        self._data: ScanResult | None = None

    def update(self, result: ScanResult) -> None:
        """Atomically replace the cached snapshot."""
        with self._lock:
            self._data = result

    def get(self) -> ScanResult | None:
        """Return the latest snapshot, or None if no scan has completed yet."""
        with self._lock:
            return self._data
