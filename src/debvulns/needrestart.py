"""Restart and reboot detection — a read-only, non-root-friendly port of the
core needrestart detection logic.

Two checks are implemented:

Service restart detection
--------------------------
Scans ``/proc/<pid>/maps`` and ``/proc/<pid>/exe`` for every running process.
A process is flagged when:

* Its executable symlink has a `` (deleted)`` suffix (binary replaced on disk
  after the process started), OR
* Any executable shared-library mapping in ``/proc/<pid>/maps`` has
  ``(deleted)`` appended to its path.

Flagged PIDs are resolved to systemd service unit names via
``/proc/<pid>/cgroup`` on systemd hosts.  On non-systemd hosts the
executable basename is used as a fallback identifier.

Kernel reboot detection
------------------------
Compares ``platform.release()`` (running kernel, same as ``uname -r``) against
the newest ``linux-image-*`` package version reported by ``dpkg-query``.
A version mismatch means the host needs a reboot to activate the new kernel.

Both checks are non-fatal: if they fail for any reason (container environment,
restricted ``/proc`` access, missing dpkg, …) the caller receives ``None`` in
``restart_info`` and the exporter continues normally.
"""

from __future__ import annotations

import glob
import logging
import os
import platform
import re
import subprocess
from dataclasses import dataclass, field

from .package import version_compare

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

_DELETED_RE = re.compile(r" \(deleted\)$|^\(deleted\)")
_CGROUP_SERVICE_RE = re.compile(r"/([^/]+\.service)$")
_CGROUP_USER_SLICE_RE = re.compile(r"/user[-@]")  # skip user-session cgroups


@dataclass
class RestartInfo:
    """Snapshot of restart/reboot state on this host."""

    # Systemd unit names (e.g. "nginx.service") or exe basenames for non-systemd
    services_needing_restart: list[str] = field(default_factory=list)

    # True when a newer kernel package is installed than the one currently running
    reboot_required: bool = False

    # Running kernel string as returned by platform.release()
    running_kernel: str = ""

    # Newest installed kernel version string; None if detection failed
    expected_kernel: str | None = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _read_text(path: str) -> str | None:
    """Read a small text file, returning None on any error."""
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _exe_deleted(pid: int) -> bool:
    """Return True if /proc/<pid>/exe points to a deleted binary."""
    try:
        target = os.readlink(f"/proc/{pid}/exe")
        return bool(_DELETED_RE.search(target))
    except OSError:
        return False


def _maps_have_deleted_lib(pid: int) -> bool:
    """Return True if any executable library mapping in /proc/<pid>/maps is deleted."""
    raw = _read_text(f"/proc/{pid}/maps")
    if raw is None:
        return False
    for line in raw.splitlines():
        parts = line.split()
        # Format: addr perms offset dev inode [pathname]
        if len(parts) < 6:
            continue
        perms = parts[1]
        path = " ".join(parts[5:])
        # Only check executable mappings that reference a real inode
        inode = parts[4]
        if "x" not in perms or inode == "0" or not path:
            continue
        if _DELETED_RE.search(path):
            return True
    return False


def _resolve_service(pid: int, is_systemd: bool) -> str | None:
    """Resolve a PID to a service name.

    On systemd: reads /proc/<pid>/cgroup and extracts the *.service unit.
    On non-systemd: returns None (caller falls back to exe basename).
    Returns None for user-session cgroup entries (we don't want to list
    user login sessions as services needing restart).
    """
    if not is_systemd:
        return None

    cgroup = _read_text(f"/proc/{pid}/cgroup")
    if not cgroup:
        return None

    for line in cgroup.splitlines():
        # cgroup v2: single line "0::/system.slice/foo.service"
        # cgroup v1: lines like "1:name=systemd:/system.slice/foo.service"
        colon_parts = line.split(":", 2)
        cg_path = colon_parts[-1].strip()

        # Skip user-session / user-manager cgroups
        if _CGROUP_USER_SLICE_RE.search(cg_path):
            return None

        m = _CGROUP_SERVICE_RE.search(cg_path)
        if m:
            return m.group(1)

    return None


def _exe_basename(pid: int) -> str | None:
    """Return the basename of the process executable (for non-systemd fallback)."""
    try:
        target = os.readlink(f"/proc/{pid}/exe")
        target = _DELETED_RE.sub("", target).strip()
        return os.path.basename(target) or None
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_services_needing_restart() -> list[str]:
    """Return a deduplicated list of service/process names that need restarting.

    Works without root on Linux — /proc/<pid>/maps and cgroup files are
    world-readable.  Processes owned by other users are silently skipped when
    the maps file is not accessible.
    """
    is_systemd = os.path.isdir("/run/systemd/system")
    my_pid = os.getpid()
    my_ppid = os.getppid()
    ignore_pids = {my_pid, my_ppid}

    found: set[str] = set()

    try:
        proc_entries = os.listdir("/proc")
    except OSError as exc:
        logger.warning("Cannot list /proc: %s", exc)
        return []

    for entry in proc_entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid in ignore_pids:
            continue

        # Skip kernel threads (no exe link)
        exe_path = f"/proc/{pid}/exe"
        if not os.path.exists(exe_path):
            continue

        needs_restart = _exe_deleted(pid) or _maps_have_deleted_lib(pid)
        if not needs_restart:
            continue

        # Resolve to service name
        service = _resolve_service(pid, is_systemd)
        if service:
            found.add(service)
        else:
            # Non-systemd fallback: use exe basename
            name = _exe_basename(pid)
            if name:
                found.add(name)

    return sorted(found)


def detect_kernel_reboot() -> tuple[bool, str, str | None]:
    """Return (reboot_required, running_kernel, expected_kernel).

    ``reboot_required`` is True when the newest installed linux-image-* package
    version is different from (i.e. newer than) the currently running kernel.
    ``expected_kernel`` is None when detection fails.
    """
    running = platform.release()

    # --- Strategy 1: dpkg-query for installed linux-image-* packages --------
    expected: str | None = None
    try:
        result = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Status}\n",
             "linux-image-*"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        best_version: str | None = None
        for line in result.stdout.splitlines():
            parts = line.split("\t", 2)
            if len(parts) < 3:
                continue
            _pkg, version, status = parts
            # Only consider installed packages
            if "installed" not in status:
                continue
            if best_version is None or version_compare(version, best_version) > 0:
                best_version = version
        if best_version:
            expected = best_version
    except Exception as exc:
        logger.debug("dpkg-query for kernel packages failed: %s", exc)

    # --- Strategy 2: glob /boot/vmlinuz-* as fallback -----------------------
    if expected is None:
        vmlinuz_files = sorted(
            glob.glob("/boot/vmlinuz-*"),
            key=lambda p: p,
            reverse=True,
        )
        if vmlinuz_files:
            # Extract the version part from the filename
            latest = os.path.basename(vmlinuz_files[0])
            if latest.startswith("vmlinuz-"):
                expected = latest[len("vmlinuz-"):]

    if expected is None:
        logger.debug("Could not determine expected kernel version")
        return False, running, None

    # Compare: strip epoch prefix from dpkg version if present for comparison
    # Running kernel is in uname format e.g. "6.1.0-27-amd64"
    # dpkg version may be "6.1.0-27" (without arch suffix) or "6.1.0-27+deb12u1"
    # A simple substring check handles the common case; version_compare handles the rest
    try:
        # Try exact match first (running is a substring of expected)
        reboot_needed = running not in expected and version_compare(expected, running) > 0
    except Exception:
        reboot_needed = running not in expected

    return reboot_needed, running, expected


def collect() -> RestartInfo:
    """Run both checks and return a populated RestartInfo.

    Raises exceptions only for programming errors; all OS/subprocess errors
    are caught internally and logged at WARNING level.
    """
    services = detect_services_needing_restart()
    reboot_required, running_kernel, expected_kernel = detect_kernel_reboot()

    return RestartInfo(
        services_needing_restart=services,
        reboot_required=reboot_required,
        running_kernel=running_kernel,
        expected_kernel=expected_kernel,
    )
