import json
import logging
import os
import shutil
import subprocess
import sys

from debian.debian_support import NativeVersion

logger = logging.getLogger(__name__)

# Try importing apt_pkg and fallback to python-debian if not available
try:
    import apt_pkg  # type: ignore[import-not-found]
except ImportError:
    # If running inside a virtualenv, python3-apt is installed in system dist-packages
    for p in ("/usr/lib/python3/dist-packages", "/usr/local/lib/python3/dist-packages"):
        if p not in sys.path and os.path.isdir(p):
            sys.path.append(p)
    try:
        import apt_pkg  # type: ignore[import-not-found]
    except ImportError:
        apt_pkg = None

if apt_pkg is not None:
    try:
        apt_pkg.init()
        _has_apt_pkg = True
    except Exception as e:
        logger.debug("Failed to initialize apt_pkg: %s", e)
        _has_apt_pkg = False
else:
    _has_apt_pkg = False


def version_compare(v1: str, v2: str) -> int:
    """Compare two Debian version strings."""
    if _has_apt_pkg and apt_pkg is not None:
        try:
            return apt_pkg.version_compare(v1, v2)
        except Exception as e:
            logger.debug("Failed to compare using apt_pkg.version_compare: %s", e)

    nv1 = NativeVersion(v1)
    nv2 = NativeVersion(v2)
    if nv1 < nv2:
        return -1
    elif nv1 > nv2:
        return 1
    return 0


class Version:
    """Version class which uses the APT comparison algorithm."""

    def __init__(self, version: str):
        if not version:
            raise ValueError("Version string cannot be empty")
        self.version = version

    def __str__(self):
        return self.version

    def __repr__(self):
        return f"Version({self.version!r})"

    def compare(self, other: "Version") -> int:
        return version_compare(self.version, other.version)

    def __lt__(self, other):
        if isinstance(other, str):
            other = Version(other)
        return self.compare(other) < 0

    def __eq__(self, other):
        if isinstance(other, str):
            other = Version(other)
        return self.compare(other) == 0

    def __gt__(self, other):
        if isinstance(other, str):
            other = Version(other)
        return self.compare(other) > 0

    def __le__(self, other):
        if isinstance(other, str):
            other = Version(other)
        return self.compare(other) <= 0

    def __ge__(self, other):
        if isinstance(other, str):
            other = Version(other)
        return self.compare(other) >= 0

    def __ne__(self, other):
        if isinstance(other, str):
            other = Version(other)
        return self.compare(other) != 0


# Known Debian archive names used to identify Debian-sourced packages.
_DEBIAN_ARCHIVES: frozenset[str] = frozenset(
    {
        "stable",
        "testing",
        "unstable",
        "sid",
        "experimental",
        "bookworm",
        "bullseye",
        "buster",
        "stretch",
        "jessie",
        "wheezy",
        "trixie",
        "forky",
    }
)


class Package:
    def __init__(
        self,
        name: str,
        version: Version,
        source: str | None = None,
        source_version: Version | None = None,
        origin: str = "",
        archive: str = "",
        maintainer: str = "",
    ):
        self.name = name
        self.version = version
        self.source = source or name
        self.source_version = source_version or version
        # Origin metadata from apt_pkg.PackageFile; empty when unknown
        # (e.g. dpkg-query fallback path).
        self.origin = origin
        self.archive = archive
        self.maintainer = maintainer if isinstance(maintainer, str) else ""

    @property
    def is_debian_origin(self) -> bool:
        """Return True if the package demonstrably comes from the Debian archive.

        Detection relies on apt_pkg metadata (origin / archive fields from
        PackageFile) and maintainer information. When origin is 'Debian' or
        archive matches a known Debian suite, it is Debian.
        Packages whose archive is 'now' (e.g. installed kernel images replaced by
        a newer version in sid) are verified using maintainer email (@debian.org
        or @debian.net).
        When both origin and archive are empty (dpkg-query fallback, or locally
        built packages that were never registered in any APT source list) the
        method returns True so that those packages are still scanned by the
        Debian Security Tracker — this is the safe default that avoids missing
        real vulnerabilities.

        A package is considered *non*-Debian when:
        - origin is explicitly non-empty and different from "Debian", OR
        - archive is "now" (installed locally / outside any APT repo) and
          origin is empty, and maintainer is not a Debian maintainer.
        """
        if self.origin == "Debian":
            return True
        if self.archive in _DEBIAN_ARCHIVES:
            return True
        maint = self.maintainer.lower()
        if "debian.org" in maint or "debian.net" in maint:
            return True
        # Both empty → origin unknown (dpkg-query path) → treat as Debian
        if not self.origin and not self.archive:
            return True
        # archive == "now" with empty origin → locally installed / third-party
        return False

    def __repr__(self):
        return (
            f"Package(name={self.name!r}, version={self.version!r}, "
            f"source={self.source!r}, source_version={self.source_version!r}, "
            f"origin={self.origin!r}, archive={self.archive!r}, "
            f"maintainer={self.maintainer!r})"
        )

    @classmethod
    def from_apt_pkg(
        cls,
        pkg: "apt_pkg.Package",
        records: "apt_pkg.PackageRecords",
        policy: "apt_pkg.Policy",
    ) -> "Package":
        """Create a Package from an apt_pkg.Package with a current version.

        The installed version's PackageFile entry sometimes lacks origin/archive
        metadata when a newer candidate is available in a known repository (APT
        stores the origin on the *candidate* entry, not the locally-cached one).
        In that case the Policy candidate version is consulted as a fallback to
        recover the correct origin/archive without altering the installed version.
        """
        ver = pkg.current_ver
        pkg_version = ver.ver_str
        pkg_source = pkg.name
        pkg_source_version = pkg_version

        # Look up the package record to extract source package info and
        # origin metadata from the APT package file entry.
        pf, idx = ver.file_list[0]
        records.lookup((pf, idx))
        if records.source_pkg:
            pkg_source = records.source_pkg
        if records.source_ver:
            pkg_source_version = records.source_ver

        pkg_origin: str = getattr(pf, "origin", "")
        pkg_archive: str = getattr(pf, "archive", "")
        raw_maint = getattr(records, "maintainer", "")
        pkg_maintainer: str = raw_maint if isinstance(raw_maint, str) else ""

        # When origin is empty the installed version's PackageFile has no repo
        # metadata (typically archive='now' for a pending upgrade).  If a newer
        # candidate exists in a known repository, borrow its origin/archive to
        # correctly classify the package's provenance.
        if not pkg_origin:
            candidate_ver = policy.get_candidate_ver(pkg)
            if candidate_ver is not None and candidate_ver > ver:
                logger.debug(
                    "Using candidate ver %s to resolve origin for %s (installed %s)",
                    candidate_ver.ver_str,
                    pkg.name,
                    ver.ver_str,
                )
                cpf, cidx = candidate_ver.file_list[0]
                records.lookup((cpf, cidx))
                pkg_origin = getattr(cpf, "origin", "")
                pkg_archive = getattr(cpf, "archive", "")
                if not pkg_maintainer:
                    raw_cand_maint = getattr(records, "maintainer", "")
                    pkg_maintainer = (
                        raw_cand_maint if isinstance(raw_cand_maint, str) else ""
                    )

        return cls(
            pkg.name,
            Version(pkg_version),
            pkg_source,
            Version(pkg_source_version),
            origin=pkg_origin,
            archive=pkg_archive,
            maintainer=pkg_maintainer,
        )


def _get_installed_packages_system_apt() -> list[Package] | None:
    """Run system python3 to access apt_pkg when the current interpreter lacks it.

    This happens when running inside a virtualenv whose Python version does not
    match the system's python3-apt C-extension (e.g. uv managed Python 3.13 on a
    system with python3-apt compiled for Python 3.14).
    """
    system_python = "/usr/bin/python3"
    if not os.path.exists(system_python):
        return None
    if os.path.realpath(system_python) == os.path.realpath(sys.executable):
        return None

    script = """
import apt_pkg, json, sys
try:
    apt_pkg.init()
    cache = apt_pkg.Cache(progress=None)
    policy = apt_pkg.Policy(cache)
    records = apt_pkg.PackageRecords(cache)
    pkgs = []
    for pkg in cache.packages:
        ver = pkg.current_ver
        if ver:
            pf, idx = ver.file_list[0]
            records.lookup((pf, idx))
            src = records.source_pkg or pkg.name
            src_ver = records.source_ver or ver.ver_str
            orig = getattr(pf, 'origin', '')
            arch = getattr(pf, 'archive', '')
            maint = getattr(records, 'maintainer', '') or ''
            if not orig:
                cver = policy.get_candidate_ver(pkg)
                if cver and cver > ver:
                    cpf, cidx = cver.file_list[0]
                    records.lookup((cpf, cidx))
                    orig = getattr(cpf, 'origin', '')
                    arch = getattr(cpf, 'archive', '')
                    if not maint:
                        maint = getattr(records, 'maintainer', '') or ''
            pkgs.append((pkg.name, ver.ver_str, src, src_ver, orig, arch, maint))
    json.dump(pkgs, sys.stdout)
except Exception as e:
    sys.exit(1)
"""
    try:
        res = subprocess.run(
            [system_python, "-c", script],
            capture_output=True,
            text=True,
            timeout=20,
            check=True,
        )
        data = json.loads(res.stdout)
        packages: list[Package] = []
        for item in data:
            if len(item) == 7:
                name, ver, src, src_ver, orig, arch, maint = item
            else:
                name, ver, src, src_ver, orig, arch = item[:6]
                maint = ""
            try:
                packages.append(
                    Package(
                        name,
                        Version(ver),
                        src,
                        Version(src_ver),
                        origin=orig,
                        archive=arch,
                        maintainer=maint,
                    )
                )
            except ValueError:
                continue
        logger.info(
            "Found %d installed packages using system python3 apt_pkg bridge",
            len(packages),
        )
        return packages
    except Exception as exc:
        logger.debug("System python apt_pkg bridge failed: %s", exc)
        return None


def get_installed_packages() -> list[Package]:
    """
    Get installed packages using python-apt (apt_pkg.Cache) if available,
    falling back to system python3 apt_pkg bridge, and finally to dpkg-query.
    """
    packages = []

    if _has_apt_pkg and apt_pkg is not None:
        try:
            cache = apt_pkg.Cache(progress=None)
            policy = apt_pkg.Policy(cache)
            records = apt_pkg.PackageRecords(cache)
            for pkg in cache.packages:
                if pkg.current_ver:
                    try:
                        packages.append(Package.from_apt_pkg(pkg, records, policy))
                    except ValueError as e:
                        logger.warning(
                            "Invalid version for package %s: %s", pkg.name, e
                        )
            logger.info("Found %d installed packages using apt_pkg", len(packages))
            return packages
        except Exception as e:
            logger.warning(
                "Failed to read apt cache, falling back to system python3 bridge: %s",
                e,
            )

    # Try system python3 bridge if apt_pkg is unavailable in current interpreter
    system_packages = _get_installed_packages_system_apt()
    if system_packages is not None:
        return system_packages

    # Fallback to dpkg-query
    if shutil.which("dpkg-query"):
        try:
            cmd = [
                "dpkg-query",
                "-W",
                "-f=${db:Status-Status}\\t${Package}\\t${Version}\\t${source:Package}\\t${source:Version}\\t${Maintainer}\\n",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue
                parts = line.split("\t")
                if len(parts) >= 3 and parts[0] == "installed":
                    pkg_name = parts[1]
                    pkg_version = parts[2]
                    pkg_source = parts[3] if len(parts) > 3 and parts[3] else pkg_name
                    pkg_source_version = (
                        parts[4] if len(parts) > 4 and parts[4] else pkg_version
                    )
                    pkg_maint = parts[5] if len(parts) > 5 else ""

                    try:
                        packages.append(
                            Package(
                                pkg_name,
                                Version(pkg_version),
                                pkg_source,
                                Version(pkg_source_version),
                                maintainer=pkg_maint,
                            )
                        )
                    except ValueError as e:
                        logger.warning(
                            "Invalid version for package %s: %s", pkg_name, e
                        )
            logger.info("Found %d installed packages using dpkg-query", len(packages))
            return packages
        except Exception as e:
            logger.error("Failed to run dpkg-query: %s", e)

    logger.warning(
        "No package database source available (both apt_pkg and "
        "dpkg-query failed/unavailable)"
    )
    return packages
