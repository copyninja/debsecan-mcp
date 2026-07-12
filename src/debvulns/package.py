import logging
import shutil
import subprocess

from debian.debian_support import NativeVersion

logger = logging.getLogger(__name__)

# Try importing apt_pkg and fallback to python-debian if not available
try:
    import apt_pkg  # type: ignore[import-not-found]

    if apt_pkg is not None:
        apt_pkg.init()
    _has_apt_pkg = True
except ImportError:
    _has_apt_pkg = False
    apt_pkg = None


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


class Package:
    def __init__(
        self,
        name: str,
        version: Version,
        source: str | None = None,
        source_version: Version | None = None,
    ):
        self.name = name
        self.version = version
        self.source = source or name
        self.source_version = source_version or version

    def __repr__(self):
        return (
            f"Package(name={self.name!r}, version={self.version!r}, "
            f"source={self.source!r}, source_version={self.source_version!r})"
        )

    @classmethod
    def from_apt_pkg(
        cls, pkg: "apt_pkg.Package", records: "apt_pkg.PackageRecords"
    ) -> "Package":
        """Create a Package from an apt_pkg.Package with a current version."""
        ver = pkg.current_ver
        pkg_version = ver.ver_str
        pkg_source = pkg.name
        pkg_source_version = pkg_version

        # Look up the package record to extract source package info
        pf, idx = ver.file_list[0]
        records.lookup((pf, idx))
        if records.source_pkg:
            pkg_source = records.source_pkg
        if records.source_ver:
            pkg_source_version = records.source_ver

        return cls(
            pkg.name,
            Version(pkg_version),
            pkg_source,
            Version(pkg_source_version),
        )


def get_installed_packages() -> list[Package]:
    """
    Get installed packages using python-apt (apt_pkg.Cache) if available,
    otherwise falling back to dpkg-query.
    """
    packages = []

    if _has_apt_pkg and apt_pkg is not None:
        try:
            cache = apt_pkg.Cache(progress=None)
            records = apt_pkg.PackageRecords(cache)
            for pkg in cache.packages:
                if pkg.current_ver:
                    try:
                        packages.append(Package.from_apt_pkg(pkg, records))
                    except ValueError as e:
                        logger.warning(
                            "Invalid version for package %s: %s", pkg.name, e
                        )
            logger.info("Found %d installed packages using apt_pkg", len(packages))
            return packages
        except Exception as e:
            logger.warning(
                "Failed to read apt cache, falling back to dpkg-query: %s",
                e,
            )

    # Fallback to dpkg-query
    if shutil.which("dpkg-query"):
        try:
            cmd = [
                "dpkg-query",
                "-W",
                "-f=${db:Status-Status}\\t${Package}\\t${Version}\\t${source:Package}\\t${source:Version}\\n",
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=True
            )
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

                    try:
                        packages.append(
                            Package(
                                pkg_name,
                                Version(pkg_version),
                                pkg_source,
                                Version(pkg_source_version),
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
