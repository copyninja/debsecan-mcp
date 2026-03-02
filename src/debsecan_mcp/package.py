import logging

import apt_pkg

logger = logging.getLogger(__name__)

apt_pkg.init()
version_compare = apt_pkg.version_compare


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
    def from_apt_pkg(cls, pkg: apt_pkg.Package) -> "Package":
        """Create a Package from an apt_pkg.Package with a current version."""
        ver = pkg.current_ver
        pkg_version = ver.ver_str
        pkg_source = pkg.name
        pkg_source_version = pkg_version

        # Extract source package info from the version record
        source_field = ver.source_pkg_name
        if source_field:
            pkg_source = source_field
        source_ver_field = ver.source_ver_str
        if source_ver_field:
            pkg_source_version = source_ver_field

        return cls(
            pkg.name,
            Version(pkg_version),
            pkg_source,
            Version(pkg_source_version),
        )


def get_installed_packages() -> list[Package]:
    """
    Get installed packages using python-apt (apt_pkg.Cache).
    """
    packages = []

    try:
        cache = apt_pkg.Cache(progress=None)
        for pkg in cache.packages:
            if pkg.current_ver:
                try:
                    packages.append(Package.from_apt_pkg(pkg))
                except ValueError as e:
                    logger.warning("Invalid version for package %s: %s", pkg.name, e)
    except Exception as e:
        logger.exception("Failed to read apt cache: %s", e)

    logger.info("Found %d installed packages", len(packages))
    return packages
