import logging
import os
import re
from collections.abc import Iterator

logger = logging.getLogger(__name__)

import apt_pkg

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


class PackageFile:
    """
    A Debian package file reader.
    Models on the debsecan.PackageFile class.
    """

    re_field = re.compile(r"^([A-Za-z][A-Za-z0-9-]+):(?:\s+(.*?))?\s*$")

    def __init__(self, filename: str):
        self.filename = filename
        if not os.path.exists(filename):
            raise FileNotFoundError(f"File not found: {filename}")

    def __iter__(self) -> Iterator[list[tuple[str, str]]]:
        with open(self.filename, encoding="utf-8") as f:
            pkg: list[tuple[str, str]] = []
            for line in f:
                if line == "\n":
                    if pkg:
                        yield pkg
                        pkg = []
                    continue

                if line[0] in " \t":
                    # Continuation line
                    if not pkg:
                        logger.warning(
                            "Unexpected continuation line in %s", self.filename
                        )
                        continue
                    name, contents = pkg[-1]
                    pkg[-1] = (name, f"{contents}\n{line[1:].rstrip()}")
                else:
                    match = self.re_field.match(line)
                    if not match:
                        logger.warning("Malformed field in %s: %r", self.filename, line)
                        continue
                    name, contents = match.groups()
                    pkg.append((name, (contents or "").rstrip()))

            if pkg:
                yield pkg


def get_installed_packages(status_file: str = "/var/lib/dpkg/status") -> list[Package]:
    """
    Parses the dpkg status file to get installed packages.
    """
    packages = []
    re_source = re.compile(r"^([a-zA-Z0-9.+-]+)(?:\s+\((\S+)\))?$")

    try:
        pkgs_iter = PackageFile(status_file)
        for record in pkgs_iter:
            fields = {name: contents for name, contents in record}

            pkg_name = fields.get("Package")
            pkg_version = fields.get("Version")
            pkg_status = fields.get("Status", "")
            source_content = fields.get("Source")

            if pkg_name and pkg_version and "installed" in pkg_status:
                pkg_source = pkg_name
                pkg_source_version = pkg_version

                if source_content:
                    match = re_source.match(source_content)
                    if match:
                        pkg_source, pkg_source_version = match.groups()
                        if not pkg_source_version:
                            pkg_source_version = pkg_version

                try:
                    v = Version(pkg_version)
                    sv = Version(pkg_source_version)
                    packages.append(Package(pkg_name, v, pkg_source, sv))
                except ValueError as e:
                    logger.warning("Invalid version for package %s: %s", pkg_name, e)

    except Exception as e:
        logger.exception("Failed to parse status file: %s", e)

    logger.info("Found %d installed packages", len(packages))
    return packages
