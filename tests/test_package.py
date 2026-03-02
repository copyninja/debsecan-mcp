from unittest.mock import MagicMock

import pytest

from debsecan_mcp.package import Package, Version, get_installed_packages


class TestVersion:
    def test_version_creation(self):
        v = Version("1.0.0")
        assert v.version == "1.0.0"

    def test_version_str(self):
        v = Version("2.0-1")
        assert str(v) == "2.0-1"

    def test_version_repr(self):
        v = Version("1.0.0")
        assert repr(v) == "Version('1.0.0')"

    def test_version_comparison_greater(self):
        v1 = Version("2.0.0")
        v2 = Version("1.0.0")
        assert v1 > v2

    def test_version_comparison_less(self):
        v1 = Version("1.0.0")
        v2 = Version("2.0.0")
        assert v1 < v2

    def test_version_comparison_equal(self):
        v1 = Version("1.0.0")
        v2 = Version("1.0.0")
        assert v1 == v2

    def test_version_comparison_greater_equal(self):
        v1 = Version("2.0.0")
        v2 = Version("1.0.0")
        assert v1 >= v2
        v3 = Version("1.0.0")
        assert v3 >= Version("1.0.0")

    def test_version_comparison_less_equal(self):
        v1 = Version("1.0.0")
        v2 = Version("2.0.0")
        assert v1 <= v2
        v3 = Version("1.0.0")
        assert v3 <= Version("1.0.0")

    def test_version_comparison_not_equal(self):
        v1 = Version("1.0.0")
        v2 = Version("2.0.0")
        assert v1 != v2

    def test_version_comparison_with_string(self):
        v = Version("2.0.0")
        assert v > "1.0.0"
        assert v < "3.0.0"
        assert v == "2.0.0"


class TestPackage:
    def test_package_creation(self):
        v = Version("1.0.0")
        pkg = Package("testpkg", v)
        assert pkg.name == "testpkg"
        assert pkg.version == v
        assert pkg.source == "testpkg"
        assert pkg.source_version == v

    def test_package_with_source(self):
        v = Version("1.0.0")
        sv = Version("1.0.0")
        pkg = Package("testpkg-bin", v, "testpkg", sv)
        assert pkg.name == "testpkg-bin"
        assert pkg.source == "testpkg"
        assert pkg.source_version == sv

    def test_package_repr(self):
        v = Version("1.0.0")
        pkg = Package("testpkg", v)
        assert "testpkg" in repr(pkg)
        assert "1.0.0" in repr(pkg)


class TestGetInstalledPackages:
    @pytest.mark.usefixtures("mock_apt_pkg")
    def test_get_installed_packages_returns_list(self, mocker):
        mock_cache = MagicMock()
        mock_pkg = MagicMock()
        mock_pkg.current_ver = MagicMock()
        mock_pkg.current_ver.ver_str = "1.0.0"
        mock_pkg.current_ver.file_list = [(MagicMock(), 0)]
        mock_pkg.name = "testpkg"

        mock_records = MagicMock()
        mock_records.source_pkg = "testpkg"
        mock_records.source_ver = "1.0.0"
        mock_records.lookup = MagicMock()

        mock_cache.packages = [mock_pkg]
        mocker.patch("debsecan_mcp.package.apt_pkg.Cache", return_value=mock_cache)
        mocker.patch(
            "debsecan_mcp.package.apt_pkg.PackageRecords", return_value=mock_records
        )

        packages = get_installed_packages()
        assert isinstance(packages, list)
        assert len(packages) == 1
        assert packages[0].name == "testpkg"
