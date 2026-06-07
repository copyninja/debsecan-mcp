import csv
import json
import os
import sys
import tempfile
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from debsecan_mcp import cli
from debsecan_mcp.package import Package, Version
from debsecan_mcp.vulnerability import Vulnerability


@pytest.fixture
def sample_packages():
    return [
        Package("bash", Version("5.2-2"), "bash", Version("5.2-2")),
        Package("openssl", Version("3.0.16-1"), "openssl", Version("3.0.16-1")),
    ]


@pytest.fixture
def sample_vulnerabilities():
    return [
        Vulnerability(
            bug_id="CVE-2024-1234",
            package="bash",
            description="Bash vulnerability",
            unstable_version="5.2-3",
            other_versions=[],
            is_binary=False,
            urgency="H",
            remote=True,
            fix_available=True,
        ),
        Vulnerability(
            bug_id="CVE-2024-5678",
            package="openssl",
            description="OpenSSL vulnerability",
            unstable_version="3.0.17",
            other_versions=[],
            is_binary=True,
            urgency="H",
            remote=True,
            fix_available=True,
        ),
    ]


@pytest.fixture
def sample_epss_data():
    return {
        "CVE-2024-1234": {"score": 0.25, "percentile": 0.95},
        "CVE-2024-5678": {"score": 0.20, "percentile": 0.75},
    }


def test_serialization_deserialization(sample_vulnerabilities):
    feed = {"bash": sample_vulnerabilities}
    serialized = cli.serialize_vulnerabilities(feed)
    assert "bash" in serialized
    assert len(serialized["bash"]) == 2
    assert serialized["bash"][0]["bug_id"] == "CVE-2024-1234"

    deserialized = cli.deserialize_vulnerabilities(serialized)
    assert "bash" in deserialized
    assert len(deserialized["bash"]) == 2
    vuln = deserialized["bash"][0]
    assert isinstance(vuln, Vulnerability)
    assert vuln.bug_id == "CVE-2024-1234"
    assert str(vuln.unstable_version) == "5.2-3"


def test_get_cache_dir_success():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = cli.get_cache_dir(tmpdir)
        assert path == tmpdir


def test_get_cache_dir_fallback():
    # Provide a directory path that is not writable.
    # To mock this, we can patch os.makedirs to raise PermissionError
    # for the first path but succeed for the fallback ~/.cache/debvulns
    original_makedirs = os.makedirs
    
    def mock_makedirs(name, mode=0o777, exist_ok=False):
        if "/unwritable" in name:
            raise PermissionError("Unwritable directory")
        return original_makedirs(name, mode, exist_ok)

    with patch("os.makedirs", side_effect=mock_makedirs):
        with patch("builtins.open", MagicMock()):
            with patch("os.remove", MagicMock()):
                path = cli.get_cache_dir("/unwritable/debvulns")
                # Should fall back to ~/.cache/debvulns
                assert path == os.path.expanduser("~/.cache/debvulns")


def test_is_cache_valid():
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"data")
        tmp_name = tmp.name

    try:
        assert cli.is_cache_valid(tmp_name) is True

        # set back in time > 24 hours (25 hours ago)
        past_time = time.time() - 25 * 3600
        os.utime(tmp_name, (past_time, past_time))
        assert cli.is_cache_valid(tmp_name) is False
    finally:
        os.remove(tmp_name)

    assert cli.is_cache_valid("/nonexistent_file") is False


def test_format_vuln_dict(sample_vulnerabilities):
    v = sample_vulnerabilities[0]
    v.epss_score = 0.85
    v.epss_percentile = 0.95
    v.installed_package = "bash"
    v.installed_version = "5.2-2"

    formatted = cli.format_vuln_dict(v, "high")
    assert formatted["cve"] == "CVE-2024-1234"
    assert formatted["package"] == "bash"
    assert formatted["severity"] == "high"
    assert formatted["installed_version"] == "5.2-2"
    assert formatted["fixed_version"] == "5.2-3"
    assert formatted["epss_score"] == 0.85
    assert formatted["epss_percentile"] == 0.95
    assert formatted["fix_available"] == "Yes"
    assert formatted["remote"] == "Yes"
    assert "Bash vulnerability" in formatted["description"]


def test_write_csv(capsys):
    vulns = [
        {
            "cve": "CVE-2024-1234",
            "package": "bash",
            "severity": "high",
            "installed_version": "5.2-2",
            "fixed_version": "5.2-3",
            "epss_score": 0.85,
            "epss_percentile": 0.95,
            "fix_available": "Yes",
            "remote": "Yes",
            "description": "Bash vulnerability",
        }
    ]
    cli.write_csv(vulns)
    captured = capsys.readouterr()
    lines = captured.out.strip().split("\n")
    assert len(lines) == 2
    assert "CVE,Package,Severity" in lines[0]
    
    # Read as CSV
    reader = csv.reader(lines)
    header = next(reader)
    row = next(reader)
    assert row[0] == "CVE-2024-1234"
    assert row[1] == "bash"
    assert row[2] == "high"
    assert row[5] == "0.8500"
    assert row[6] == "95.00%"


@pytest.mark.asyncio
@patch("debsecan_mcp.cli.detect_suite", return_value="bookworm")
@patch("debsecan_mcp.cli.epss.download_epss", new_callable=AsyncMock)
@patch("debsecan_mcp.cli.vulnerability.fetch_data", new_callable=AsyncMock)
@patch("debsecan_mcp.cli.package.get_installed_packages")
async def test_async_main_json_no_filter(
    mock_get_pkgs, mock_fetch_data, mock_download_epss, mock_detect, capsys, sample_packages, sample_vulnerabilities, sample_epss_data, mock_apt_pkg
):
    mock_get_pkgs.return_value = sample_packages
    feed = {}
    for v in sample_vulnerabilities:
        feed[v.package] = [v]
    mock_fetch_data.return_value = feed
    mock_download_epss.return_value = sample_epss_data

    # run with --no-cache to avoid disk interactions
    test_args = ["debvulns", "--no-cache", "-f", "json"]
    with patch("sys.argv", test_args):
        await cli.async_main()

    captured = capsys.readouterr()
    output_data = json.loads(captured.out)
    assert isinstance(output_data, dict)
    assert "high" in output_data
    assert len(output_data["high"]) == 2
    assert output_data["high"][0]["cve"] in ["CVE-2024-1234", "CVE-2024-5678"]


@pytest.mark.asyncio
@patch("debsecan_mcp.cli.detect_suite", return_value="bookworm")
@patch("debsecan_mcp.cli.epss.download_epss", new_callable=AsyncMock)
@patch("debsecan_mcp.cli.vulnerability.fetch_data", new_callable=AsyncMock)
@patch("debsecan_mcp.cli.package.get_installed_packages")
async def test_async_main_severity_filter(
    mock_get_pkgs, mock_fetch_data, mock_download_epss, mock_detect, capsys, sample_packages, sample_vulnerabilities, sample_epss_data, mock_apt_pkg
):
    mock_get_pkgs.return_value = sample_packages
    feed = {}
    for v in sample_vulnerabilities:
        feed[v.package] = [v]
    mock_fetch_data.return_value = feed
    mock_download_epss.return_value = sample_epss_data

    test_args = ["debvulns", "--no-cache", "-f", "json", "--severity", "high"]
    with patch("sys.argv", test_args):
        await cli.async_main()

    captured = capsys.readouterr()
    output_data = json.loads(captured.out)
    # When filtered, outputs a flat list of that severity
    assert isinstance(output_data, list)
    assert len(output_data) == 2
    assert output_data[0]["severity"] == "high"


@pytest.mark.asyncio
@patch("debsecan_mcp.cli.detect_suite", return_value="bookworm")
@patch("debsecan_mcp.cli.epss.download_epss", new_callable=AsyncMock)
@patch("debsecan_mcp.cli.vulnerability.fetch_data", new_callable=AsyncMock)
@patch("debsecan_mcp.cli.package.get_installed_packages")
async def test_async_main_csv(
    mock_get_pkgs, mock_fetch_data, mock_download_epss, mock_detect, capsys, sample_packages, sample_vulnerabilities, sample_epss_data, mock_apt_pkg
):
    mock_get_pkgs.return_value = sample_packages
    feed = {}
    for v in sample_vulnerabilities:
        feed[v.package] = [v]
    mock_fetch_data.return_value = feed
    mock_download_epss.return_value = sample_epss_data

    test_args = ["debvulns", "--no-cache", "-f", "csv"]
    with patch("sys.argv", test_args):
        await cli.async_main()

    captured = capsys.readouterr()
    lines = captured.out.strip().split("\n")
    assert len(lines) == 3  # Header + 2 vulns
    assert lines[0].startswith("CVE,Package,Severity")


@pytest.mark.asyncio
@patch("debsecan_mcp.cli.detect_suite", return_value="bookworm")
@patch("debsecan_mcp.cli.epss.download_epss", new_callable=AsyncMock)
@patch("debsecan_mcp.cli.vulnerability.fetch_data", new_callable=AsyncMock)
@patch("debsecan_mcp.cli.package.get_installed_packages")
async def test_async_main_caching_flow(
    mock_get_pkgs, mock_fetch_data, mock_download_epss, mock_detect, sample_packages, sample_vulnerabilities, sample_epss_data, mock_apt_pkg
):
    mock_get_pkgs.return_value = sample_packages
    feed = {}
    for v in sample_vulnerabilities:
        feed[v.package] = [v]
    mock_fetch_data.return_value = feed
    mock_download_epss.return_value = sample_epss_data

    with tempfile.TemporaryDirectory() as tmpdir:
        test_args = ["debvulns", "--cache-dir", tmpdir]
        
        # First execution (downloads and populates cache)
        with patch("sys.argv", test_args):
            await cli.async_main()
        
        assert mock_fetch_data.call_count == 1
        assert mock_download_epss.call_count == 1

        # Verify cache files created
        assert os.path.exists(os.path.join(tmpdir, "epss.json"))
        assert os.path.exists(os.path.join(tmpdir, "vulnerabilities_bookworm.json"))

        # Second execution (should load from cache, not fetch/download again)
        with patch("sys.argv", test_args):
            await cli.async_main()

        assert mock_fetch_data.call_count == 1
        assert mock_download_epss.call_count == 1


def test_sort_vulnerabilities():
    vulns = [
        {"cve": "CVE-2024-5678", "package": "openssl"},
        {"cve": "CVE-2024-1234", "package": "bash"},
    ]
    # Sort by package
    sorted_pkg = cli.sort_vulnerabilities(vulns, "package")
    assert sorted_pkg[0]["package"] == "bash"
    assert sorted_pkg[1]["package"] == "openssl"

    # Sort by CVE
    sorted_cve = cli.sort_vulnerabilities(vulns, "cve")
    assert sorted_cve[0]["cve"] == "CVE-2024-1234"
    assert sorted_cve[1]["cve"] == "CVE-2024-5678"

    # Sort by None
    sorted_none = cli.sort_vulnerabilities(vulns, None)
    assert sorted_none == vulns


@pytest.mark.asyncio
@patch("debsecan_mcp.cli.detect_suite", return_value="bookworm")
@patch("debsecan_mcp.cli.epss.download_epss", new_callable=AsyncMock)
@patch("debsecan_mcp.cli.vulnerability.fetch_data", new_callable=AsyncMock)
@patch("debsecan_mcp.cli.package.get_installed_packages")
async def test_async_main_sorting(
    mock_get_pkgs, mock_fetch_data, mock_download_epss, mock_detect, capsys, sample_packages, sample_vulnerabilities, sample_epss_data, mock_apt_pkg
):
    mock_get_pkgs.return_value = sample_packages
    feed = {}
    for v in sample_vulnerabilities:
        feed[v.package] = [v]
    mock_fetch_data.return_value = feed
    mock_download_epss.return_value = sample_epss_data

    # Test sorting by CVE via CLI flag
    test_args = ["debvulns", "--no-cache", "-f", "json", "--sort-by", "cve"]
    with patch("sys.argv", test_args):
        await cli.async_main()

    captured = capsys.readouterr()
    output_data = json.loads(captured.out)
    high_vulns = output_data["high"]
    assert high_vulns[0]["cve"] == "CVE-2024-1234"
    assert high_vulns[1]["cve"] == "CVE-2024-5678"
