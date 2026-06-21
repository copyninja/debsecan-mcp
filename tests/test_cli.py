import contextlib
import csv
import json
import os
import subprocess
import sys
import tempfile
import time
from io import StringIO
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from debsecan_mcp import cli
from debsecan_mcp.package import Package, Version
from debsecan_mcp.vulnerability import Vulnerability
from tests.conftest import requires_debian, requires_debsecan



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


class TestDebsecanIntegration:
    @pytest.mark.asyncio
    @requires_debsecan
    @requires_debian
    async def test_debvulns_cves_are_subset_of_debsecan(self):
        """
        Validates that every CVE/TEMP ID reported by debvulns CLI is also known
        to the debsecan binary on the same system.

        Comparison strategy — unique vulnerability IDs (not package pairs):
        ---------------------------------------------------------------
        debsecan outputs one line per (ID, package) combination, e.g.:
            CVE-2024-1234 bash [flags]
            TEMP-0000000-3CAD20 somepackage [flags]

        We extract the *unique set of vulnerability IDs* from debsecan and
        compare that against the unique set of IDs in debvulns JSON output.
        IDs include both CVE-* and TEMP-* identifiers.

        Why not (ID, package) pairs?
        - debsecan's internal is_vulnerable() logic can differ from ours
          at the package-name matching level (binary vs source), producing
          thousands of false negatives that are expected and acceptable.
        - Comparing just vulnerability IDs answers the real question:
          "Does debvulns ever invent an ID that debsecan doesn't know about?"

        Assertion (one direction only):
            debvulns_ids ⊆ debsecan_ids

        i.e. debvulns must not report an ID absent from debsecan.
        The reverse (debsecan reporting more IDs than debvulns) is expected:
        debsecan includes low/negligible/no-urgency entries and uses its own
        version-matching logic, while debvulns fetches the Debian Security
        Tracker feed and applies our is_vulnerable() version comparisons.

        This test is skipped automatically on non-Debian systems and when the
        debsecan binary is not installed (e.g. GitHub CI). It runs locally.
        """
        # 1. Run debsecan and collect unique CVE IDs
        try:
            result = subprocess.run(
                ["debsecan"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            pytest.skip("debsecan timed out waiting for network")

        debsecan_ids: set[str] = set()
        for line in result.stdout.strip().splitlines():
            if not line:
                continue
            parts = line.split()
            # debsecan output format: <ID> package_name [flags...]
            # ID can be CVE-XXXX-XXXXX or TEMP-XXXXXXX-XXXXXX
            if parts and (parts[0].startswith("CVE-") or parts[0].startswith("TEMP-")):
                debsecan_ids.add(parts[0])

        if not debsecan_ids:
            pytest.skip("debsecan returned no vulnerabilities — nothing to compare")

        # 2. Run debvulns CLI with --no-cache and JSON output (all severities)
        stdout_capture = StringIO()
        with patch("sys.argv", ["debvulns", "--no-cache", "-f", "json"]):
            with contextlib.redirect_stdout(stdout_capture):
                await cli.async_main()

        output_data = json.loads(stdout_capture.getvalue())

        # 3. Collect unique vulnerability IDs from debvulns output
        #    JSON structure: {severity: [{cve: "CVE-...", package: "...", ...}, ...]}
        #    The "cve" field may contain CVE-* or TEMP-* identifiers.
        debvulns_ids: set[str] = set()
        for sev_vulns in output_data.values():
            for v in sev_vulns:
                debvulns_ids.add(v["cve"])

        # 4. Print a count summary (visible with pytest -s)
        print(
            f"\n[debsecan vs debvulns] "
            f"debsecan unique IDs: {len(debsecan_ids)}, "
            f"debvulns unique IDs: {len(debvulns_ids)}",
            file=sys.stderr,
        )

        # 5. Assert debvulns ⊆ debsecan — no invented IDs
        extra_in_debvulns = debvulns_ids - debsecan_ids
        assert len(extra_in_debvulns) == 0, (
            f"debvulns reported {len(extra_in_debvulns)} ID(s) "
            f"not found in debsecan output (possible false positives):\n"
            + "\n".join(f"  {vid}" for vid in sorted(extra_in_debvulns))
        )

        # 6. Informational: IDs debsecan knows about that debvulns didn't report.
        #    This is expected — debsecan includes low/negligible/unurgent entries
        #    that our version-comparison logic may resolve differently.
        missing_in_debvulns = debsecan_ids - debvulns_ids
        if missing_in_debvulns:
            print(
                f"[debsecan vs debvulns] "
                f"{len(missing_in_debvulns)} ID(s) in debsecan not reported by debvulns "
                f"(expected — urgency/version-match differences)",
                file=sys.stderr,
            )

