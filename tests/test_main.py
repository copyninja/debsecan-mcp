import os
import subprocess
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from debsecan_mcp import main
from debsecan_mcp.main import detect_suite, list_vulnerabilities, research_cves


def is_debsecan_available():
    try:
        subprocess.run(["debsecan", "--help"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


requires_debsecan = pytest.mark.skipif(
    not is_debsecan_available(), reason="debsecan binary not found"
)


class TestDetectSuite:
    def test_detect_suite_from_env(self, monkeypatch):
        monkeypatch.setenv("DEBSECAN_SUITE", "bookworm")
        assert detect_suite() == "bookworm"

    def test_detect_suite_from_os_release(self, monkeypatch):
        monkeypatch.delenv("DEBSECAN_SUITE", raising=False)

        os_release_content = 'VERSION_CODENAME="bookworm"\n'

        with patch("os.path.exists", return_value=True):
            with patch(
                "builtins.open",
                MagicMock(
                    return_value=MagicMock(
                        __enter__=MagicMock(
                            return_value=MagicMock(
                                __iter__=lambda self: iter([os_release_content])
                            )
                        ),
                        __exit__=MagicMock(return_value=None),
                    )
                ),
            ):
                suite = detect_suite()
                assert suite == "bookworm"

    def test_detect_suite_sid_from_pretty_name(self, monkeypatch):
        monkeypatch.delenv("DEBSECAN_SUITE", raising=False)

        os_release_content = (
            'PRETTY_NAME="Debian GNU/Linux sid"\nVERSION="Debian GNU/Linux sid"\n'
        )

        with patch("os.path.exists", return_value=True):
            with patch(
                "builtins.open",
                MagicMock(
                    return_value=MagicMock(
                        __enter__=MagicMock(
                            return_value=MagicMock(
                                __iter__=lambda self: iter([os_release_content])
                            )
                        ),
                        __exit__=MagicMock(return_value=None),
                    )
                ),
            ):
                suite = detect_suite()
                assert suite == "sid"

    def test_detect_suite_raises_when_unable(self, monkeypatch):
        monkeypatch.delenv("DEBSECAN_SUITE", raising=False)
        with patch("os.path.exists", return_value=False):
            with pytest.raises(
                RuntimeError, match="Debian suite could not be detected"
            ):
                detect_suite()


class TestListVulnerabilities:
    @pytest.mark.asyncio
    async def test_list_vulnerabilities_returns_dict(
        self, sample_packages, mock_vulnerability_feed, sample_epss_data
    ):
        with patch("debsecan_mcp.main.installed_packages", sample_packages):
            with patch("debsecan_mcp.main.vulnerability_feed", mock_vulnerability_feed):
                with patch("debsecan_mcp.main.epss_data", sample_epss_data):
                    result = await list_vulnerabilities()

                    assert isinstance(result, dict)
                    for category in ["critical", "high", "medium", "low", "negligible"]:
                        assert category in result or category in result

    @pytest.mark.asyncio
    async def test_list_vulnerabilities_with_specific_suite(
        self, mocker, sample_packages, sample_epss_data
    ):
        mock_vuln_feed = {
            "bash": [
                MagicMock(
                    bug_id="CVE-2024-1234",
                    package="bash",
                    is_vulnerable=MagicMock(return_value=True),
                )
            ]
        }

        with patch("debsecan_mcp.main.installed_packages", sample_packages):
            with patch("debsecan_mcp.main.epss_data", sample_epss_data):
                mocker.patch(
                    "debsecan_mcp.main.vulnerability.fetch_data",
                    return_value=mock_vuln_feed,
                )

                result = await list_vulnerabilities(suite="bookworm")

                assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_list_vulnerabilities_no_vulns(self, sample_packages):
        with patch("debsecan_mcp.main.installed_packages", sample_packages):
            with patch("debsecan_mcp.main.vulnerability_feed", {}):
                with patch("debsecan_mcp.main.epss_data", {}):
                    result = await list_vulnerabilities()

                    assert isinstance(result, dict)
                    for category in ["critical", "high", "medium", "low", "negligible"]:
                        assert category in result
                        assert result[category] == []

    @pytest.mark.asyncio
    async def test_list_vulnerabilities_deduplication(
        self, sample_packages, sample_epss_data
    ):
        vuln1 = MagicMock()
        vuln1.bug_id = "CVE-2024-1234"
        vuln1.package = "bash"
        vuln1.installed_package = "bash"
        vuln1.is_vulnerable = MagicMock(return_value=True)
        vuln1.epss_score = 0.5
        vuln1.epss_percentile = 0.5

        vuln2 = MagicMock()
        vuln2.bug_id = "CVE-2024-1234"
        vuln2.package = "bash"
        vuln2.installed_package = "bash"
        vuln2.is_vulnerable = MagicMock(return_value=True)
        vuln2.epss_score = 0.5
        vuln2.epss_percentile = 0.5

        mock_feed = {"bash": [vuln1, vuln2]}

        with patch("debsecan_mcp.main.installed_packages", sample_packages):
            with patch("debsecan_mcp.main.vulnerability_feed", mock_feed):
                with patch("debsecan_mcp.main.epss_data", sample_epss_data):
                    result = await list_vulnerabilities()

                    cve_ids = []
                    for vulns in result.values():
                        cve_ids.extend(vulns)
                    assert cve_ids.count("CVE-2024-1234") == 1


class TestResearchCves:
    @pytest.mark.asyncio
    async def test_research_cves_found(self, sample_packages, mock_vulnerability_feed):
        with patch("debsecan_mcp.main.installed_packages", sample_packages):
            with patch("debsecan_mcp.main.vulnerability_feed", mock_vulnerability_feed):
                with patch("debsecan_mcp.main.epss_data", {}):
                    result = await research_cves(["CVE-2024-1234"])

                    assert isinstance(result, str)
                    assert "CVE-2024-1234" in result

    @pytest.mark.asyncio
    async def test_research_cves_not_found(self):
        with patch("debsecan_mcp.main.installed_packages", []):
            with patch("debsecan_mcp.main.vulnerability_feed", {}):
                result = await research_cves(["CVE-9999-9999"])

                assert isinstance(result, str)
                assert "No detailed information found" in result

    @pytest.mark.asyncio
    async def test_research_cves_uppercase_normalization(self, sample_packages):
        mock_vuln = MagicMock()
        mock_vuln.bug_id = "CVE-2024-1234"
        mock_vuln.package = "bash"
        mock_vuln.urgency = "high"
        mock_vuln.fix_available = True
        mock_vuln.remote = True
        mock_vuln.description = "Test description"

        mock_feed = {"bash": [mock_vuln]}

        with patch("debsecan_mcp.main.installed_packages", sample_packages):
            with patch("debsecan_mcp.main.vulnerability_feed", mock_feed):
                with patch("debsecan_mcp.main.epss_data", {}):
                    result = await research_cves(["cve-2024-1234"])

                    assert "CVE-2024-1234" in result

    @pytest.mark.asyncio
    async def test_research_cves_multiple(self, sample_packages):
        mock_vuln1 = MagicMock()
        mock_vuln1.bug_id = "CVE-2024-1234"
        mock_vuln1.package = "bash"
        mock_vuln1.urgency = "high"
        mock_vuln1.fix_available = True
        mock_vuln1.remote = True
        mock_vuln1.description = "Test description 1"

        mock_vuln2 = MagicMock()
        mock_vuln2.bug_id = "CVE-2024-5678"
        mock_vuln2.package = "bash"
        mock_vuln2.urgency = "medium"
        mock_vuln2.fix_available = True
        mock_vuln2.remote = True
        mock_vuln2.description = "Test description 2"

        mock_feed = {"bash": [mock_vuln1, mock_vuln2]}

        with patch("debsecan_mcp.main.installed_packages", sample_packages):
            with patch("debsecan_mcp.main.vulnerability_feed", mock_feed):
                with patch("debsecan_mcp.main.epss_data", {}):
                    result = await research_cves(["CVE-2024-1234", "CVE-2024-5678"])

                    assert "CVE-2024-1234" in result
                    assert "CVE-2024-5678" in result


class TestDebsecanIntegration:
    @pytest.mark.asyncio
    @requires_debsecan
    async def test_list_vulnerabilities_matches_debsecan(self):
        result = subprocess.run(
            ["debsecan", "--suite", "bookworm"],
            capture_output=True,
            text=True,
            check=True,
        )
        debsecan_cves = set()
        for line in result.stdout.strip().split("\n"):
            if line:
                cve = line.split()[0]
                if cve.startswith("CVE-"):
                    debsecan_cves.add(cve)

        main.epss_data = {}
        main.vulnerability_feed = await main.vulnerability.fetch_data("bookworm")

        our_result = await list_vulnerabilities(suite="bookworm")

        our_cves = set()
        for cves in our_result.values():
            our_cves.update(cves)

        extra_in_ours = our_cves - debsecan_cves

        assert len(extra_in_ours) == 0, (
            f"Extra CVEs in our output not in debsecan: {extra_in_ours}"
        )
