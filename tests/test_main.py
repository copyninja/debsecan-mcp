import os
import subprocess
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from debvulns import main
from debvulns.main import detect_suite, list_vulnerabilities, research_cves
from tests.conftest import requires_debsecan


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

    def test_detect_suite_exception_on_read(self, monkeypatch, caplog):
        monkeypatch.delenv("DEBSECAN_SUITE", raising=False)
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", side_effect=Exception("Read error")):
                with pytest.raises(
                    RuntimeError, match="Debian suite could not be detected"
                ):
                    detect_suite()
                assert "Error reading /etc/os-release: Read error" in caplog.text


class TestListVulnerabilities:
    @pytest.mark.asyncio
    async def test_list_vulnerabilities_returns_dict(
        self, sample_packages, mock_vulnerability_feed, sample_epss_data
    ):
        with patch("debvulns.main.installed_packages", sample_packages):
            with patch("debvulns.main.vulnerability_feed", mock_vulnerability_feed):
                with patch("debvulns.main.epss_data", sample_epss_data):
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

        with patch("debvulns.main.installed_packages", sample_packages):
            with patch("debvulns.main.epss_data", sample_epss_data):
                mocker.patch(
                    "debvulns.main.vulnerability.fetch_data",
                    return_value=mock_vuln_feed,
                )

                result = await list_vulnerabilities(suite="bookworm")

                assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_list_vulnerabilities_no_vulns(self, sample_packages):
        with patch("debvulns.main.installed_packages", sample_packages):
            with patch("debvulns.main.vulnerability_feed", {}):
                with patch("debvulns.main.epss_data", {}):
                    # To hit the string return 'No vulnerabilities detected...', categorized must be empty.
                    with patch(
                        "debvulns.main.vulnerability.categorise_vulnerabilities",
                        return_value={},
                    ):
                        result = await list_vulnerabilities()

                        assert result == "No vulnerabilities detected on the system."

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

        with patch("debvulns.main.installed_packages", sample_packages):
            with patch("debvulns.main.vulnerability_feed", mock_feed):
                with patch("debvulns.main.epss_data", sample_epss_data):
                    result = await list_vulnerabilities()

                    cve_ids = []
                    for vulns in result.values():
                        cve_ids.extend(vulns)
                    assert cve_ids.count("CVE-2024-1234") == 1



    @pytest.mark.asyncio
    async def test_non_debian_packages_excluded_from_debian_scan(
        self, sample_packages, sample_non_debian_packages, sample_epss_data, mocker
    ):
        """Non-Debian packages must not be fed into the Debian Security Tracker loop."""
        all_packages = sample_packages + sample_non_debian_packages

        from debvulns.vulnerability import Vulnerability

        grafana_debian_vuln = MagicMock(spec=Vulnerability)
        grafana_debian_vuln.bug_id = "CVE-2021-39226"
        grafana_debian_vuln.package = "grafana"
        grafana_debian_vuln.is_vulnerable = MagicMock(return_value=True)

        mock_feed = {"grafana": [grafana_debian_vuln]}

        mocker.patch(
            "debvulns.main.osv.check_non_debian_packages",
            new_callable=AsyncMock,
            return_value=[],
        )

        with patch("debvulns.main.installed_packages", all_packages):
            with patch("debvulns.main.vulnerability_feed", mock_feed):
                with patch("debvulns.main.epss_data", sample_epss_data):
                    await list_vulnerabilities()

        # grafana is non-Debian so is_vulnerable should NOT have been called
        grafana_debian_vuln.is_vulnerable.assert_not_called()

    @pytest.mark.asyncio
    async def test_osv_results_merged_into_output(
        self, sample_packages, sample_non_debian_packages, sample_epss_data, mocker
    ):
        """OSV-confirmed vulnerabilities appear in the final output."""
        all_packages = sample_packages + sample_non_debian_packages

        osv_entry = {
            "cve": "CVE-2021-39226",
            "package": "grafana",
            "installed_version": "8.1.5",
            "urgency": "medium",
            "epss_score": 0.42,
            "epss_percentile": 0.87,
            "fix_available": "Yes",
            "remote": "Unknown",
            "description": "Grafana snapshot issue",
            "source": "osv.dev",
        }
        mocker.patch(
            "debvulns.main.osv.check_non_debian_packages",
            new_callable=AsyncMock,
            return_value=[osv_entry],
        )

        with patch("debvulns.main.installed_packages", all_packages):
            with patch("debvulns.main.vulnerability_feed", {}):
                with patch("debvulns.main.epss_data", sample_epss_data):
                    result = await list_vulnerabilities()

        all_cves: set[str] = set()
        for cves in result.values():
            all_cves.update(cves)

        assert "CVE-2021-39226" in all_cves

    @pytest.mark.asyncio
    async def test_osv_failure_does_not_crash(
        self, sample_packages, sample_non_debian_packages, sample_epss_data, mocker
    ):
        """A failure in OSV cross-check is logged but does not abort the scan."""
        all_packages = sample_packages + sample_non_debian_packages

        mocker.patch(
            "debvulns.main.osv.check_non_debian_packages",
            new_callable=AsyncMock,
            side_effect=Exception("OSV network failure"),
        )

        with patch("debvulns.main.installed_packages", all_packages):
            with patch("debvulns.main.vulnerability_feed", {}):
                with patch("debvulns.main.epss_data", sample_epss_data):
                    result = await list_vulnerabilities()

        assert isinstance(result, (dict, str))

class TestResearchCves:
    @pytest.mark.asyncio
    async def test_research_cves_found(self, sample_packages, mock_vulnerability_feed):
        with patch("debvulns.main.installed_packages", sample_packages):
            with patch("debvulns.main.vulnerability_feed", mock_vulnerability_feed):
                with patch("debvulns.main.epss_data", {}):
                    result = await research_cves(["CVE-2024-1234"])

                    assert isinstance(result, str)
                    assert "CVE-2024-1234" in result

    @pytest.mark.asyncio
    async def test_research_cves_not_found(self):
        with patch("debvulns.main.installed_packages", []):
            with patch("debvulns.main.vulnerability_feed", {}):
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

        with patch("debvulns.main.installed_packages", sample_packages):
            with patch("debvulns.main.vulnerability_feed", mock_feed):
                with patch("debvulns.main.epss_data", {}):
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

        with patch("debvulns.main.installed_packages", sample_packages):
            with patch("debvulns.main.vulnerability_feed", mock_feed):
                with patch("debvulns.main.epss_data", {}):
                    result = await research_cves(["CVE-2024-1234", "CVE-2024-5678"])

                    assert "CVE-2024-1234" in result
                    assert "CVE-2024-5678" in result


class TestDebsecanIntegration:
    @pytest.mark.asyncio
    @requires_debsecan
    async def test_list_vulnerabilities_matches_debsecan(self):
        try:
            result = subprocess.run(
                ["debsecan", "--suite", "bookworm"],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
        except subprocess.TimeoutExpired:
            pytest.skip("debsecan --suite timed out")

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


class TestCreateMcp:
    @patch("debvulns.main.FastMCP")
    def test_create_mcp_stdio(self, mock_fastmcp):
        main.create_mcp("stdio", "0.0.0.0", 8000, "/mcp")
        mock_fastmcp.assert_called_once_with("DebSecCan")

    @patch("debvulns.main.FastMCP")
    def test_create_mcp_sse(self, mock_fastmcp):
        main.create_mcp("sse", "127.0.0.1", 9000, "/test")
        mock_fastmcp.assert_called_once_with(
            "DebSecCan", host="127.0.0.1", port=9000, sse_path="/test"
        )

    @patch("debvulns.main.FastMCP")
    def test_create_mcp_streamable_http(self, mock_fastmcp):
        main.create_mcp("streamable-http", "127.0.0.1", 9000, "/test")
        mock_fastmcp.assert_called_once_with(
            "DebSecCan", host="127.0.0.1", port=9000, streamable_http_path="/test"
        )


class TestMain:
    @patch("debvulns.main.asyncio.get_event_loop")
    @patch("debvulns.main.create_mcp")
    @patch("sys.argv", ["main.py", "--transport", "stdio"])
    def test_main_stdio(self, mock_create_mcp, mock_get_loop):
        mock_mcp = MagicMock()
        mock_create_mcp.return_value = mock_mcp
        mock_loop = MagicMock()
        mock_get_loop.return_value = mock_loop

        main.main()

        mock_create_mcp.assert_called_once_with("stdio", "0.0.0.0", 8000, "/mcp")
        mock_mcp.run.assert_called_once_with(transport="stdio")
        mock_loop.run_until_complete.assert_called_once()

    @patch("debvulns.main.asyncio.get_event_loop")
    @patch("debvulns.main.create_mcp")
    @patch(
        "sys.argv",
        [
            "main.py",
            "--transport",
            "sse",
            "--host",
            "1.2.3.4",
            "--port",
            "1234",
            "--mount-path",
            "/sse",
        ],
    )
    def test_main_sse(self, mock_create_mcp, mock_get_loop):
        mock_mcp = MagicMock()
        mock_create_mcp.return_value = mock_mcp
        mock_loop = MagicMock()
        mock_get_loop.return_value = mock_loop

        main.main()

        mock_create_mcp.assert_called_once_with("sse", "1.2.3.4", 1234, "/sse")
        mock_mcp.run.assert_called_once_with(transport="sse")
        mock_loop.run_until_complete.assert_called_once()

    @patch("debvulns.main.asyncio.get_event_loop")
    @patch("debvulns.main.create_mcp")
    @patch("sys.argv", ["main.py", "--transport", "streamable-http"])
    def test_main_streamable_http(self, mock_create_mcp, mock_get_loop):
        mock_mcp = MagicMock()
        mock_create_mcp.return_value = mock_mcp
        mock_loop = MagicMock()
        mock_get_loop.return_value = mock_loop

        main.main()

        mock_create_mcp.assert_called_once_with(
            "streamable-http", "0.0.0.0", 8000, "/mcp"
        )
        mock_mcp.run.assert_called_once_with(transport="streamable-http")
        mock_loop.run_until_complete.assert_called_once()

    @patch("debvulns.main.asyncio.get_event_loop")
    @patch("debvulns.main.create_mcp")
    @patch("sys.argv", ["main.py"])
    def test_main_initialization_failure(self, mock_create_mcp, mock_get_loop, caplog):
        mock_mcp = MagicMock()
        mock_create_mcp.return_value = mock_mcp
        mock_loop = MagicMock()
        mock_get_loop.return_value = mock_loop
        mock_loop.run_until_complete.side_effect = Exception("Test init failure")

        main.main()

        mock_mcp.run.assert_not_called()
        assert (
            "Server failed to initialize and will not start: Test init failure"
            in caplog.text
        )


class TestInitialize:
    @patch("debvulns.main.epss.download_epss", new_callable=AsyncMock)
    @patch("debvulns.main.package.get_installed_packages")
    @patch("debvulns.main.detect_suite")
    @patch("debvulns.main.vulnerability.fetch_data", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_initialize_success(
        self, mock_fetch_data, mock_detect, mock_get_pkgs, mock_epss
    ):
        mock_detect.return_value = "bookworm"
        mock_fetch_data.return_value = {"bash": []}
        mock_get_pkgs.return_value = []
        mock_epss.return_value = {}

        await main.initialize()

        assert main.epss_data == {}
        assert main.installed_packages == []
        assert main.vulnerability_feed == {"bash": []}

    @patch("debvulns.main.epss.download_epss", new_callable=AsyncMock)
    @patch("debvulns.main.package.get_installed_packages")
    @patch("debvulns.main.detect_suite")
    @patch("debvulns.main.vulnerability.fetch_data", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_initialize_fallback_generic(
        self, mock_fetch_data, mock_detect, mock_get_pkgs, mock_epss
    ):
        mock_detect.return_value = "bookworm"
        mock_fetch_data.side_effect = [Exception("Feed error"), {"generic": []}]

        await main.initialize()

        assert main.vulnerability_feed == {"generic": []}
        mock_fetch_data.assert_any_call("bookworm")
        mock_fetch_data.assert_any_call("GENERIC")

    @patch("debvulns.main.epss.download_epss", new_callable=AsyncMock)
    @patch("debvulns.main.package.get_installed_packages")
    @patch("debvulns.main.detect_suite")
    @patch("debvulns.main.vulnerability.fetch_data", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_initialize_complete_failure(
        self, mock_fetch_data, mock_detect, mock_get_pkgs, mock_epss
    ):
        mock_detect.return_value = "bookworm"
        mock_fetch_data.side_effect = Exception("Total failure")

        with pytest.raises(
            RuntimeError, match="Could not fetch any vulnerability data"
        ):
            await main.initialize()

    @patch("debvulns.main.detect_suite")
    @pytest.mark.asyncio
    async def test_initialize_detect_suite_failure(self, mock_detect):
        mock_detect.side_effect = RuntimeError("No suite")

        with pytest.raises(RuntimeError, match="No suite"):
            await main.initialize()

    @patch("debvulns.main.epss.download_epss", new_callable=AsyncMock)
    @patch("debvulns.main.package.get_installed_packages")
    @patch("debvulns.main.detect_suite")
    @patch("debvulns.main.vulnerability.fetch_data", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_initialize_other_errors(
        self, mock_fetch_data, mock_detect, mock_get_pkgs, mock_epss, caplog
    ):
        mock_detect.return_value = "bookworm"
        mock_fetch_data.return_value = {}
        mock_epss.side_effect = Exception("EPSS fails")
        mock_get_pkgs.side_effect = Exception("Pkg fails")

        await main.initialize()

        assert "Failed to initialize EPSS data" in caplog.text
        assert "Failed to initialize installed packages" in caplog.text
