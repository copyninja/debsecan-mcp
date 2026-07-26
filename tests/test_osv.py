"""Tests for the osv.py module."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from debvulns.osv import (
    OsvVulnerability,
    _parse_osv_response,
    check_non_debian_packages,
    fetch_osv_vuln,
    is_version_affected,
)
from debvulns.package import Package, Version


# ---------------------------------------------------------------------------
# OsvVulnerability
# ---------------------------------------------------------------------------


class TestOsvVulnerability:
    def test_cvss_base_score_missing(self):
        """Returns 5.0 when no severity info is present."""
        v = OsvVulnerability(id="CVE-x", summary="", details="")
        assert v.cvss_base_score() == 5.0

    def test_urgency_from_cvss_high(self):
        """CVSS >= 7.0 maps to 'high'."""
        v = OsvVulnerability(
            id="CVE-x",
            summary="",
            details="",
            severity=[{"type": "CVSS_V3", "score": "...", "base_score": 7.5}],
        )
        assert v.urgency_from_cvss() == "high"

    def test_urgency_from_cvss_medium(self):
        """CVSS 4.0–6.9 maps to 'medium'."""
        v = OsvVulnerability(
            id="CVE-x",
            summary="",
            details="",
            severity=[{"type": "CVSS_V3", "score": "...", "base_score": 5.3}],
        )
        assert v.urgency_from_cvss() == "medium"

    def test_urgency_from_cvss_low(self):
        """CVSS < 4.0 maps to 'low'."""
        v = OsvVulnerability(
            id="CVE-x",
            summary="",
            details="",
            severity=[{"type": "CVSS_V3", "score": "...", "base_score": 2.1}],
        )
        assert v.urgency_from_cvss() == "low"

    def test_urgency_from_cvss_critical(self):
        """CVSS >= 9.0 also maps to 'high' (categoriser promotes it)."""
        v = OsvVulnerability(
            id="CVE-x",
            summary="",
            details="",
            severity=[{"type": "CVSS_V3", "score": "...", "base_score": 9.8}],
        )
        assert v.urgency_from_cvss() == "high"


# ---------------------------------------------------------------------------
# _parse_osv_response
# ---------------------------------------------------------------------------


class TestParseOsvResponse:
    def test_parse_basic(self, sample_osv_response):
        osv_vuln = _parse_osv_response(sample_osv_response)

        assert osv_vuln.id == "CVE-2021-39226"
        assert "snapshot" in osv_vuln.summary.lower()
        assert "GHSA-69j6-29vr-p3j9" in osv_vuln.aliases
        assert "v8.1.5" in osv_vuln.affected_versions
        assert "v7.5.10" in osv_vuln.affected_versions

    def test_parse_empty_affected(self):
        data = {
            "id": "CVE-9999-0001",
            "summary": "test",
            "details": "test details",
            "affected": [],
        }
        osv_vuln = _parse_osv_response(data)
        assert osv_vuln.affected_versions == []

    def test_parse_multiple_affected_blocks(self):
        data = {
            "id": "CVE-9999-0002",
            "summary": "multi",
            "details": "",
            "affected": [
                {"versions": ["1.0.0", "1.0.1"]},
                {"versions": ["2.0.0"]},
            ],
        }
        osv_vuln = _parse_osv_response(data)
        assert "1.0.0" in osv_vuln.affected_versions
        assert "2.0.0" in osv_vuln.affected_versions
        assert len(osv_vuln.affected_versions) == 3


# ---------------------------------------------------------------------------
# is_version_affected
# ---------------------------------------------------------------------------


class TestIsVersionAffected:
    def _make_vuln(self, versions: list[str]) -> OsvVulnerability:
        return OsvVulnerability(
            id="CVE-test",
            summary="",
            details="",
            affected_versions=versions,
        )

    def test_affected_version_with_v_prefix(self):
        """OSV uses 'v8.1.5', installed version is '8.1.5' → affected."""
        vuln = self._make_vuln(["v8.1.5", "v8.1.4"])
        assert is_version_affected("8.1.5", vuln) is True

    def test_affected_version_exact_match(self):
        """Both installed and OSV use same format."""
        vuln = self._make_vuln(["8.1.5", "8.1.4"])
        assert is_version_affected("8.1.5", vuln) is True

    def test_not_affected_newer_version(self):
        """Installed version 13.1.0 is not in affected list → not affected."""
        vuln = self._make_vuln(["v8.1.5", "v8.1.4", "v7.5.10"])
        assert is_version_affected("13.1.0", vuln) is False

    def test_not_affected_version_after_fix(self):
        """Fixed version 8.1.6 is not in affected list → not affected."""
        vuln = self._make_vuln(["v8.1.5", "v8.1.4"])
        assert is_version_affected("8.1.6", vuln) is False

    def test_empty_affected_versions_returns_false(self):
        """Empty versions list → always not affected."""
        vuln = self._make_vuln([])
        assert is_version_affected("1.0.0", vuln) is False

    def test_installed_with_v_prefix_matches_osv_plain(self):
        """Edge case: installed version has 'v' prefix, OSV doesn't."""
        vuln = self._make_vuln(["8.1.5"])
        assert is_version_affected("v8.1.5", vuln) is True


# ---------------------------------------------------------------------------
# fetch_osv_vuln
# ---------------------------------------------------------------------------


class TestFetchOsvVuln:
    @pytest.mark.asyncio
    async def test_returns_vuln_on_success(self, sample_osv_response):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = sample_osv_response
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await fetch_osv_vuln("CVE-2021-39226", client=mock_client)

        assert result is not None
        assert result.id == "CVE-2021-39226"
        assert "v8.1.5" in result.affected_versions

    @pytest.mark.asyncio
    async def test_returns_none_on_404(self):
        mock_response = MagicMock()
        mock_response.status_code = 404

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await fetch_osv_vuln("CVE-9999-9999", client=mock_client)
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_when_no_affected_versions(self):
        """OSV record with no versions list → returns None (can't cross-check)."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "CVE-9999-0001",
            "summary": "test",
            "details": "no versions",
            "affected": [{"ranges": []}],
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await fetch_osv_vuln("CVE-9999-0001", client=mock_client)
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_on_network_error(self):
        import httpx

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))

        result = await fetch_osv_vuln("CVE-2021-39226", client=mock_client)
        assert result is None


# ---------------------------------------------------------------------------
# check_non_debian_packages
# ---------------------------------------------------------------------------


class TestCheckNonDebianPackages:
    @pytest.mark.asyncio
    async def test_grafana_affected_version_detected(
        self, sample_non_debian_packages, sample_osv_response
    ):
        """Grafana 8.1.5 is in OSV affected list → should be reported."""
        # Build a minimal Debian feed entry for grafana + CVE-2021-39226
        from debvulns.vulnerability import Vulnerability

        grafana_vuln = Vulnerability(
            bug_id="CVE-2021-39226",
            package="grafana",
            description="Grafana snapshot vulnerability",
            unstable_version="",
            other_versions=[],
            is_binary=False,
            urgency="H",
            remote=True,
            fix_available=False,
        )
        vuln_feed = {"grafana": [grafana_vuln]}
        epss_data = {"CVE-2021-39226": {"score": 0.42, "percentile": 0.87}}

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = sample_osv_response
        mock_response.raise_for_status = MagicMock()

        with patch("debvulns.osv.httpx.AsyncClient") as mock_client_cls:
            mock_client_instance = AsyncMock()
            mock_client_instance.get = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value.__aenter__ = AsyncMock(
                return_value=mock_client_instance
            )
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=None)

            results = await check_non_debian_packages(
                sample_non_debian_packages, vuln_feed, epss_data
            )

        assert len(results) == 1
        assert results[0]["cve"] == "CVE-2021-39226"
        assert results[0]["package"] == "grafana"
        assert results[0]["epss_score"] == 0.42
        assert results[0]["source"] == "osv.dev"

    @pytest.mark.asyncio
    async def test_grafana_fixed_version_not_reported(self, sample_osv_response):
        """Grafana 13.1.0 is NOT in OSV affected list → should NOT be reported."""
        from debvulns.package import Package, Version
        from debvulns.vulnerability import Vulnerability

        fixed_grafana = [
            Package("grafana", Version("13.1.0"), "grafana", Version("13.1.0"), origin="", archive="now")
        ]

        grafana_vuln = Vulnerability(
            bug_id="CVE-2021-39226",
            package="grafana",
            description="Grafana snapshot vulnerability",
            unstable_version="",
            other_versions=[],
            is_binary=False,
            urgency="H",
            remote=True,
            fix_available=False,
        )
        vuln_feed = {"grafana": [grafana_vuln]}
        epss_data = {}

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = sample_osv_response
        mock_response.raise_for_status = MagicMock()

        with patch("debvulns.osv.httpx.AsyncClient") as mock_client_cls:
            mock_client_instance = AsyncMock()
            mock_client_instance.get = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value.__aenter__ = AsyncMock(
                return_value=mock_client_instance
            )
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=None)

            results = await check_non_debian_packages(fixed_grafana, vuln_feed, epss_data)

        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_no_debian_feed_entry_skipped(self, sample_non_debian_packages):
        """Package with no Debian feed entry → no OSV calls, no results."""
        vuln_feed: dict = {}  # grafana not in feed at all
        epss_data: dict = {}

        with patch("debvulns.osv.fetch_osv_vuln", new_callable=AsyncMock) as mock_fetch:
            results = await check_non_debian_packages(
                sample_non_debian_packages, vuln_feed, epss_data
            )

        mock_fetch.assert_not_called()
        assert results == []

    @pytest.mark.asyncio
    async def test_osv_no_data_for_cve_skipped(self, sample_non_debian_packages):
        """OSV returns None for a CVE → skip without reporting."""
        from debvulns.vulnerability import Vulnerability

        grafana_vuln = Vulnerability(
            bug_id="CVE-2099-9999",
            package="grafana",
            description="Unknown future CVE",
            unstable_version="",
            other_versions=[],
            is_binary=False,
            urgency="H",
            remote=True,
            fix_available=False,
        )
        vuln_feed = {"grafana": [grafana_vuln]}

        with patch(
            "debvulns.osv.fetch_osv_vuln", new_callable=AsyncMock, return_value=None
        ):
            results = await check_non_debian_packages(
                sample_non_debian_packages, vuln_feed, {}
            )

        assert results == []

    @pytest.mark.asyncio
    async def test_empty_non_debian_list(self):
        """No non-Debian packages → returns empty list without any API calls."""
        with patch("debvulns.osv.fetch_osv_vuln", new_callable=AsyncMock) as mock_fetch:
            results = await check_non_debian_packages([], {}, {})

        mock_fetch.assert_not_called()
        assert results == []
