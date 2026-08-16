import os
import platform
import subprocess
from unittest.mock import MagicMock, AsyncMock

import pytest


def is_debian():
    if not platform.system().lower().startswith("linux"):
        return False
    try:
        with open("/etc/debian_version", "r"):
            return True
    except (FileNotFoundError, PermissionError):
        return False


requires_debian = pytest.mark.skipif(
    not is_debian(), reason="Test requires a Debian-based system"
)


def is_debsecan_available():
    try:
        subprocess.run(
            ["debsecan", "--help"], capture_output=True, check=True, timeout=2
        )
        return True
    except (
        subprocess.CalledProcessError,
        FileNotFoundError,
        subprocess.TimeoutExpired,
    ):
        return False


requires_debsecan = pytest.mark.skipif(
    not is_debsecan_available(), reason="debsecan binary not found"
)


@pytest.fixture
def mock_apt_pkg(mocker):
    mock = MagicMock()
    mock.version_compare = lambda a, b: (1 if a > b else (-1 if a < b else 0))
    mocker.patch("debvulns.package.apt_pkg", mock)
    mocker.patch("debvulns.package._has_apt_pkg", True)
    mocker.patch("debvulns.package.version_compare", mock.version_compare)
    return mock


@pytest.fixture
def sample_packages():
    from debvulns.package import Package, Version

    return [
        Package("bash", Version("5.2-2"), "bash", Version("5.2-2"), origin="Debian", archive="unstable"),
        Package("openssl", Version("3.0.16-1"), "openssl", Version("3.0.16-1"), origin="Debian", archive="unstable"),
        Package("curl", Version("8.5.0-1"), "curl", Version("8.5.0-1"), origin="Debian", archive="unstable"),
    ]


@pytest.fixture
def sample_non_debian_packages():
    """Packages installed from third-party repos (e.g. grafana.com APT repo)."""
    from debvulns.package import Package, Version

    return [
        Package("grafana", Version("8.1.5"), "grafana", Version("8.1.5"), origin="", archive="now"),
    ]


@pytest.fixture
def sample_osv_response():
    """Minimal OSV API response for CVE-2021-39226 (Grafana snapshot vulnerability)."""
    return {
        "id": "CVE-2021-39226",
        "summary": "Grafana snapshot vulnerability",
        "details": "Unauthenticated users can view snapshots with lowest database key.",
        "aliases": ["GHSA-69j6-29vr-p3j9"],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"}],
        "affected": [
            {
                "versions": [
                    "v8.1.5", "v8.1.4", "v8.1.3", "v8.1.2", "v8.1.1",
                    "v7.5.10", "v7.5.9", "v7.5.8",
                ],
                "ranges": [],
            }
        ],
    }


@pytest.fixture
def sample_vulnerabilities():
    from debvulns.vulnerability import Vulnerability

    return [
        Vulnerability(
            bug_id="CVE-2024-1234",
            package="bash",
            description="Bash command injection vulnerability",
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
            description="OpenSSL buffer overflow",
            unstable_version="3.0.17",
            other_versions=[],
            is_binary=True,
            urgency="H",
            remote=True,
            fix_available=True,
        ),
        Vulnerability(
            bug_id="CVE-2024-9999",
            package="curl",
            description="CURL information disclosure",
            unstable_version="",
            other_versions=["8.5.0-2"],
            is_binary=True,
            urgency="M",
            remote=True,
            fix_available=False,
        ),
    ]


@pytest.fixture
def sample_epss_data():
    return {
        "CVE-2024-1234": {"score": 0.85, "percentile": 0.95},
        "CVE-2024-5678": {"score": 0.45, "percentile": 0.75},
        "CVE-2024-9999": {"score": 0.12, "percentile": 0.30},
    }


@pytest.fixture
def mock_vulnerability_feed(sample_vulnerabilities):
    feed = {}
    for vuln in sample_vulnerabilities:
        if vuln.package not in feed:
            feed[vuln.package] = []
        feed[vuln.package].append(vuln)
    return feed


@pytest.fixture
def mock_http_response():
    def _create_response(content, status_code=200):
        response = MagicMock()
        response.status_code = status_code
        response.content = content
        response.raise_for_status = MagicMock()
        return response

    return _create_response
