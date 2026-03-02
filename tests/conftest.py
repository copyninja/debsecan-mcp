import os
import platform
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


@pytest.fixture
def mock_apt_pkg(mocker):
    mock = MagicMock()
    mock.version_compare = lambda a, b: (1 if a > b else (-1 if a < b else 0))
    mocker.patch("debsecan_mcp.package.apt_pkg", mock)
    mocker.patch("debsecan_mcp.package.version_compare", mock.version_compare)
    return mock


@pytest.fixture
def sample_packages():
    from debsecan_mcp.package import Package, Version

    return [
        Package("bash", Version("5.2-2"), "bash", Version("5.2-2")),
        Package("openssl", Version("3.0.16-1"), "openssl", Version("3.0.16-1")),
        Package("curl", Version("8.5.0-1"), "curl", Version("8.5.0-1")),
    ]


@pytest.fixture
def sample_vulnerabilities():
    from debsecan_mcp.vulnerability import Vulnerability

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
