import gzip
from unittest.mock import AsyncMock, MagicMock

import pytest

from debsecan_mcp.epss import download_epss


class TestDownloadEpss:
    @pytest.mark.asyncio
    async def test_download_epss_success(self, mocker):
        csv_content = """# epss_scores
cve,epss,percentile
CVE-2024-1234,0.85,0.95
CVE-2024-5678,0.45,0.75
CVE-2024-9999,0.12,0.30
"""
        gzipped_content = gzip.compress(csv_content.encode("utf-8"))

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = gzipped_content
        mock_response.raise_for_status = MagicMock()

        mock_async_client = AsyncMock()
        mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
        mock_async_client.__aexit__ = AsyncMock(return_value=None)
        mock_async_client.get = AsyncMock(return_value=mock_response)

        mocker.patch("httpx.AsyncClient", return_value=mock_async_client)

        result = await download_epss()

        assert "CVE-2024-1234" in result
        assert result["CVE-2024-1234"]["score"] == 0.85
        assert result["CVE-2024-1234"]["percentile"] == 0.95
        assert "CVE-2024-5678" in result
        assert "CVE-2024-9999" in result

    @pytest.mark.asyncio
    async def test_download_epss_http_error(self, mocker):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = Exception("HTTP 500")

        mock_async_client = AsyncMock()
        mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
        mock_async_client.__aexit__ = AsyncMock(return_value=None)
        mock_async_client.get = AsyncMock(return_value=mock_response)

        mocker.patch("httpx.AsyncClient", return_value=mock_async_client)

        with pytest.raises(Exception):
            await download_epss()

    @pytest.mark.asyncio
    async def test_download_epss_invalid_csv(self, mocker):
        csv_content = """# epss_scores
invalid,content
"""
        gzipped_content = gzip.compress(csv_content.encode("utf-8"))

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = gzipped_content
        mock_response.raise_for_status = MagicMock()

        mock_async_client = AsyncMock()
        mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
        mock_async_client.__aexit__ = AsyncMock(return_value=None)
        mock_async_client.get = AsyncMock(return_value=mock_response)

        mocker.patch("httpx.AsyncClient", return_value=mock_async_client)

        result = await download_epss()
        assert result == {}

    @pytest.mark.asyncio
    async def test_download_epss_follows_redirects(self, mocker):
        csv_content = """# epss_scores
cve,epss,percentile
CVE-2024-1234,0.85,0.95
"""
        gzipped_content = gzip.compress(csv_content.encode("utf-8"))

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = gzipped_content

        mock_async_client = AsyncMock()
        mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
        mock_async_client.__aexit__ = AsyncMock(return_value=None)
        mock_async_client.get = AsyncMock(return_value=mock_response)

        mocker.patch("httpx.AsyncClient")
        httpx_client = mocker.patch("httpx.AsyncClient", return_value=mock_async_client)

        await download_epss()

        httpx_client.assert_called_once_with(follow_redirects=True)
