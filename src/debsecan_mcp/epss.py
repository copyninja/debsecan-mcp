import csv
import gzip
import logging
from io import StringIO

import httpx

logger = logging.getLogger(__name__)

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


async def download_epss() -> dict[str, dict[str, float]]:
    """
    Downloads the latest EPSS data and returns a map of CVE to EPSS score and percentile.
    """
    logger.info("Downloading EPSS data from %s", EPSS_URL)
    async with httpx.AsyncClient(follow_redirects=True) as client:
        response = await client.get(EPSS_URL)
        response.raise_for_status()

        # Decompress the gzipped data
        content = gzip.decompress(response.content).decode("utf-8")

        # Parse CSV
        lines = content.splitlines()
        # The EPSS CSV usually starts with # or metadata
        data_lines = [line for line in lines if not line.startswith("#")]

        epss_map = {}
        reader = csv.DictReader(StringIO("\n".join(data_lines)))
        for row in reader:
            try:
                cve = row["cve"]
                score = float(row["epss"])
                percentile = float(row["percentile"])
                epss_map[cve] = {"score": score, "percentile": percentile}
            except (KeyError, ValueError) as e:
                logger.warning("Error parsing EPSS row %s: %s", row, e)
                continue

    logger.info("Loaded %d EPSS scores", len(epss_map))
    return epss_map
