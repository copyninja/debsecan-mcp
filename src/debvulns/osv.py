"""OSV.dev integration for non-Debian package vulnerability checking.

This module provides CVE-based vulnerability lookup using the OSV.dev API.
It is used as a secondary vulnerability source for packages that do not
originate from the Debian archive (e.g. Grafana from grafana.com's APT repo).

Strategy
--------
1. For each non-Debian package, find candidate CVEs from the Debian Security
   Tracker feed (the feed lists CVEs for many upstream projects even when
   Debian itself has no packaged fix).
2. For each candidate CVE, fetch the authoritative OSV record via
   ``GET https://api.osv.dev/v1/vulns/{CVE-ID}``.
3. Check whether the installed version is listed in the OSV ``affected``
   block.  If NOT listed → the upstream fix is already present → drop it.
4. Return only genuinely affected (bug_id, package) pairs so they can be
   surfaced alongside the normal Debian feed results.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import httpx

from .package import Package

logger = logging.getLogger(__name__)

OSV_BASE_URL = "https://api.osv.dev/v1/vulns"


@dataclass
class OsvVulnerability:
    """Lightweight representation of an OSV vulnerability record."""

    id: str  # e.g. "CVE-2021-39226"
    summary: str
    details: str
    # CVSS severity entries, each is {"type": "CVSS_V3", "score": "CVSS:3.1/..."}
    severity: list[dict] = field(default_factory=list)
    # All explicitly enumerated affected version strings (with or without 'v' prefix)
    affected_versions: list[str] = field(default_factory=list)
    # Aliases (e.g. GHSA IDs)
    aliases: list[str] = field(default_factory=list)

    def cvss_base_score(self) -> float:
        """Extract the numeric CVSS base score (0.0 if not available)."""
        for entry in self.severity:
            vector = entry.get("score", "")
            # CVSS vectors encode the base score after the last '/'
            # e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
            # We derive the score from the AV metric combination instead of
            # parsing the full vector; use the pre-computed score if OSV
            # exposes it (some records do), otherwise return 5.0 as a
            # conservative mid-range default.
            score_val = entry.get("base_score")
            if score_val is not None:
                try:
                    return float(score_val)
                except (TypeError, ValueError):
                    pass
        # Fallback: return 5.0 so the CVE ends up in "medium" rather than
        # being silently dropped.
        return 5.0

    def urgency_from_cvss(self) -> str:
        """Map CVSS base score to an urgency string matching the Debian feed."""
        score = self.cvss_base_score()
        if score >= 9.0:
            return "high"  # will be promoted to critical by categoriser
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low"


def _parse_osv_response(data: dict) -> OsvVulnerability:
    """Convert a raw OSV API response dict to an OsvVulnerability."""
    affected_versions: list[str] = []
    for affected_block in data.get("affected", []):
        for v in affected_block.get("versions", []):
            affected_versions.append(v)

    return OsvVulnerability(
        id=data.get("id", ""),
        summary=data.get("summary", ""),
        details=data.get("details", ""),
        severity=data.get("severity", []),
        affected_versions=affected_versions,
        aliases=data.get("aliases", []),
    )


async def fetch_osv_vuln(
    cve_id: str, client: httpx.AsyncClient | None = None
) -> OsvVulnerability | None:
    """Fetch a single vulnerability by CVE ID from OSV.dev.

    Returns ``None`` if the CVE is not found in OSV (404) or has no affected
    version data — in that case the caller should fall back to the Debian feed
    result as-is.
    """
    url = f"{OSV_BASE_URL}/{cve_id}"
    try:
        if client is not None:
            response = await client.get(url)
        else:
            async with httpx.AsyncClient(timeout=10.0) as c:
                response = await c.get(url)

        if response.status_code == 404:
            logger.debug("CVE %s not found in OSV", cve_id)
            return None

        response.raise_for_status()
        data = response.json()
    except httpx.HTTPStatusError as exc:
        logger.warning("HTTP error fetching OSV for %s: %s", cve_id, exc)
        return None
    except Exception as exc:
        logger.warning("Failed to fetch OSV data for %s: %s", cve_id, exc)
        return None

    osv_vuln = _parse_osv_response(data)
    if not osv_vuln.affected_versions:
        logger.debug(
            "OSV record for %s has no enumerated affected versions — skipping",
            cve_id,
        )
        return None

    return osv_vuln


def is_version_affected(installed_version: str, osv_vuln: OsvVulnerability) -> bool:
    """Return True if *installed_version* is in the OSV affected versions list.

    The OSV ``affected[].versions`` field enumerates **every** affected release
    tag for a vulnerability.  A version that does NOT appear in this list is
    therefore **not** affected (the fix was already shipped before or at that
    release).

    Version comparison is done after stripping a leading ``v`` prefix so that
    ``"v8.1.5"`` and ``"8.1.5"`` are treated as equivalent.

    Args:
        installed_version: The version string from the installed package (as
            returned by dpkg / apt_pkg).
        osv_vuln: The :class:`OsvVulnerability` to check against.

    Returns:
        ``True`` if the installed version is explicitly listed as affected by
        OSV.  ``False`` otherwise (including when the affected_versions list
        is empty, which should not happen since :func:`fetch_osv_vuln` filters
        those out).
    """
    if not osv_vuln.affected_versions:
        return False

    normalized = installed_version.lstrip("v")
    for av in osv_vuln.affected_versions:
        if av.lstrip("v") == normalized:
            return True

    return False


async def check_non_debian_packages(
    non_debian_pkgs: list[Package],
    vuln_feed: dict,
    epss_data: dict[str, dict[str, float]],
) -> list[dict]:
    """Cross-check non-Debian packages against OSV.dev using CVE IDs from the
    Debian Security Tracker feed.

    For each non-Debian package we:
    1. Look up candidate CVEs in the Debian feed (the feed knows about upstream
       CVEs even for packages Debian doesn't ship a fix for).
    2. For each candidate CVE, call OSV to get the authoritative affected
       version list.
    3. Return only genuinely affected (package, CVE) pairs enriched with EPSS.

    Args:
        non_debian_pkgs: Packages that failed the ``is_debian_origin`` check.
        vuln_feed: The Debian Security Tracker feed (source → vulnerabilities).
        epss_data: EPSS score map {CVE-ID → {"score": float, "percentile": float}}.

    Returns:
        A list of result dicts that callers can merge into the vulnerability
        output.  Each dict has the same keys as ``format_vuln_dict`` in cli.py::

            {
                "cve": str,
                "package": str,
                "installed_version": str,
                "severity": str,
                "epss_score": float,
                "epss_percentile": float,
                "fix_available": "Yes",
                "remote": "Unknown",
                "description": str,
                "source": "osv.dev",
            }
    """
    results: list[dict] = []
    # Cache OSV responses within a single scan to avoid duplicate API calls.
    osv_cache: dict[str, OsvVulnerability | None] = {}

    async with httpx.AsyncClient(timeout=10.0) as client:
        for pkg in non_debian_pkgs:
            # Find candidate vulnerabilities from the Debian feed.
            candidate_vulns = vuln_feed.get(pkg.source, None)
            if candidate_vulns is None:
                candidate_vulns = vuln_feed.get(pkg.name, [])

            # Collect unique CVE IDs from the candidate list.
            seen_cves: set[str] = set()
            for deb_vuln in candidate_vulns:
                cve_id = deb_vuln.bug_id
                if cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)

                # Fetch (or reuse cached) OSV data.
                if cve_id not in osv_cache:
                    osv_cache[cve_id] = await fetch_osv_vuln(cve_id, client)

                osv_vuln = osv_cache[cve_id]
                if osv_vuln is None:
                    # OSV has no data for this CVE → can't cross-check;
                    # skip silently to avoid false positives.
                    logger.debug(
                        "No OSV data for %s (package %s) — skipping",
                        cve_id,
                        pkg.name,
                    )
                    continue

                if not is_version_affected(str(pkg.version), osv_vuln):
                    logger.debug(
                        "%s v%s is NOT in OSV affected list for %s — skipping",
                        pkg.name,
                        pkg.version,
                        cve_id,
                    )
                    continue

                # Version IS affected — build the result entry.
                epss_info = epss_data.get(cve_id, {"score": 0.0, "percentile": 0.0})
                description = osv_vuln.details or osv_vuln.summary

                results.append(
                    {
                        "cve": cve_id,
                        "package": pkg.name,
                        "installed_version": str(pkg.version),
                        "urgency": osv_vuln.urgency_from_cvss(),
                        "epss_score": epss_info["score"],
                        "epss_percentile": epss_info["percentile"],
                        "fix_available": "Yes",  # fix exists upstream per OSV
                        "remote": "Unknown",
                        "description": description[:200] if description else "",
                        "source": "osv.dev",
                    }
                )
                logger.info(
                    "OSV confirmed %s affects %s v%s",
                    cve_id,
                    pkg.name,
                    pkg.version,
                )

    return results
