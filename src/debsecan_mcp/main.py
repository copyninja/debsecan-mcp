import asyncio
import logging
import os

from mcp.server.fastmcp import FastMCP

from . import epss, package, vulnerability

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("debsecan-mcp")

# Initialize FastMCP
mcp = FastMCP("DebSecCan")

# Global data stores
epss_data = {}
installed_packages = []
vulnerability_feed = {}


def detect_suite() -> str:
    """
    Detects the current Debian suite codename from environment or /etc/os-release.
    Raises RuntimeError if suite cannot be determined.
    """
    suite = os.getenv("DEBSECAN_SUITE")
    if suite:
        return suite

    try:
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release") as f:
                os_info = {}
                for line in f:
                    if "=" in line:
                        k, v = line.split("=", 1)
                        os_info[k.strip()] = v.strip().strip('"')

                # Preference: VERSION_CODENAME
                suite = os_info.get("VERSION_CODENAME")
                if not suite:
                    # Fallback for sid/unstable: check PRETTY_NAME or VERSION
                    pretty_name = os_info.get("PRETTY_NAME", "").lower()
                    version_str = os_info.get("VERSION", "").lower()
                    if "sid" in pretty_name or "sid" in version_str:
                        suite = "sid"
    except Exception as e:
        logger.error("Error reading /etc/os-release: %s", e)

    if not suite:
        raise RuntimeError(
            "Debian suite could not be detected. Please set DEBSECAN_SUITE environment variable."
        )

    return suite


@mcp.tool()
async def list_vulnerabilities(suite: str | None = None):
    """
    Lists all vulnerabilities affecting the currently installed packages on the system.
    Categorises them by severity and EPSS score.
    """
    logger.info("Listing vulnerabilities...")

    # Refresh vulnerability feed if a specific suite is requested
    if suite:
        vulns_by_pkg = await vulnerability.fetch_data(suite)
    else:
        vulns_by_pkg = vulnerability_feed

    detected_vulnerabilities = []

    for pkg in installed_packages:
        # Check both binary package name and source package name
        relevant_vulns = vulns_by_pkg.get(pkg.name, [])
        if pkg.source != pkg.name:
            relevant_vulns.extend(vulns_by_pkg.get(pkg.source, []))

        for v in relevant_vulns:
            if v.is_vulnerable(pkg):
                # Enrich with EPSS score and percentile
                epss_info = epss_data.get(v.bug_id, {"score": 0.0, "percentile": 0.0})
                # Create a shallow copy to avoid mutating the feed data
                import copy
                v_copy = copy.copy(v)
                v_copy.epss_score = epss_info["score"]
                v_copy.epss_percentile = epss_info["percentile"]
                # Track the actual installed package that matched
                v_copy.installed_package = pkg.name
                detected_vulnerabilities.append(v_copy)

    # Deduplicate by bug_id + installed_package
    unique_vulns = {}
    for v in detected_vulnerabilities:
        key = (v.bug_id, v.installed_package)
        if key not in unique_vulns:
            unique_vulns[key] = v

    categorized = vulnerability.categorise_vulnerabilities(list(unique_vulns.values()))

    # Format output for the LLM
    output = []
    for cat, vulns in categorized.items():
        if vulns:
            output.append(f"## {cat.upper()} VULNERABILITIES")
            for v in vulns:
                desc = v.description[:150]
                percentile_str = f"{getattr(v, 'epss_percentile', 0.0) * 100:.2f}%"
                # Report both source (from feed) and the actual installed package
                package_info = f"{v.package} (installed: {v.installed_package})" if v.package != v.installed_package else v.package
                output.append(
                    f"- **{v.bug_id}** ({package_info}): {desc}... "
                    f"[EPSS: {getattr(v, 'epss_score', 0.0):.4f}, Percentile: {percentile_str}]"
                )
            output.append("")

    if not output:
        return "No vulnerabilities detected on the system."

    return "\n".join(output)


@mcp.tool()
async def research_cves(cves: list[str]):
    """
    Provides detailed information for a list of CVE IDs.
    """
    logger.info("Researching CVEs: %s", cves)

    results = []
    for cve in cves:
        cve = cve.strip().upper()
        # Search for this CVE in our vulnerability feed across all packages
        found_vulns = []
        for pkg_vulns in vulnerability_feed.values():
            for v in pkg_vulns:
                if v.bug_id == cve:
                    # Enrich with EPSS
                    epss_info = epss_data.get(
                        v.bug_id, {"score": 0.0, "percentile": 0.0}
                    )
                    v.epss_score = epss_info["score"]
                    v.epss_percentile = epss_info["percentile"]
                    found_vulns.append(v)
                    break
            if found_vulns:
                break

        if found_vulns:
            v = found_vulns[0]
            percentile_str = f"{v.epss_percentile * 100:.2f}%"
            res = (
                f"### {v.bug_id}\n"
                f"- **Package**: {v.package}\n"
                f"- **Urgency**: {v.urgency}\n"
                f"- **EPSS Score**: {v.epss_score:.4f}\n"
                f"- **EPSS Percentile**: {percentile_str}\n"
                f"- **Fix Available**: {'Yes' if v.fix_available else 'No'}\n"
                f"- **Remote**: {v.remote}\n"
                f"- **Description**: {v.description}\n"
            )
            results.append(res)
        else:
            results.append(f"### {cve}\nNo detailed information found in current feed.")

    return "\n---\n".join(results)


async def initialize():
    """
    Global initialization of data.
    """
    global epss_data, installed_packages, vulnerability_feed

    logger.info("Initializing DebSecCan MCP Server...")

    # 1. EPSS Data
    try:
        epss_data = await epss.download_epss()
    except Exception as e:
        logger.error("Failed to initialize EPSS data: %s", e)

    # 2. Installed Packages
    try:
        installed_packages = package.get_installed_packages()
    except Exception as e:
        logger.error("Failed to initialize installed packages: %s", e)

    # 3. Vulnerability Feed
    # Strict suite detection as requested by user
    try:
        current_suite = detect_suite()
        logger.info("Detected suite: %s", current_suite)
        vulnerability_feed = await vulnerability.fetch_data(current_suite)
    except RuntimeError as e:
        logger.critical("Initialization failed: %s", e)
        raise
    except Exception as e:
        logger.error("Failed to initialize vulnerability feed for suite: %s", e)
        # Fallback to GENERIC if specific suite fails
        logger.info("Retrying with GENERIC suite...")
        try:
            vulnerability_feed = await vulnerability.fetch_data("GENERIC")
        except Exception as e2:
            logger.error("Failed to fetch GENERIC data: %s", e2)
            raise RuntimeError("Could not fetch any vulnerability data.") from e2

    logger.info("Initialization complete.")


def main():
    # Run initialization before starting the server
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(initialize())
    except Exception as e:
        logger.critical("Server failed to initialize and will not start: %s", e)
        return

    # Start FastMCP server
    mcp.run()


if __name__ == "__main__":
    main()
