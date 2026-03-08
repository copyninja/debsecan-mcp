import argparse
import asyncio
import logging
import os
import sys

from mcp.server.fastmcp import FastMCP

from . import epss, package, vulnerability


def create_mcp(transport: str, host: str, port: int, mount_path: str) -> FastMCP:
    """Create FastMCP instance based on transport type."""
    if transport == "stdio":
        return FastMCP("DebSecCan")
    elif transport == "sse":
        return FastMCP("DebSecCan", host=host, port=port, sse_path=mount_path)
    else:
        return FastMCP(
            "DebSecCan", host=host, port=port, streamable_http_path=mount_path
        )


# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("debsecan-mcp")

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
        # Try source package first, fallback to binary package (matching debsecan logic)
        # debsecan uses: try vulns[source], if KeyError then try vulns[binary]
        relevant_vulns = vulns_by_pkg.get(pkg.source, None)
        if relevant_vulns is None:
            relevant_vulns = vulns_by_pkg.get(pkg.name, [])

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
    output = {}
    for cat, vulns in categorized.items():
        output[cat] = {v.bug_id for v in vulns}

    if not output:
        return "No vulnerabilities detected on the system."

    return output


async def research_cves(cves: list[str]):
    """
    Provides detailed information for a list of CVE IDs.
    """
    logger.info("Researching CVEs: %s", cves)

    results = []
    installed_pkg_names = {pkg.name for pkg in installed_packages}
    installed_source_names = {pkg.source for pkg in installed_packages}

    for cve in cves:
        cve = cve.strip().upper()
        # Search for this CVE in our vulnerability feed across all packages
        found_vulns = []
        for pkg_name, pkg_vulns in vulnerability_feed.items():
            for v in pkg_vulns:
                if v.bug_id == cve:
                    found_vulns.append(v)
                    break

        if not found_vulns:
            results.append(f"### {cve}\nNo detailed information found in current feed.")
            continue

        # Prioritize vulns affecting installed packages (binary or source)
        # Sort so installed ones come first
        found_vulns.sort(
            key=lambda x: (
                x.package in installed_pkg_names or x.package in installed_source_names
            ),
            reverse=True,
        )

        v = found_vulns[0]
        epss_info = epss_data.get(v.bug_id, {"score": 0.0, "percentile": 0.0})
        percentile_str = f"{epss_info['percentile'] * 100:.2f}%"

        is_installed = (
            v.package in installed_pkg_names or v.package in installed_source_names
        )
        status_str = " (INSTALLED)" if is_installed else ""

        res = (
            f"### {v.bug_id}{status_str}\n"
            f"- **Package**: {v.package}\n"
            f"- **Urgency**: {v.urgency}\n"
            f"- **EPSS Score**: {epss_info['score']:.4f}\n"
            f"- **EPSS Percentile**: {percentile_str}\n"
            f"- **Fix Available**: {'Yes' if v.fix_available else 'No'}\n"
            f"- **Remote**: {v.remote}\n"
            f"- **Description**: {v.description}\n"
        )
        results.append(res)

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
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("debsecan-mcp")

    parser = argparse.ArgumentParser(description="DebSecCan MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="Transport mode (default: stdio)",
    )
    parser.add_argument(
        "--mount-path",
        default="/mcp",
        help="Mount path for HTTP transports (default: /mcp)",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind to for HTTP transport (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind to for HTTP transport (default: 8000)",
    )
    parsed = parser.parse_args()
    mcp = create_mcp(parsed.transport, parsed.host, parsed.port, parsed.mount_path)

    # Add the tools
    mcp.add_tool(list_vulnerabilities)
    mcp.add_tool(research_cves)

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(initialize())
    except Exception as e:
        logger.critical("Server failed to initialize and will not start: %s", e)
        return

    logger.info(
        f"Starting {parsed.transport} server on {parsed.host}:{parsed.port}{parsed.mount_path}"
    )

    if parsed.transport == "stdio":
        mcp.run(transport="stdio")
    elif parsed.transport == "sse":
        mcp.run(transport="sse")
    else:
        mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
