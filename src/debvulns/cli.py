import argparse
import asyncio
import copy
import csv
import json
import logging
import os
import sys
import time

from . import epss, package, vulnerability
from .main import detect_suite
from .vulnerability import Vulnerability

logger = logging.getLogger("debvulns")


def serialize_vulnerabilities(feed: dict[str, list[Vulnerability]]) -> dict:
    return {
        pkg: [
            {
                "bug_id": v.bug_id,
                "package": v.package,
                "description": v.description,
                "unstable_version": str(v.unstable_version)
                if v.unstable_version
                else "",
                "other_versions": [str(ov) for ov in v.other_versions],
                "is_binary": v.is_binary,
                "urgency": v.urgency,
                "remote": v.remote,
                "fix_available": v.fix_available,
            }
            for v in vulns
        ]
        for pkg, vulns in feed.items()
    }


def deserialize_vulnerabilities(data: dict) -> dict[str, list[Vulnerability]]:
    feed = {}
    for pkg, vulns in data.items():
        feed[pkg] = [
            Vulnerability(
                bug_id=v["bug_id"],
                package=v["package"],
                description=v["description"],
                unstable_version=v["unstable_version"],
                other_versions=v["other_versions"],
                is_binary=v["is_binary"],
                urgency=v["urgency"],
                remote=v["remote"],
                fix_available=v["fix_available"],
            )
            for v in vulns
        ]
    return feed


def get_cache_dir(configured_dir: str) -> str | None:
    for path in [configured_dir, os.path.expanduser("~/.cache/debvulns")]:
        try:
            os.makedirs(path, exist_ok=True)
            test_file = os.path.join(path, ".write_test")
            with open(test_file, "w") as f:
                f.write("test")
            os.remove(test_file)
            return path
        except (PermissionError, OSError) as e:
            logger.debug(f"Cache path {path} not writable: {e}")
            continue
    return None


def is_cache_valid(cache_file: str) -> bool:
    if not os.path.exists(cache_file):
        return False
    mtime = os.path.getmtime(cache_file)
    return (time.time() - mtime) < 24 * 3600


def format_vuln_dict(v: Vulnerability, severity: str) -> dict:
    fixed_ver = "None"
    if v.unstable_version:
        fixed_ver = str(v.unstable_version)
    elif v.other_versions:
        fixed_ver = ", ".join(str(ov) for ov in v.other_versions)

    return {
        "cve": v.bug_id,
        "package": getattr(v, "installed_package", v.package),
        "severity": severity,
        "installed_version": str(getattr(v, "installed_version", "")),
        "fixed_version": fixed_ver,
        "epss_score": v.epss_score,
        "epss_percentile": v.epss_percentile,
        "fix_available": "Yes" if v.fix_available else "No",
        "remote": "Yes" if v.remote else "No",
        "description": v.description,
    }


def sort_vulnerabilities(vuln_list: list[dict], sort_by: str | None) -> list[dict]:
    if not sort_by:
        return vuln_list
    if sort_by == "package":
        return sorted(vuln_list, key=lambda x: (x["package"], x["cve"]))
    elif sort_by == "cve":
        return sorted(vuln_list, key=lambda x: (x["cve"], x["package"]))
    return vuln_list


def write_csv(vuln_list: list[dict]) -> None:
    headers = [
        "CVE",
        "Package",
        "Severity",
        "Installed Version",
        "Fixed Version",
        "EPSS Score",
        "EPSS Percentile",
        "Fix Available",
        "Remote",
        "Description",
    ]
    writer = csv.writer(sys.stdout)
    writer.writerow(headers)
    for v in vuln_list:
        writer.writerow(
            [
                v["cve"],
                v["package"],
                v["severity"],
                v["installed_version"],
                v["fixed_version"],
                f"{v['epss_score']:.4f}",
                f"{v['epss_percentile'] * 100:.2f}%",
                v["fix_available"],
                v["remote"],
                v["description"],
            ]
        )


async def async_main():
    parser = argparse.ArgumentParser(
        description="debvulns - CLI Debian Vulnerabilities Tracker"
    )
    parser.add_argument(
        "-s",
        "--severity",
        choices=["critical", "high", "medium", "low", "negligible"],
        help="Filter vulnerabilities by severity",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--sort-by",
        choices=["package", "cve"],
        help="Sort vulnerabilities by 'package' or 'cve'",
    )
    parser.add_argument(
        "--vuln-url",
        help="Custom URL or local path for Debian Security Tracker data",
    )
    parser.add_argument(
        "--epss-url",
        help="Custom URL or local path for EPSS scores data",
    )
    parser.add_argument(
        "--suite",
        help="Debian suite name (e.g. bookworm, sid). Auto-detected by default.",
    )
    parser.add_argument(
        "--cache-dir",
        default="/var/cache/debvulns",
        help=(
            "Directory to cache fetched and parsed data (default: /var/cache/debvulns)"
        ),
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Do not use cached data, force downloading and parsing",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging (sent to stderr)",
    )

    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stderr,
        force=True,
    )

    try:
        suite = args.suite or detect_suite()
    except Exception as e:
        logger.error(f"Failed to detect Debian suite: {e}")
        sys.exit(1)

    use_cache = not args.no_cache
    cache_dir = None
    if use_cache:
        cache_dir = get_cache_dir(args.cache_dir)
        if not cache_dir:
            logger.warning("No writable cache directory found. Caching is disabled.")
            use_cache = False

    epss_cache_path = os.path.join(cache_dir, "epss.json") if use_cache else None
    vuln_cache_path = (
        os.path.join(cache_dir, f"vulnerabilities_{suite}.json") if use_cache else None
    )

    # Load EPSS
    epss_data = None
    if use_cache and is_cache_valid(epss_cache_path):
        logger.debug(f"Loading EPSS from cache: {epss_cache_path}")
        try:
            with open(epss_cache_path) as f:
                epss_data = json.load(f)
        except Exception as e:
            logger.warning(f"Failed to read cached EPSS: {e}")

    if epss_data is None:
        try:
            epss_data = await epss.download_epss(args.epss_url)
            if use_cache:
                logger.debug(f"Saving EPSS to cache: {epss_cache_path}")
                try:
                    with open(epss_cache_path, "w") as f:
                        json.dump(epss_data, f)
                except Exception as e:
                    logger.warning(f"Failed to write EPSS to cache: {e}")
        except Exception as e:
            logger.error(f"Failed to download EPSS data: {e}")
            sys.exit(1)

    # Load Vulnerabilities
    vuln_feed = None
    if use_cache and is_cache_valid(vuln_cache_path):
        logger.debug(f"Loading vulnerabilities from cache: {vuln_cache_path}")
        try:
            with open(vuln_cache_path) as f:
                vuln_feed = deserialize_vulnerabilities(json.load(f))
        except Exception as e:
            logger.warning(f"Failed to read cached vulnerabilities: {e}")

    if vuln_feed is None:
        try:
            vuln_feed = await vulnerability.fetch_data(suite, args.vuln_url)
            if use_cache:
                logger.debug(f"Saving vulnerabilities to cache: {vuln_cache_path}")
                try:
                    with open(vuln_cache_path, "w") as f:
                        json.dump(serialize_vulnerabilities(vuln_feed), f)
                except Exception as e:
                    logger.warning(f"Failed to write vulnerabilities to cache: {e}")
        except Exception as e:
            logger.error(
                f"Failed to download vulnerability data for suite {suite}: {e}"
            )
            sys.exit(1)

    try:
        installed_packages = package.get_installed_packages()
    except Exception as e:
        logger.error(f"Failed to get installed packages: {e}")
        sys.exit(1)

    detected_vulnerabilities = []
    for pkg in installed_packages:
        relevant_vulns = vuln_feed.get(pkg.source, None)
        if relevant_vulns is None:
            relevant_vulns = vuln_feed.get(pkg.name, [])

        for v in relevant_vulns:
            if v.is_vulnerable(pkg):
                epss_info = epss_data.get(v.bug_id, {"score": 0.0, "percentile": 0.0})
                v_copy = copy.copy(v)
                v_copy.epss_score = epss_info["score"]
                v_copy.epss_percentile = epss_info["percentile"]
                v_copy.installed_package = pkg.name
                v_copy.installed_version = pkg.version
                detected_vulnerabilities.append(v_copy)

    unique_vulns = {}
    for v in detected_vulnerabilities:
        key = (v.bug_id, v.installed_package)
        if key not in unique_vulns:
            unique_vulns[key] = v

    categorized = vulnerability.categorise_vulnerabilities(list(unique_vulns.values()))

    if args.severity:
        target_severity = args.severity.lower()
        vulns_list = categorized.get(target_severity, [])
        formatted_list = [format_vuln_dict(v, target_severity) for v in vulns_list]
        formatted_list = sort_vulnerabilities(formatted_list, args.sort_by)
        if args.format == "json":
            print(json.dumps(formatted_list, indent=2))
        else:
            write_csv(formatted_list)
    else:
        if args.format == "json":
            output = {}
            for sev, vulns in categorized.items():
                formatted_list = [format_vuln_dict(v, sev) for v in vulns]
                output[sev] = sort_vulnerabilities(formatted_list, args.sort_by)
            print(json.dumps(output, indent=2))
        else:
            all_vulns = []
            for sev, vulns in categorized.items():
                all_vulns.extend([format_vuln_dict(v, sev) for v in vulns])
            all_vulns = sort_vulnerabilities(all_vulns, args.sort_by)
            write_csv(all_vulns)


def main():
    asyncio.run(async_main())
