# Grafana Dashboard: Debian Vulnerability Analysis (debvulns)

A ready-to-import Grafana dashboard for monitoring Debian package vulnerabilities reported
by the `debvulns-exporter` Prometheus exporter.

## Quick Import

1. In Grafana → **Dashboards → Import**
2. Upload `contrib/grafana/debvulns-dashboard.json`
3. Select your **Prometheus** datasource when prompted
4. Click **Import**

> [!NOTE]
> Requires Grafana ≥ 10.0 and a Prometheus datasource scraping at least one
> `debvulns-exporter` instance. The exporter must be reachable at its configured
> port (default `9222`) and appearing in your Prometheus targets.

---

## Variables

| Variable | Type | Description |
|---|---|---|
| `instance` | Query | Multi-select. Populated from `label_values(debvulns_exporter_info, instance)`. Select one or more instances to filter all panels. Defaults to All. |
| `severity` | Custom | Multi-select. Values: `critical`, `high`, `medium`, `low`, `negligible`. Filters the Vulnerability Details table. Defaults to All. |

---

## Panel Reference

### Row 1 — Health & At-a-Glance (6 stat panels)

| Panel | Query | What it tells you |
|---|---|---|
| **Scan Status** | `debvulns_scan_status{instance=~"..."}` | Whether the last scan succeeded. Green = OK, Red = FAILED. A failed scan still serves the last good cached data. |
| **Scan Age** | `time() - min(debvulns_last_scan_timestamp_seconds{...})` | Seconds since the oldest scan across selected instances. Auto-scales to minutes/hours/days. Color: green (<1 h), yellow (<6 h), orange (<24 h), red (>24 h). The default refresh interval is 24 h so red means something went wrong. |
| **Total CVEs** | `sum(debvulns_vulnerabilities_total{...})` | Total active vulnerability count across all severities and all selected instances. |
| **Critical + High** | `sum(debvulns_vulnerabilities_total{severity=~"critical\|high", ...})` | High-priority CVEs only. Red if any exist. The `severity` label is **derived** — it combines the raw debsecan urgency flag with the EPSS score (a high-urgency CVE with EPSS > 0.3 is promoted to `critical`). |
| **Fix Available** | `sum(debvulns_vulnerabilities_total{fix_available="true", ...})` | CVEs for which a Debian patch is already available. Running `apt update && apt upgrade` will resolve these. |
| **Affected Packages** | `count(debvulns_package_info{...})` | Number of distinct installed packages with at least one active CVE. One package can have many CVEs — this is the actual number of `apt upgrade` targets. |

---

### Row 2 — Priority Intelligence

These two panels answer the core operational question: **what do I act on today?**

#### 🔴 Patch Now — High EPSS, Fix Available

```promql
topk(10,
  debvulns_vulnerability_epss_score{instance=~"^$instance$"}
  * on(cve, package, instance) group_left()
    (debvulns_vulnerability_info{instance=~"^$instance$", fix_available="true"})
)
```

Top 10 vulnerabilities by **EPSS exploitation probability** where a Debian patch **already exists**.
These are the highest-leverage patches: both likely to be exploited *and* immediately fixable.

**Threshold colours (EPSS score):**
- 🔵 Blue: < 10% exploitation probability
- 🟡 Yellow: 10–30%
- 🟠 Orange: 30–75%
- 🔴 Red: > 75% — actively being exploited in the wild

**Action:** Run `apt update && apt upgrade` on the affected host.

#### 🟡 Monitor — High EPSS, No Fix Yet

```promql
topk(10,
  debvulns_vulnerability_epss_score{instance=~"^$instance$"}
  * on(cve, package, instance) group_left()
    (debvulns_vulnerability_info{instance=~"^$instance$", fix_available="false"})
)
```

Top 10 vulnerabilities by EPSS where **no Debian patch exists yet**.
You cannot patch these, but you should know about them for compensating controls
(network isolation, WAF rules, disabling the affected service).

**Action:** Subscribe to the [Debian Security Tracker](https://security-tracker.debian.org/)
for the relevant CVE. When `fix_available` flips to `true` it will appear in the
"Patch Now" panel.

> [!NOTE]
> **Multi-instance joins**: Both bar gauge queries use `* on(cve, package, instance) group_left()`
> rather than `* on(cve, package)`. This is required when scraping multiple instances to
> avoid Prometheus "multiple matches" errors — each `(cve, package)` pair is unique per instance.

---

### Row 3 — Full Vulnerability Inventory

#### Vulnerability Details (table)

```promql
(
  (
    debvulns_vulnerability_epss_score{instance=~"^$instance$"}
    * on(cve, package, instance) group_left(severity, urgency, fix_available, remote)
      debvulns_vulnerability_info{instance=~"^$instance$"}
  )
  * on(package, instance) group_left(installed_version)
    debvulns_package_info{instance=~"^$instance$"}
)
* on(cve, package, instance) group_left(fix_version)
  debvulns_vulnerability_fix_info{instance=~"^$instance$"}
```

A four-way join enriching every active CVE with:

| Column | Source metric | Notes |
|---|---|---|
| **CVE** | `debvulns_vulnerability_info` | Clickable link to NVD entry |
| **Package** | `debvulns_vulnerability_info` | Binary package name |
| **Severity** | `debvulns_vulnerability_info` | Color-coded: Critical / High / Medium / Low / Negligible |
| **Fix Available** | `debvulns_vulnerability_info` | ✓ Yes (green) / ✗ No (red) |
| **Fix Version** | `debvulns_vulnerability_fix_info` | Target version for the fix; empty if none known |
| **Installed Version** | `debvulns_package_info` | Currently installed version |
| **Remote** | `debvulns_vulnerability_info` | Remote / Local / — (unknown). In practice most debsecan entries are `unknown` because the `?` flag is used when remote exploitability is unconfirmed |
| **Instance** | label | Which host this row is from |
| **EPSS Score** | `debvulns_vulnerability_epss_score` | LCD gauge 0–1; sorted descending by default |

**Tip:** Use the `severity` variable dropdown at the top to filter to `critical,high` only.
The column headers are also clickable to re-sort.

---

### Instance Info (bottom table)

```promql
debvulns_exporter_info{instance=~"^$instance$"}
```

Shows the Debian suite codename (`bookworm`, `trixie`, `sid`, etc.) and exporter version
for each monitored host. Particularly useful in mixed-fleet environments where different
machines run different Debian releases.

---

## Alerting

The following PrometheusRule examples are provided in [`docs/prometheus_exporter_design.md`](prometheus_exporter_design.md#suggested-promql-alerts).
Copy them into your Prometheus alerting rules:

| Alert | Condition | Severity |
|---|---|---|
| `DebsecanCriticalVulnerabilityWithFix` | `debvulns_vulnerabilities_total{severity="critical", fix_available="true"} > 0` | critical |
| `DebsecanHighEpssScoreVulnerability` | `debvulns_vulnerability_epss_score > 0.70` | warning |
| `DebsecanScanFailed` | `debvulns_scan_status == 0` for 15 m | warning |
| `DebsecanNoScanReporting` | `(time() - debvulns_last_scan_timestamp_seconds) > 86400` | warning |
| `DebsecanRemoteExploitableNoFix` | `debvulns_vulnerabilities_total{remote="true", fix_available="false", severity=~"critical\|high"} > 0` | critical |

---

## Troubleshooting

### All panels show "No data"

1. Check the `instance` variable dropdown — if it's empty, `label_values(debvulns_exporter_info, instance)`
   returned nothing, meaning Prometheus is not scraping any exporter.
2. Verify targets in Prometheus: `http://<prometheus>:9090/targets` — the `debvulns-exporter` job
   should show UP.
3. Check the exporter health endpoint: `curl http://<host>:9222/-/healthy` and
   `curl http://<host>:9222/-/ready`.
4. On first startup the exporter returns HTTP 503 until the initial scan completes
   (can take 30–60 s depending on network speed).

### "Patch Now" / "Monitor" bar gauges show "No data"

The join queries use `* on(cve, package, instance) group_left()`. If you get a
"multiple matches" error in the Grafana panel inspector, you are likely scraping
multiple instances and the `instance` label is not included in the `on()` clause.
This dashboard already handles this correctly — if you modify the queries, always
include `instance` in every `on()` clause.

### "Vulnerability Details" table is empty

The four-way join requires all four metrics to be populated. If `debvulns_vulnerability_epss_score`
is missing (e.g. EPSS download failed at startup), the join produces no results.
Check `debvulns_scan_status` — a value of `0` means the last scan failed.
Restart the exporter to trigger a fresh scan.

### Scan Age shows a very large value / red background

The exporter refreshes its vulnerability cache every 24 hours by default
(`--refresh-interval 24h`). If the Scan Age exceeds 24 hours, either:
- The exporter service crashed: `systemctl status debvulns-exporter.service`
- The cache refresh thread failed: `journalctl -u debvulns-exporter.service | grep ERROR`
- Prometheus stopped scraping: check `/targets` in Prometheus UI
