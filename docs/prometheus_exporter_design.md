# Prometheus Exporter Design for debsecan-mcp

This document outlines the design for exposing Prometheus metrics from the `debsecan-mcp`
vulnerability analysis server. These metrics allow Site Reliability Engineers (SREs) and
security operations teams to monitor, alert on, and visualize package vulnerabilities across
their Debian infrastructure.

---

## Architecture Overview

Fetching vulnerability data is expensive: the exporter downloads the Debian Security Tracker
database (compressed, ~1–2 MB) and optionally the full EPSS CSV (~15 MB). Vulnerability
data changes at most once per day (aligned with Debian DSA publication cadence), so there is
no value in re-fetching on every Prometheus scrape.

The exporter therefore uses a **two-thread design**:

- **Cache-refresh thread** — runs the full scan pipeline once at startup, then sleeps for a
  configurable interval (default: 24 h) and repeats. The refreshed snapshot is swapped into
  shared state atomically under a `threading.RLock`.
- **HTTP server thread** — serves `/metrics` requests instantly from the cached snapshot.
  Scrape latency is effectively zero because no I/O occurs on the hot path.

```
┌──────────────────────────────────────────────────────────┐
│                   debvulns-exporter                      │
│                                                          │
│  Thread 1 — Cache Refresher                              │
│  ┌────────────────────────────────────────────────────┐  │
│  │  startup ──► scan() ──► swap cache ──► sleep 24h  │  │
│  │                              ▲                     │  │
│  │                              └──────── repeat ─────│  │
│  └────────────────────────────────────────────────────┘  │
│                          │ RLock                          │
│  Thread 2 — HTTP Server  ▼                               │
│  ┌────────────────────────────────────────────────────┐  │
│  │  GET /metrics ──► read cache ──► emit text format  │  │
│  │  GET /-/healthy  GET /-/ready                      │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

### Startup Behaviour

Before the first scan completes the HTTP server returns **HTTP 503** on `/metrics` and
`/-/ready`, signalling to Prometheus that data is not yet available. `/-/healthy` returns
200 immediately so process supervisors can distinguish "starting" from "broken".

### Cache Swap

The cache refresher holds the write lock only for the in-memory swap, **not** during the
network downloads. This keeps the critical section sub-millisecond and ensures scrapes are
never blocked by a slow network.

### Deployment

The exporter runs as a long-running systemd service (no timer required):

**`/etc/systemd/system/debvulns-exporter.service`**
```ini
[Unit]
Description=Debvulns Prometheus native exporter
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/debvulns-exporter --port 9222 --refresh-interval 24h
Restart=on-failure
RestartSec=30s
User=debvulns
AmbientCapabilities=
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Enable with:
```bash
systemctl daemon-reload
systemctl enable --now debvulns-exporter.service
```

All logs flow to journald: `journalctl -u debvulns-exporter.service -f`.

### Integration with the Existing Codebase

The core scan pipeline already lives in `src/debvulns_mcp/` (vulnerability fetching,
package detection, EPSS scoring, categorisation). The exporter imports and calls these
modules directly — it does **not** shell out to the CLI or duplicate any logic.

All metrics are prefixed with the namespace `debvulns_`.

---

## Metric Definitions

### 1. General & Health Metrics

These metrics track the health of the exporter itself, the last scan time, and static
metadata.

#### `debvulns_exporter_info`

* **Type**: Gauge
* **Value**: Always `1`
* **Labels**:
  * `version`: Version of the `debvulns` exporter.
  * `suite`: Debian suite codename (e.g., `bookworm`, `trixie`, `sid`, `generic`).
* **Description**: Metadata about the exporter configuration.

#### `debvulns_scan_status`

* **Type**: Gauge
* **Value**: `1` (success) or `0` (failure)
* **Labels**: None
* **Description**: Indicates whether the last vulnerability scan/refresh completed
  successfully.

#### `debvulns_last_scan_timestamp_seconds`

* **Type**: Gauge
* **Value**: Unix epoch timestamp of the last scan.
* **Labels**: None
* **Description**: Epoch timestamp of when the last scan was executed.

#### `debvulns_scan_duration_seconds`

* **Type**: Gauge
* **Value**: Time taken in seconds.
* **Labels**: None
* **Description**: Duration of the last vulnerability scan in seconds.

#### `debvulns_installed_packages_count`

* **Type**: Gauge
* **Value**: Count of installed packages.
* **Labels**: None
* **Description**: Total number of Debian packages currently installed on the host.

> [!NOTE]
> The metric name uses `_count` rather than `_total`. The `_total` suffix is reserved by
> Prometheus convention for **Counter** types (monotonically increasing values). Since
> the number of installed packages can decrease (after removal), this is a Gauge.

---

### 2. Aggregated Vulnerability Metrics

These metrics provide quick top-level summaries suitable for high-level dashboards and
general alerting.

#### `debvulns_vulnerabilities_total`

* **Type**: Gauge
* **Value**: Count of detected vulnerabilities.
* **Labels**:
  * `severity`: Categorized severity level (`critical`, `high`, `medium`, `low`,
    `negligible`). This is the **derived** category computed by `categorise_vulnerabilities()`
    which considers both the raw debsecan urgency flag and the EPSS score together (e.g., a
    `high` urgency CVE with EPSS > 0.3 is promoted to `critical`).
  * `fix_available`: Whether a package update is available (`true` or `false`).
  * `remote`: Whether the vulnerability is remotely exploitable (`true`, `false`, or
    `unknown`).
* **Description**: Aggregate count of vulnerabilities currently affecting the system,
  segmented by severity, fix availability, and remote exploitability.

> [!NOTE]
> **`severity` vs `urgency`**: The raw debsecan urgency flags (`L`, `M`, `H`, or blank) are
> mapped to a derived severity by `categorise_vulnerabilities()`. This function uses a
> composite of the raw urgency and the EPSS score to determine the final category. The
> `severity` label in these metrics always reflects the **derived** category. The raw urgency
> string is available on the per-CVE `debvulns_vulnerability_info` metric as the `urgency`
> label.

---

### 3. Per-Vulnerability Metrics

These metrics provide fine-grained information per vulnerability and package. To keep
cardinality manageable and avoid churn, the data is **split across three metrics** that
can be joined in PromQL on the natural key `(cve, package)` or `package`.

> [!NOTE]
> **Why split?** On a `sid`/unstable suite, the `(cve, package)` cardinality can reach
> 10 000+ time series. Embedding `installed_version` and `fix_version` as labels on every
> series multiplies memory use and causes constant churn on package upgrades (retired series
> + new series every time a package version changes). Splitting isolates those high-entropy,
> high-churn labels into purpose-specific metrics so that the core alerting metric remains
> stable and cheap.
>
> **Joining in PromQL** uses `* on(<key>) group_left(<label>)` — the standard Prometheus
> info-metric join pattern. See the [Sample Output](#sample-prometheus-exposition-output)
> section for worked examples.

#### `debvulns_vulnerability_info`

* **Type**: Gauge
* **Value**: Always `1`
* **Labels**:
  * `cve`: CVE identifier (e.g., `CVE-2023-38408`).
  * `package`: Name of the vulnerable installed package (e.g., `openssh-client`).
  * `urgency`: The **raw** debsecan urgency string (`high`, `medium`, `low`, or empty string
    for unspecified).
  * `severity`: The **derived** severity category (`critical`, `high`, `medium`, `low`,
    `negligible`) from `categorise_vulnerabilities()`.
  * `fix_available`: Whether a fix is available (`true` or `false`).
  * `remote`: Whether the vulnerability is remotely exploitable (`true`, `false`, or
    `unknown`). `unknown` corresponds to the `?` flag in the debsecan data.
* **Description**: Core fact metric — one series per active `(cve, package)` pair detected
  on the host. Used as the primary join key and the basis for all alerting expressions.
  Version information is available via `debvulns_package_info` and
  `debvulns_vulnerability_fix_info`.

> [!NOTE]
> `installed_version` and `fix_version` are intentionally absent from this metric. Both
> are high-entropy strings that drive TSDB churn on every package upgrade. They are exposed
> separately (see below) so that operators who do not need them in Prometheus can simply
> omit those metrics from their scrape `metric_relabel_configs`.

---

#### `debvulns_package_info`

* **Type**: Gauge
* **Value**: Always `1`
* **Labels**:
  * `package`: Name of the installed package (e.g., `openssh-client`).
  * `installed_version`: The currently installed version of the package
    (e.g., `1:9.2p1-2+deb12u1`).
* **Description**: Installed version for each Debian package that has at least one active
  vulnerability. One series per **unique package** (not per CVE), so cardinality is bounded
  by the number of vulnerable packages (~tens to hundreds) rather than the number of CVEs.
  Join onto `debvulns_vulnerability_info` on `package` to retrieve the installed version for
  alert annotations or dashboards.

> [!NOTE]
> Storing `installed_version` here rather than on `debvulns_vulnerability_info` means a
> package with 50 active CVEs contributes just **1** version-label series instead of 50.
> Churn (on package upgrade) is isolated to this metric only.

---

#### `debvulns_vulnerability_fix_info`

* **Type**: Gauge
* **Value**: Always `1`
* **Labels**:
  * `cve`: CVE identifier.
  * `package`: Name of the vulnerable installed package.
  * `fix_version`: The version that fixes this vulnerability, taken from `unstable_version`
    or `other_versions`. Empty string `""` if no fixed version is known.
* **Description**: Remediation version for each active `(cve, package)` pair. Kept as a
  separate metric so operators who need fix versions in dashboards can join it in, while
  those who do not can drop it via `metric_relabel_configs` without affecting the core
  alerting metric.

> [!NOTE]
> **Joining fix version into an alert**:
> ```promql
> debvulns_vulnerability_info{severity="critical", fix_available="true"}
>   * on(cve, package) group_left(fix_version)
>   debvulns_vulnerability_fix_info
> ```

---

#### `debvulns_vulnerability_epss_score`

* **Type**: Gauge
* **Value**: Floating-point EPSS probability score between `0.0` and `1.0`.
* **Labels**:
  * `cve`: CVE identifier.
  * `package`: Name of the vulnerable installed package.
* **Description**: The Exploit Prediction Scoring System (EPSS) probability score for the
  detected vulnerability.

> [!NOTE]
> **Design Decision**: The EPSS score is the **metric value**, not a label. This keeps label
> cardinality clean and allows threshold-based PromQL filtering (e.g.,
> `debvulns_vulnerability_epss_score > 0.75`).

#### `debvulns_vulnerability_epss_percentile`

* **Type**: Gauge
* **Value**: Floating-point EPSS percentile rank between `0.0` and `1.0`.
* **Labels**:
  * `cve`: CVE identifier.
  * `package`: Name of the vulnerable installed package.
* **Description**: The EPSS percentile rank of the detected vulnerability.

---

## Label Value Reference

| Label               | Metric(s)                                                           | Possible Values                                   | Notes                                           |
|---------------------|---------------------------------------------------------------------|---------------------------------------------------|-------------------------------------------------|
| `severity`          | `debvulns_vulnerability_info`, `debvulns_vulnerabilities_total`     | `critical`, `high`, `medium`, `low`, `negligible` | Derived by `categorise_vulnerabilities()`       |
| `urgency`           | `debvulns_vulnerability_info`                                       | `high`, `medium`, `low`, `""`                     | Raw debsecan flag value                         |
| `remote`            | `debvulns_vulnerability_info`, `debvulns_vulnerabilities_total`     | `true`, `false`, `unknown`                        | `unknown` maps to the `?` flag in debsecan data |
| `fix_available`     | `debvulns_vulnerability_info`, `debvulns_vulnerabilities_total`     | `true`, `false`                                   | Directly from debsecan `F` flag                 |
| `installed_version` | `debvulns_package_info`                                             | version string                                    | One series per package, not per CVE             |
| `fix_version`       | `debvulns_vulnerability_fix_info`                                   | version string or `""`                            | Empty when no fixed version is known            |

---

## Sample Prometheus Exposition Output

Below is an example of the `/metrics` endpoint output:

```text
# HELP debvulns_exporter_info Metadata about the exporter configuration.
# TYPE debvulns_exporter_info gauge
debvulns_exporter_info{suite="bookworm",version="0.1.0"} 1

# HELP debvulns_scan_status Indicates whether the last vulnerability scan completed successfully.
# TYPE debvulns_scan_status gauge
debvulns_scan_status 1

# HELP debvulns_last_scan_timestamp_seconds Epoch timestamp of when the last scan was executed.
# TYPE debvulns_last_scan_timestamp_seconds gauge
debvulns_last_scan_timestamp_seconds 1780824000

# HELP debvulns_scan_duration_seconds Duration of the last vulnerability scan in seconds.
# TYPE debvulns_scan_duration_seconds gauge
debvulns_scan_duration_seconds 2.45

# HELP debvulns_installed_packages_count Total number of Debian packages currently installed on the host.
# TYPE debvulns_installed_packages_count gauge
debvulns_installed_packages_count 852

# HELP debvulns_vulnerabilities_total Aggregate count of vulnerabilities affecting the system.
# TYPE debvulns_vulnerabilities_total gauge
debvulns_vulnerabilities_total{fix_available="true",remote="true",severity="critical"} 1
debvulns_vulnerabilities_total{fix_available="false",remote="true",severity="high"} 2
debvulns_vulnerabilities_total{fix_available="true",remote="false",severity="medium"} 4
debvulns_vulnerabilities_total{fix_available="true",remote="false",severity="low"} 12

# HELP debvulns_vulnerability_info Core fact metric — one series per active (cve, package) pair.
# TYPE debvulns_vulnerability_info gauge
debvulns_vulnerability_info{cve="CVE-2023-38408",fix_available="true",package="openssh-client",remote="true",severity="critical",urgency="high"} 1
debvulns_vulnerability_info{cve="CVE-2023-4806",fix_available="false",package="libc6",remote="true",severity="high",urgency="high"} 1
debvulns_vulnerability_info{cve="CVE-2024-1234",fix_available="false",package="libfoo1",remote="unknown",severity="medium",urgency="medium"} 1

# HELP debvulns_package_info Installed version for each vulnerable package (one series per package).
# TYPE debvulns_package_info gauge
debvulns_package_info{installed_version="1:9.2p1-2+deb12u1",package="openssh-client"} 1
debvulns_package_info{installed_version="2.36-9+deb12u3",package="libc6"} 1
debvulns_package_info{installed_version="1.2.3-1",package="libfoo1"} 1

# HELP debvulns_vulnerability_fix_info Fix version for each active (cve, package) pair.
# TYPE debvulns_vulnerability_fix_info gauge
debvulns_vulnerability_fix_info{cve="CVE-2023-38408",fix_version="1:9.3p1-1",package="openssh-client"} 1
debvulns_vulnerability_fix_info{cve="CVE-2023-4806",fix_version="",package="libc6"} 1
debvulns_vulnerability_fix_info{cve="CVE-2024-1234",fix_version="",package="libfoo1"} 1

# HELP debvulns_vulnerability_epss_score The EPSS probability score for the detected vulnerability.
# TYPE debvulns_vulnerability_epss_score gauge
debvulns_vulnerability_epss_score{cve="CVE-2023-38408",package="openssh-client"} 0.9423
debvulns_vulnerability_epss_score{cve="CVE-2023-4806",package="libc6"} 0.1245
debvulns_vulnerability_epss_score{cve="CVE-2024-1234",package="libfoo1"} 0.0312

# HELP debvulns_vulnerability_epss_percentile The EPSS percentile rank of the detected vulnerability.
# TYPE debvulns_vulnerability_epss_percentile gauge
debvulns_vulnerability_epss_percentile{cve="CVE-2023-38408",package="openssh-client"} 0.9884
debvulns_vulnerability_epss_percentile{cve="CVE-2023-4806",package="libc6"} 0.4567
debvulns_vulnerability_epss_percentile{cve="CVE-2024-1234",package="libfoo1"} 0.1102
```

### PromQL Join Examples

Joining installed version onto a vulnerability query:
```promql
debvulns_vulnerability_info{severity="critical"}
  * on(package) group_left(installed_version)
  debvulns_package_info
```

Joining fix version for remediation dashboards:
```promql
debvulns_vulnerability_info{fix_available="true"}
  * on(cve, package) group_left(fix_version)
  debvulns_vulnerability_fix_info
```

Full enrichment — all context in one result (e.g., for a Grafana table panel):
```promql
debvulns_vulnerability_info{severity=~"critical|high"}
  * on(package) group_left(installed_version)
  debvulns_package_info
  * on(cve, package) group_left(fix_version)
  debvulns_vulnerability_fix_info
```

---

## Suggested PromQL Alerts

### 1. Alert on Critical Vulnerability with Available Fix

Fires immediately when a critical vulnerability with a fix is detected — this is a
scan result, not a flapping service, so `for: 1m` is sufficient to avoid noise from
a single failed scan write.

```yaml
groups:
  - name: debvulns_alerts
    rules:
      - alert: DebsecanCriticalVulnerabilityWithFix
        expr: debvulns_vulnerabilities_total{severity="critical", fix_available="true"} > 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Critical vulnerability with fix available on {{ $labels.instance }}"
          description: >
            There are {{ $value }} critical vulnerability/vulnerabilities on
            {{ $labels.instance }} that have fixes available.
            Run `apt update && apt upgrade` immediately.
```

### 2. Alert on High EPSS Score Vulnerability

Fires when a vulnerability has an EPSS score > 0.70, indicating active or imminent
exploitation in the wild. The join with `debvulns_vulnerability_info` enriches the alert
with `severity` for routing rules.

```yaml
      - alert: DebsecanHighEpssScoreVulnerability
        expr: >
          debvulns_vulnerability_epss_score > 0.70
            * on(cve, package) group_left(severity)
            debvulns_vulnerability_info
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "High EPSS score vulnerability on {{ $labels.instance }}"
          description: >
            CVE {{ $labels.cve }} affecting package {{ $labels.package }} on
            {{ $labels.instance }} has an EPSS score of {{ $value | humanizePercentage }}.
            This indicates a high likelihood of active exploitation in the wild.
```

### 3. Exporter Health / Scan Failures

```yaml
      - alert: DebsecanScanFailed
        expr: debvulns_scan_status == 0
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "Debsecan scan failed on {{ $labels.instance }}"
          description: >
            The cache-refresh thread on {{ $labels.instance }} failed its last scan.
            The exporter continues serving the previous cached snapshot.
            Check logs with `journalctl -u debvulns-exporter.service`.

      - alert: DebsecanNoScanReporting
        expr: (time() - debvulns_last_scan_timestamp_seconds) > 86400
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Debsecan cache stale on {{ $labels.instance }}"
          description: >
            The debvulns-exporter on {{ $labels.instance }} has not refreshed its
            vulnerability cache in over 24 hours. Check the service status:
            `systemctl status debvulns-exporter.service` and
            `journalctl -u debvulns-exporter.service`.
```

### 4. Alert on Remote-Exploitable Vulnerability with No Fix

Highlights the most dangerous exposure: remotely exploitable with no patch yet
available. Use this to trigger compensating controls (WAF rules, network isolation).

```yaml
      - alert: DebsecanRemoteExploitableNoFix
        expr: debvulns_vulnerabilities_total{remote="true", fix_available="false", severity=~"critical|high"} > 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Unpatched remote-exploitable vulnerability on {{ $labels.instance }}"
          description: >
            There are {{ $value }} remotely exploitable {{ $labels.severity }} severity
            vulnerabilities on {{ $labels.instance }} with no fix currently available.
            Consider compensating controls until a patch is released.
```

---

## Open Questions

The following points require a decision before implementation begins:

1. **Severity categorisation as a label vs. separate metric**: The `categorise_vulnerabilities()`
   function currently implements business logic (EPSS + urgency combined) that is not part of
   the debsecan data spec. Should this logic be considered stable/authoritative, or should the
   exporter expose only raw urgency values and leave categorisation to PromQL recording rules?

2. **EPSS data on scan failure**: If the EPSS download fails but the vulnerability scan
   succeeds, should the cache refresh serve partial metrics (vulnerability info without EPSS
   scores) or retain the last known-good cache and set `debvulns_scan_status 0`?

3. **Refresh interval configuration**: Should the 24 h refresh interval be configurable via a
   CLI flag (`--refresh-interval`) and/or an environment variable? What should the minimum
   allowed interval be to avoid hammering upstream data sources?

4. **Stale-cache behaviour on startup failure**: If the very first scan fails (e.g., no
   network at boot), should the exporter keep returning HTTP 503 until a scan succeeds, or
   should it retry with a shorter backoff before the next scheduled interval?
