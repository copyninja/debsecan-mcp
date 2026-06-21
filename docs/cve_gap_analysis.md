# CVE Gap Analysis: debsecan vs debvulns

> Produced: 2026-06-14 | System: Debian forky (trixie) | Suite: forky

## Numbers

| Tool | Unique CVEs |
|---|---|
| `debsecan` | 3,854 |
| `debvulns` | 918 |
| **Missing from debvulns** | **2,936** |

All 2,936 missing CVEs fell into a **single root cause**: a wrong `is_vulnerable()` implementation.

---

## Root Cause: `is_vulnerable()` used `>=` instead of exact membership for `other_versions`

### The data format

The Debian Security Tracker feed (`https://security-tracker.debian.org/tracker/debsecan/release/1/<suite>`)
encodes each vulnerability as:

```
<pkg_name>,<vuln_index>,<flags>,<unstable_version>,<other_versions...>
```

- **`unstable_version`** — the version in which the bug was fixed in Debian unstable/sid.
- **`other_versions`** — exact version strings where the bug was fixed in specific
  **stable backport branches** (e.g. `6.1.174-1` = fixed in bookworm's 6.1.x kernel series).

### debsecan's exact `is_vulnerable` logic

From `/usr/bin/debsecan` (the installed binary):

```python
def is_vulnerable(self, bp, sp):
    if self.binary_package and bp.name == self.package:
        # BINARY entry: only check unstable_version
        if self.unstable_version:
            return bp.version < self.unstable_version
        else:
            return True
    elif sp.name == self.package:
        # SOURCE entry: exact membership for other_versions
        if self.unstable_version:
            return sp.version < self.unstable_version \
                   and sp.version not in self.other_versions
        else:
            return sp.version not in self.other_versions
    else:
        return False
```

Key points:
1. **Binary entries** — `other_versions` is **never consulted**. Only `unstable_version` matters.
2. **Source entries** — `other_versions` is an **exact set** (`not in`). A package is considered
   fixed only if its version is literally one of those strings, not if it's numerically greater.

### Our buggy implementation

```python
# WRONG (old code):
if self.unstable_version:
    if v >= self.unstable_version:
        return False
    for ov in self.other_versions:
        if v >= ov:        # ← WRONG: >= instead of exact membership
            return False
    return True
```

### The concrete failure: `linux-kbuild-6.5.0-5`

This old kernel build-tools package was still installed on the system alongside newer kernels:

```
Package:        linux-kbuild-6.5.0-5
Version:        6.5.13-1
Source:         linux
Source-Version: 6.5.13-1
```

For `CVE-2022-48772` (kernel vulnerability):
```
unstable_version = 6.9.7-1
other_versions   = [6.1.174-1, 6.1.170-3, 6.1.162-1, ...]   ← bookworm 6.1.x branch fixes
```

**Our check (wrong):**
```
6.5.13-1 < 6.9.7-1   → True  (not fixed in unstable, keep going)
6.5.13-1 >= 6.1.174-1 → True  (BUG: treats 6.5.x as "fixed" by a 6.1.x backport!)
→ is_vulnerable() = False  (wrong)
```

**debsecan's check (correct):**
```
6.5.13-1 < 6.9.7-1               → True
6.5.13-1 not in [6.1.174-1, ...] → True  (exact membership — it's not in the list)
→ is_vulnerable() = True  (correct)
```

**Why `6.5.13-1 >= 6.1.174-1` is numerically True:**  
Debian version comparison is numeric field-by-field. `6.5 > 6.1`, so the `>=` check
passes — but semantically `6.5.13` is a *different upstream branch*, not a patched
version of the `6.1.x` branch. The `6.1.174-1` fix only applies to kernels in the
`6.1.x` series.

---

## Fix Applied

### `src/debsecan_mcp/vulnerability.py`

```python
# BEFORE (buggy):
if self.unstable_version:
    if v >= self.unstable_version:
        return False
    for ov in self.other_versions:
        if v >= ov:
            return False
    return True
else:
    if not self.other_versions:
        return True
    for ov in self.other_versions:
        if v >= ov:
            return False
    return True

# AFTER (correct, matching debsecan exactly):
if self.is_binary:
    if installed_pkg.name != self.package:
        return False
    v = installed_pkg.version
    # Binary entries: only unstable_version matters
    if self.unstable_version:
        return v < self.unstable_version
    else:
        return True
else:
    if installed_pkg.source != self.package:
        return False
    v = installed_pkg.source_version
    # Source entries: exact membership check for other_versions
    if self.unstable_version:
        return v < self.unstable_version and v not in self.other_versions
    else:
        return v not in self.other_versions
```

---

## Impact

- **2,936 kernel CVEs** were previously missed (all associated with `linux-kbuild-6.5.0-5`)
- **1 non-kernel CVE** for `intel-microcode` was also affected
- After the fix, debvulns should report significantly more CVEs matching debsecan

---

## Regression Tests

### `test_is_vulnerable_cross_branch_other_version_not_applied`

`tests/test_vulnerability.py::TestVulnerabilityIsVulnerable`

Directly models the `linux-kbuild-6.5.0-5` scenario with three assertions:
- `linux-kbuild-6.5.0-5` (source `6.5.13-1`) → **vulnerable** ✅
- `linux-image-6.1.0-30-amd64` (source `6.1.174-1`, exact fix point) → **not vulnerable** ✅
- `linux-image-6.1.0-4-amd64` (source `6.1.11-1`, below fix point) → **vulnerable** ✅
- `linux-image-7.0.10-amd64` (source `7.0.10-1`, above unstable fix) → **not vulnerable** ✅

### Integration test: `TEMP-*` identifiers

`tests/test_cli.py::TestDebsecanIntegration::test_debvulns_cves_are_subset_of_debsecan`

**Second issue found after the `>=` fix**: the integration test only collected `CVE-*`
prefixed IDs from `debsecan` output, silently ignoring `TEMP-XXXXXXX-XXXXXX` identifiers.

Debian's Security Tracker assigns `TEMP-*` IDs to vulnerabilities that have not yet
received an official CVE. `debsecan` reports these with `TEMP-` prefixes; our feed
parser includes them too. Since the test excluded them from `debsecan_ids` but included
them in `debvulns_ids`, three entries (`TEMP-0000000-3CAD20`, `TEMP-0000000-E5FBCA`,
`TEMP-1140176-50C86A`) appeared as false positives.

**Fix**: the debsecan ID collection loop now accepts both `CVE-` and `TEMP-` prefixes.
Variables renamed from `debsecan_cves`/`debvulns_cves` to `debsecan_ids`/`debvulns_ids`
to reflect that both CVE and TEMP identifiers are tracked.
