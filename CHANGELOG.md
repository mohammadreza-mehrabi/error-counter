# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

_Nothing yet._

---

## [1.0.0] — 2026-10-30

First stable release. 22 bugs fixed since the initial prototype,
plus 4× performance improvement through multiple optimizations.

### Added

- IPv6 address support (was IPv4-only)
- Apache compatibility: `-` accepted for zero-byte responses (304/204/HEAD)
- `ident` and `authuser` parsing (Basic Auth logs now work)
- Per-IP attack tracking with attack-type accumulation
- Three exit codes: `0` (clean), `1` (usage error), `2` (threats detected)
- `Skipped` and `Empty` counts in the report header
- `docs/usage.md` and `docs/examples.md`
- `install.sh` and `Makefile`
- `.gitignore` with exception for test fixtures

### Changed

- **`patterns.conf`** no longer defines `SUSPICIOUS_SCORE_THRESHOLD` or
  `CRITICAL_SCORE_THRESHOLD` — these now live only in `thresholds.conf`.
  Before this change, `thresholds.conf` was silently overridden.
- **Report layout:** IP column widened from 20 to 40 characters for full IPv6
- **`report_suspicious_ips`:** critical IPs no longer appear in this section
  (they were previously duplicated in both SUSPICIOUS and CRITICAL)
- **Exit code for threats** is now `2` (was `1`, colliding with usage errors)

### Fixed

**Parsing (`parser.sh`, `validators.sh`):**

- IPv6 addresses were silently skipped
- Apache `-` response size caused the entire line to be skipped
- Lines with non-`-` authuser were rejected (Basic Auth)

**Detection (`patterns.conf`, `security.sh`):**

- Shellshock pattern `()` was an empty group in ERE — never matched
- SSRF/RFI patterns had empty alternative `(=||%3[Dd])` — matched any path
  containing `localhost`, including `/blog/localhost-guide` (false positive)
- Scanner UA patterns used substring matching — `Zapier` matched as `ZAP`,
  `unmapped` as `nmap`, `dirbased` as `dirb`
- Log4Shell payloads `${jndi:...}` were also counted as SSTI (double-counted
  score: 17 points instead of 10)
- `NOSQL_PATTERNS` used double quotes and crashed under `set -u` on `$ne`
- `_prev_nocasematch=$(shopt -p nocasematch)` returned 1 when option was OFF,
  killing the script under `set -e` on the first line

**Reporting (`reporter.sh`):**

- Critical color used hardcoded `30` instead of `$CRITICAL_SCORE_THRESHOLD`
- `report_suspicious_ips` returned 1 when all suspicious IPs were critical,
  breaking `set -e` and skipping CRITICAL/ANOMALIES/FOOTER sections
- `wc -l` off-by-one on files without trailing newline
- IP column was 20 chars — IPv6 addresses (up to 39) broke table alignment

**Entry point (`bin/error_counter.sh`):**

- No bash 4.4+ version check (script would fail cryptically on bash 3.x)
- Installed-mode detection used directory check — fallback was dead code
- Libs and configs were sourced without existence checks — cryptic error
- `-o` output used `exec > >(tee ...)` without waiting — truncated files
- `TMP_OUTPUT` was referenced in `cleanup` but never set (dead code)
- Skipped lines were silently dropped — no warning, no count

**Config:**

- `thresholds.conf` overrides were ignored (see Changed above)

### Optimized

- **`url_decode`:** replaced `$(printf "\xNN")` with `printf -v` (eliminates
  one subshell fork per `%XX` byte)
- **`url_decode`:** fast-path returns input unchanged for URLs without `%` or `+`
- **`_quickcheck_danger`** (new): skips all 15 detection categories for lines
  that cannot possibly contain an attack. Safe by construction — every known
  attack trigger is covered. ~70% of typical traffic skips detection.
- **`_match_any`:** `pattern` variable now `local` (was clobbering global)
- **`nocasematch`:** set once in `error_counter.sh`, removed per-call
  `shopt -p nocasematch` subshells (~130K forks eliminated per 100K log)

### Performance

Measured on realistic Nginx logs (80% normal traffic, 20% attacks).

| Log size   | Before      | After | Speedup  |
| ---------- | ----------- | ----- | -------- |
| 10K lines  | 51s         | ~18s  | **2.8×** |
| 100K lines | 648s        | 188s  | **3.4×** |
| 1M lines   | 6500s (est) | 1570s | **4.1×** |

**Validation** on 1M-line log:

- `Lines=1,000,000 = Analyzed=989,932 + Skipped=8,063 + Empty=2,005`
- `Total attacks=334,997 = sum of 13 categories`
- All 12 attacker IPs in `CRITICAL THREATS` with correct severity weights
- 33/33 attack payloads detected by fast-path filter
- 8/8 safe paths correctly skipped (no false positives)

---

## [0.1.0] — 2026-10-15

Initial prototype (not publicly released).

- Nginx `combined` log parsing (IPv4 only)
- 15 attack categories
- Basic text report
