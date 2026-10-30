# Usage Guide

Detailed instructions for running error-counter.

---

## Quick Start

```bash
# Analyze an Nginx access log
error-counter /var/log/nginx/access.log
```

Output goes to stdout (terminal) and stderr (warnings). Exit code tells
you the result:

- `0` — clean, no threats
- `1` — usage error (bad args, missing file, corrupt config)
- `2` — threats detected

---

## Command Line Options

```
error-counter <log_file> [OPTIONS]

Options:
  -o, --output FILE    Save report to FILE (in addition to stdout)
  -s, --suspicious N   Suspicious score threshold (default: 10)
  -c, --critical N     Critical score threshold (default: 30)
  -h, --help           Show help
  -V, --version        Show version
```

### `-o FILE` — Save report

```bash
error-counter access.log -o report.txt
```

Writes the report to both `report.txt` and stdout. If `report.txt` exists,
it will be **overwritten** (not appended).

The script waits for `tee` to finish before exiting — no truncated files,
even on interruption (Ctrl+C).

### `-s N` — Suspicious threshold

IPs with score ≥ `N` appear in the **SUSPICIOUS IPs** section
(unless also ≥ `-c`, then they go to CRITICAL).

```bash
# Lower threshold: more IPs in SUSPICIOUS
error-counter access.log -s 5

# Higher threshold: fewer IPs, less noise
error-counter access.log -s 20
```

Default: `10` (one CRITICAL attack, or ~2 HIGH, or ~3 MEDIUM).

### `-c N` — Critical threshold

IPs with score ≥ `N` appear in the **CRITICAL THREATS** section,
with `IMMEDIATE ACTION REQUIRED` banner.

```bash
# Only worst offenders in CRITICAL
error-counter access.log -c 50

# Everything above SUSPICIOUS is CRITICAL
error-counter access.log -s 10 -c 10
```

Default: `30` (three CRITICAL attacks, or one SQLi + sustained probing).

---

## Config Files

Located in `$PREFIX/etc/error-counter/` (default `/usr/local/etc/error-counter/`):

- `thresholds.conf` — score thresholds (`-s` and `-c` override these)
- `patterns.conf` — attack regexes and severity weights

### Editing thresholds

```bash
sudo nano /usr/local/etc/error-counter/thresholds.conf
```

```bash
SUSPICIOUS_SCORE_THRESHOLD=10
CRITICAL_SCORE_THRESHOLD=30
TOP_ENDPOINTS=10
```

Changes take effect on the next run. CLI flags override config.

### Editing patterns

```bash
sudo nano /usr/local/etc/error-counter/patterns.conf
```

Each category is a bash array of POSIX Extended Regular Expressions (ERE):

```bash
SQLI_PATTERNS=(
    "'[[:space:]]*OR[[:space:]]*'?1'?[[:space:]]*=[[:space:]]*'?1"
    "UNION[[:space:]]+(ALL[[:space:]]+)?SELECT"
    ...
)
```

Weights are in `CATEGORY_SEVERITY`:

```bash
declare -A CATEGORY_SEVERITY=(
    [sqli]=10
    [xss]=7
    ...
)
```

**To add a pattern to an existing category:** just append to the array.

**To add a new category:** requires code change in `lib/security.sh`. See
the "Adding a new category" section below.

---

## Reading the Report

### Header

```
File:        /var/log/nginx/access.log
Lines:       10000
Analyzed:    9895
Skipped:     105
Empty:       0
Generated:   2026-10-30 03:55:07
```

| Field        | Meaning                                      |
| ------------ | -------------------------------------------- |
| **Lines**    | Total lines in file (from `awk END{NR}`)     |
| **Analyzed** | Lines that parsed AND had a valid IP         |
| **Skipped**  | Lines that failed to parse or had invalid IP |
| **Empty**    | Blank lines (skipped without warning)        |

**Invariant:** `Analyzed + Skipped + Empty = Lines` (always).

If `Skipped` is high (>1% of lines), your log format is not exactly
Nginx `combined`. Check `[WARN]` output on stderr.

### Overview

```
Total requests:           9895
Unique IPs:               6907
Unique endpoints:         69
Unique statuses:          10
Unique methods:           2
Unique user agents:       19
```

Total requests = Analyzed (every valid line is one request).

### Status Codes

HTTP status codes with count and percentage. Color-coded:

- Green — 2xx
- Cyan — 3xx
- Yellow — 4xx
- Red — 5xx

### Security Analysis

15 attack categories, each with count and severity. Only categories
with at least one detection are shown.

`Total attacks` = sum of all categories. Note: one line can trigger
multiple categories (e.g., `?url=http://127.0.0.1` matches both SSRF
and RFI), so `Total attacks` can exceed the number of attack lines.

### Suspicious IPs

IPs with score ≥ `-s` but < `-c`. Sorted by score descending. Yellow.

```
  (score >= 10, below 30)
  IP                                       SCORE    ATTACK TYPE
  ────────────────────────────────────────────────────
  10.0.0.7                                 20       rfi
  10.0.0.4                                 20       log4shell
```

### Critical Threats

IPs with score ≥ `-c`. Sorted by score descending. Red.
Banner: `IMMEDIATE ACTION REQUIRED`.

```
  (score >= 30) - IMMEDIATE ACTION REQUIRED
  IP                                       SCORE    ATTACK TYPES
  ────────────────────────────────────────────────────
  45.155.141.1                             4844     sqli,scanner
  45.5.8.3                                 2107     traversal
```

IPs are never shown in both sections — critical IPs appear only in CRITICAL.

### Anomalies

Invalid HTTP status codes (e.g., `999`) or methods (e.g., `BREW`) found
in the log. Presence indicates log corruption or a custom protocol.

---

## Exit Codes in Scripts

The distinction between 0, 1, 2 lets your automation react correctly:

```bash
#!/usr/bin/env bash

error-counter /var/log/nginx/access.log > /tmp/report.txt
case $? in
    0)
        echo "✓ Log is clean"
        ;;
    1)
        echo "✗ Tool failed (check config, file path)" >&2
        exit 1
        ;;
    2)
        echo "⚠ Threats detected — sending alert" >&2
        send_to_security_team /tmp/report.txt
        exit 2
        ;;
esac
```

---

## Performance Tips

For logs larger than 1M lines, or if you run analysis frequently:

### 1. Log rotation

Split logs daily with `logrotate` (default on most distros). Analyze
one day at a time:

```bash
error-counter /var/log/nginx/access.log.1
```

### 2. Reduce patterns

If you don't need all 15 categories, remove some from
`/usr/local/etc/error-counter/patterns.conf`. Each category removed
saves ~5-10% processing time.

### 3. Higher thresholds

Higher `-s` and `-c` reduce the size of the CRITICAL/SUSPICIOUS sections
(less output), but not processing time.

---

## Adding a New Category

To add a detection category (e.g., "prototype pollution"):

### 1. Add patterns in `patterns.conf`

```bash
PROTO_POLLUTION_PATTERNS=(
    "__proto__"
    "constructor\\[.*\\]"
)

declare -A CATEGORY_SEVERITY=(
    ...
    [proto]=7
)
```

### 2. Add detection in `lib/security.sh`

Inside `detect_attacks`, after other categories:

```bash
if _match_any "$decoded_path" PROTO_POLLUTION_PATTERNS
then
    _record_attack "proto" "PROTO_POLLUTION_ATTACKS"
    ((TOTAL_PROTO_POLLUTION += 1))
fi
```

### 3. Declare counter in `security.sh`

```bash
declare -A PROTO_POLLUTION_ATTACKS=()
TOTAL_PROTO_POLLUTION=0
```

### 4. Add getter

```bash
get_proto_pollution_total() {
    echo "$TOTAL_PROTO_POLLUTION"
}
```

### 5. Add to report in `reporter.sh`

```bash
_report_attack_row "Prototype Pollution" "$(get_proto_pollution_total)" "HIGH"
```

### 6. Test

```bash
echo "10.0.0.1 - - [ts] \"GET /?__proto__=x HTTP/1.1\" 200 100 \"-\" \"UA\"" > /tmp/test.log
./bin/error_counter.sh /tmp/test.log 2>&1 | grep "Prototype"
```

---

## Troubleshooting

### "missing library" or "missing config"

Error like:

```
error-counter: missing library: /usr/local/lib/error-counter/colors.sh
```

The install is incomplete. Reinstall:

```bash
sudo ./install.sh
```

### "bash 4.4+ required"

```
error-counter: bash 4.4+ required (found 3.2.57(1)-release)
```

macOS ships bash 3.2 (from 2007). Install newer:

```bash
brew install bash
```

Then use `/usr/local/bin/bash` or `/opt/homebrew/bin/bash`.

### "N line(s) skipped"

```
[WARN] 500 line(s) skipped (unparseable or invalid IP)
```

Your log format is not exactly Nginx `combined`. Check:

```bash
head -1 /var/log/your.log
```

Compare to:

```
192.168.1.1 - - [10/Oct/2024:13:55:36 -0700] "GET / HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
```

Common differences:

- Apache `LogFormat` with different field order
- No referer/user-agent fields (Common Log Format)
- IPv6 with zone ID (`fe80::1%eth0` — not parsed by v1)

### Report is empty or "No attacks detected" but log has attacks

Possible causes:

1. **Wrong log format** — check `Skipped` count in header
2. **Patterns don't cover your attack** — check `patterns.conf`
3. **Attack in Referer or body** — v1 only checks path and User-Agent

---

## Integration Examples

### Cron job (daily report)

`/etc/cron.daily/error-counter`:

```bash
#!/bin/sh
REPORT=/var/log/error-counter-$(date +%F).txt
/usr/local/bin/error-counter /var/log/nginx/access.log.1 -o "$REPORT"

exit_code=$?
if [ "$exit_code" -eq 2 ]; then
    mail -s "SECURITY: attacks in nginx log" security@example.com < "$REPORT"
fi
```

### GitHub Actions (CI)

```yaml
- name: Analyze Nginx log
  run: |
    ./bin/error_counter.sh test.log -o report.txt
    exit_code=$?
    if [ "$exit_code" -eq 2 ]; then
      echo "::warning::Attacks detected in log"
      cat report.txt
    fi
    exit 0  # don't fail the build
```

### In a Docker container

```bash
docker run --rm \
    -v /var/log/nginx:/logs:ro \
    -v "$PWD:/opt/ec:ro" \
    bash:5.2 \
    bash /opt/ec/bin/error_counter.sh /logs/access.log
```
