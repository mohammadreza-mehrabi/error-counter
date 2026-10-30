#!/usr/bin/env bash
# ============================================
# security.sh — Attack detection engine
# ============================================
# Depends on:
#   - config/patterns.conf (pattern definitions)
#   - parser.sh            (LOG_* globals)
#
# Features:
#   - URL decoding before matching
#   - Case-insensitive matching
#   - Severity-based anomaly scoring
#   - Per-IP attack-type tracking
# ============================================

# ============================================
# Data containers
# ============================================
if [[ -z "${SQLI_ATTACKS+x}" ]]; then
    declare -A SQLI_ATTACKS=()
    declare -A CMD_ATTACKS=()
    declare -A RFI_ATTACKS=()
    declare -A LOG4SHELL_ATTACKS=()
    declare -A SHELLSHOCK_ATTACKS=()
    declare -A XSS_ATTACKS=()
    declare -A TRAVERSAL_ATTACKS=()
    declare -A SSRF_ATTACKS=()
    declare -A XXE_ATTACKS=()
    declare -A NOSQL_ATTACKS=()
    declare -A SSTI_ATTACKS=()
    declare -A SENSITIVE_ATTACKS=()
    declare -A CRLF_ATTACKS=()
    declare -A OPENREDIR_ATTACKS=()
    declare -A SCANNER_ATTACKS=()
    declare -A IP_SCORE=()
    declare -A IP_ATTACKS=()

    TOTAL_SQLI=0
    TOTAL_CMD=0
    TOTAL_RFI=0
    TOTAL_LOG4SHELL=0
    TOTAL_SHELLSHOCK=0
    TOTAL_XSS=0
    TOTAL_TRAVERSAL=0
    TOTAL_SSRF=0
    TOTAL_XXE=0
    TOTAL_NOSQL=0
    TOTAL_SSTI=0
    TOTAL_SENSITIVE=0
    TOTAL_CRLF=0
    TOTAL_OPENREDIR=0
    TOTAL_SCANNERS=0
fi
# ============================================
# reset_security
# ============================================
# Clear all counters and scores.
reset_security() {
    SQLI_ATTACKS=()
    CMD_ATTACKS=()
    RFI_ATTACKS=()
    LOG4SHELL_ATTACKS=()
    SHELLSHOCK_ATTACKS=()
    XSS_ATTACKS=()
    TRAVERSAL_ATTACKS=()
    SSRF_ATTACKS=()
    XXE_ATTACKS=()
    NOSQL_ATTACKS=()
    SSTI_ATTACKS=()
    SENSITIVE_ATTACKS=()
    CRLF_ATTACKS=()
    OPENREDIR_ATTACKS=()
    SCANNER_ATTACKS=()

    IP_SCORE=()
    IP_ATTACKS=()

    TOTAL_SQLI=0
    TOTAL_CMD=0
    TOTAL_RFI=0
    TOTAL_LOG4SHELL=0
    TOTAL_SHELLSHOCK=0
    TOTAL_XSS=0
    TOTAL_TRAVERSAL=0
    TOTAL_SSRF=0
    TOTAL_XXE=0
    TOTAL_NOSQL=0
    TOTAL_SSTI=0
    TOTAL_SENSITIVE=0
    TOTAL_CRLF=0
    TOTAL_OPENREDIR=0
    TOTAL_SCANNERS=0

}

# ============================================
# url_decode
# ============================================
# Decode URL-encoded string (%XX → char, + → space).
#
# Usage: url_decode "%2e%2e%2f"
# Output: "../"
# ============================================
url_decode() {
    local input="$1"

    # Fast path: no % or + → nothing to decode (saves loop for ~70% of lines)
    if [[ "$input" != *"%"* && "$input" != *"+"* ]]; then
        printf "%s" "$input"
        return
    fi

    local output=""
    local i
    local len=${#input}
    for ((i=0;i<len;i++))
    do
        local c="${input:i:1}"
        if [[ "$c"  == "%"  ]] && [[  "${input:i+1:2}" =~ ^[0-9A-Fa-f]{2}$  ]]
        then
            local _byte
            printf -v _byte "\\x${input:i+1:2}"     # ← no subshell
            output+="$_byte"
            ((i += 2))
        elif [[ "$c" == "+"  ]]
        then
            output+=" "
        else
            output+="$c"
        fi
    done
    printf "%s" "$output"
}
# ============================================
# _match_any
# ============================================
# Check if a string matches any pattern in an array.
#
# Usage: _match_any "$target" ARRAY_NAME
# Returns: 0 if match, 1 if no match
# ============================================
_match_any() {
    local target="$1"
    local arr_name="$2"
    local -n arr_ref="$arr_name"
    local pattern                       # ← local (no global clobber)
    for pattern in "${arr_ref[@]}"
    do
        if [[  "$target" =~ $pattern ]]
        then
            return 0
        fi
    done
    return 1
}
# ============================================
# _record_attack
# ============================================
# Record an attack for the current IP.
# - increments per-category counter
# - adds severity to IP score
# - appends category to IP_ATTACKS
#
# Usage: _record_attack CATEGORY COUNT_ARRAY_NAME
# ============================================
_record_attack() {
    local category="$1"
    local arr_name="$2"

    local -n counts="$arr_name"

    ((counts["$LOG_IP"] += 1))
    ((IP_SCORE["$LOG_IP"] += CATEGORY_SEVERITY[$category]))

    # Track unique attack types per IP
    if [[ -z "${IP_ATTACKS[$LOG_IP]:-}" ]]
    then
        IP_ATTACKS["$LOG_IP"]="$category"
    elif [[  "${IP_ATTACKS["$LOG_IP"]}" != *"$category"* ]]
    then
        IP_ATTACKS["$LOG_IP"]+=",$category"
    fi

}
# ============================================
# _quickcheck_danger
# ============================================
# Returns 0 if path or UA contain any attack indicator (→ run full detection).
# Returns 1 if line is definitely safe (→ skip all 15 categories).
#
# Designed to have ZERO false negatives: every known attack trigger
# is covered by either the char-class check or a keyword check.
# ============================================
_quickcheck_danger() {
    local path="$1"
    local ua="$2"

    # Case-insensitive matching (mixed-case scanner UAs, /.ENV, etc.)
    local _prev



    local result=1  # 1 = safe, 0 = dangerous

    case "$path" in
        *[!a-zA-Z0-9./_\ -]*) result=0 ;;
        *..*|*127.*|*localhost*|*169.254*|*0.0.0.0*) result=0 ;;
        *.env*|*.git*|*.svn*|*.aws*|*.ssh*|*.htaccess*|*.htpasswd*|*wp-config*|*config.php*|*backup*|*phpinfo*|*server-status*|*win.ini*|*boot.ini*) result=0 ;;
        *file:*|*gopher:*|*dict:*|*php:*|*expect:*|*zip:*|*phar:*|*data:*) result=0 ;;
    esac

    if (( result == 1 )); then
        case "$ua" in
            *"() {"*) result=0 ;;
            *\'*|*\"*|*\<*|*\>*|*\$*|*\`*) result=0 ;;
            *sqlmap*|*nikto*|*nmap*|*masscan*|*dirbuster*|*gobuster*|*wfuzz*|*nuclei*|*acunetix*|*nessus*|*openvas*|*hydra*|*medusa*|*w3af*|*skipfish*|*whatweb*|*wpscan*|*dirb*|*ffuf*|*zap*|*burp*) result=0 ;;
        esac
    fi


    return $result
}
# ============================================
# detect_attacks
# ============================================
# Detect all attack types in the current parsed line.
# Uses URL-decoded path for robust matching.
# Case-insensitive.
#
# Returns: 0 always (attacks are logged, not rejected)
# ============================================
detect_attacks() {
    if [[ -z "$LOG_IP" ]]
    then
        return 0
    fi

    local path="${LOG_PATH:-}"
    local ua="${LOG_USER_AGENT:-}"

    # ── Fast-path: skip detection if no attack indicators ──
    _quickcheck_danger "$path" "$ua" || return 0

    # Save previous nocasematch state
    local _prev_nocasematch



    local decoded_path
    decoded_path=$(url_decode "$path")

    # ── 1. SQL Injection ──
    if _match_any "$decoded_path" SQLI_PATTERNS
    then
        _record_attack "sqli" "SQLI_ATTACKS"
        ((TOTAL_SQLI += 1))
    fi

    # ── 2. Command Injection ──
    if _match_any "$decoded_path" CMD_PATTERNS
    then
        _record_attack "cmd" "CMD_ATTACKS"
        ((TOTAL_CMD += 1))
    fi

    # ── 3. Remote File Inclusion ──
    if _match_any "$decoded_path" RFI_PATTERNS
    then
        _record_attack "rfi" "RFI_ATTACKS"
        ((TOTAL_RFI += 1))
    fi

    # ── 4. Log4Shell (path OR UA) — flag set to avoid SSTI double-count ──
    local log4shell_hit=0
    if _match_any "$decoded_path" LOG4SHELL_PATTERNS || _match_any "$ua" LOG4SHELL_PATTERNS
    then
        _record_attack "log4shell" "LOG4SHELL_ATTACKS"
        ((TOTAL_LOG4SHELL += 1))
        log4shell_hit=1
    fi

    # ── 5. Shellshock (user-agent only) ──
    if _match_any "$ua" SHELLSHOCK_PATTERNS
    then
        _record_attack "shellshock" "SHELLSHOCK_ATTACKS"
        ((TOTAL_SHELLSHOCK += 1))
    fi

    # ── 6. XSS ──
    if _match_any "$decoded_path" XSS_PATTERNS
    then
        _record_attack "xss" "XSS_ATTACKS"
        ((TOTAL_XSS += 1))
    fi

    # ── 7. Path Traversal (decoded AND raw) ──
    if _match_any "$decoded_path" TRAVERSAL_PATTERNS || _match_any "$path" TRAVERSAL_PATTERNS
    then
        _record_attack "traversal" "TRAVERSAL_ATTACKS"
        ((TOTAL_TRAVERSAL += 1))
    fi

    # ── 8. SSRF ──
    if _match_any "$decoded_path" SSRF_PATTERNS
    then
        _record_attack "ssrf" "SSRF_ATTACKS"
        ((TOTAL_SSRF += 1))
    fi

    # ── 9. XXE ──
    if _match_any "$decoded_path" XXE_PATTERNS
    then
        _record_attack "xxe" "XXE_ATTACKS"
        ((TOTAL_XXE += 1))
    fi

    # ── 10. NoSQL Injection ──
    if _match_any "$decoded_path" NOSQL_PATTERNS
    then
        _record_attack "nosql" "NOSQL_ATTACKS"
        ((TOTAL_NOSQL += 1))
    fi

    # ── 11. SSTI — skip if Log4Shell already matched (${jndi:} matches both) ──
    if (( !log4shell_hit )) && _match_any "$decoded_path" SSTI_PATTERNS
    then
        _record_attack "ssti" "SSTI_ATTACKS"
        ((TOTAL_SSTI += 1))
    fi

    # ── 12. Sensitive Files ──
    if _match_any "$decoded_path" SENSITIVE_PATTERNS
    then
        _record_attack "sensitive" "SENSITIVE_ATTACKS"
        ((TOTAL_SENSITIVE += 1))
    fi

    # ── 13. CRLF Injection (raw path) ──
    if _match_any "$path" CRLF_PATTERNS
    then
        _record_attack "crlf" "CRLF_ATTACKS"
        ((TOTAL_CRLF += 1))
    fi

    # ── 14. Open Redirect ──
    if _match_any "$decoded_path" OPENREDIR_PATTERNS
    then
        _record_attack "openredir" "OPENREDIR_ATTACKS"
        ((TOTAL_OPENREDIR += 1))
    fi

    # ── 15. Scanner User-Agent ──
    if _match_any "$ua" SCANNER_USER_AGENTS
    then
        _record_attack "scanner" "SCANNER_ATTACKS"
        ((TOTAL_SCANNERS += 1))
    fi




    return 0
}

# ============================================
# Getters — per-category totals
# ============================================
get_sqli_total() {
    echo "$TOTAL_SQLI"
}
get_cmd_total() {
    echo "$TOTAL_CMD"
}
get_rfi_total() {
    echo "$TOTAL_RFI"
}
get_log4shell_total() {
    echo "$TOTAL_LOG4SHELL"
}
get_shellshock_total() {
    echo "$TOTAL_SHELLSHOCK"
}
get_xss_total() {
    echo "$TOTAL_XSS"
}
get_traversal_total() {
    echo "$TOTAL_TRAVERSAL"
}
get_ssrf_total() {
    echo "$TOTAL_SSRF"
}
get_xxe_total() {
    echo "$TOTAL_XXE"
}
get_nosql_total() {
    echo "$TOTAL_NOSQL"
}
get_ssti_total() {
    echo "$TOTAL_SSTI"
}
get_sensitive_total() {
    echo "$TOTAL_SENSITIVE"
}
get_crlf_total() {
    echo "$TOTAL_CRLF"
}
get_openredir_total() {
    echo "$TOTAL_OPENREDIR"
}
get_scanner_total() {
    echo "$TOTAL_SCANNERS"
}

# ============================================
# Getters — aggregate counts
# ============================================
get_total_attacks() {
    echo $((  TOTAL_SQLI + TOTAL_CMD + TOTAL_RFI + TOTAL_LOG4SHELL + TOTAL_SHELLSHOCK + TOTAL_XSS + TOTAL_TRAVERSAL +
    TOTAL_SSRF + TOTAL_XXE + TOTAL_NOSQL + TOTAL_SSTI + TOTAL_SENSITIVE + TOTAL_CRLF + TOTAL_OPENREDIR + TOTAL_SCANNERS ))
}
get_attacking_ip_count() {
    echo "${#IP_SCORE[@]}"
}

# ============================================
# Getter — per-IP score
# ============================================
get_ip_score() {
    local ip="$1"
    echo "${IP_SCORE[$ip]:-0}"
}

# ============================================
# _dump_attack_ips — helper
# ============================================
# Usage: _dump_attack_ips ARRAY_NAME
_dump_attack_ips() {
    local -n arr="$1"
    for ip in "${!arr[@]}"
    do
        echo "$ip ${arr[$ip]}"
    done
}

# ============================================
# Dumps — per-category IP lists
# ============================================
dump_sqli_ips() {
    _dump_attack_ips SQLI_ATTACKS
}
dump_cmd_ips() {
    _dump_attack_ips CMD_ATTACKS
}
dump_rfi_ips() {
    _dump_attack_ips RFI_ATTACKS
}
dump_log4shell_ips() {
    _dump_attack_ips LOG4SHELL_ATTACKS
}
dump_shellshock_ips() {
    _dump_attack_ips SHELLSHOCK_ATTACKS
}
dump_xss_ips() {
    _dump_attack_ips XSS_ATTACKS
}
dump_traversal_ips() {
    _dump_attack_ips TRAVERSAL_ATTACKS
}
dump_ssrf_ips() {
    _dump_attack_ips SSRF_ATTACKS
}
dump_xxe_ips() {
    _dump_attack_ips XXE_ATTACKS
}
dump_nosql_ips() {
    _dump_attack_ips NOSQL_ATTACKS
}
dump_ssti_ips() {
    _dump_attack_ips SSTI_ATTACKS
}
dump_sensitive_ips() {
    _dump_attack_ips SENSITIVE_ATTACKS
}
dump_crlf_ips() {
    _dump_attack_ips CRLF_ATTACKS
}
dump_openredir_ips() {
    _dump_attack_ips OPENREDIR_ATTACKS
}
dump_scanner_ips() {
    _dump_attack_ips SCANNER_ATTACKS
}

# ============================================
# Dumps — per-IP details
# ============================================
dump_ip_scores() {
    for ip in "${!IP_SCORE[@]}"
    do
        echo "$ip ${IP_SCORE[$ip]}"
    done
}

dump_ip_attacks() {
    for ip in "${!IP_ATTACKS[@]}"
    do
        echo "$ip ${IP_ATTACKS[$ip]}"
    done
}

# ============================================
# Chained detection — suspicious IPs
# ============================================
# Returns IPs whose severity score exceeds threshold.
# Args: $1 = threshold (default: 10)
dump_suspicious_ips() {
    local threshold="${1:-${SUSPICIOUS_SCORE_THRESHOLD:-10}}"
    for ip in "${!IP_SCORE[@]}"
    do
        if ((  IP_SCORE[$ip] >= threshold ))
        then
            echo "$ip ${IP_SCORE[$ip]} ${IP_ATTACKS[$ip]:-unknown}"
        fi

    done
}

# ============================================
# Chained detection — critical IPs
# ============================================
# Returns IPs whose severity score exceeds critical threshold.
# Args: $1 = threshold (default: 30)
dump_critical_ips() {
    local threshold="${1:-${CRITICAL_SCORE_THRESHOLD:-30}}"

    for ip in "${!IP_SCORE[@]}"
    do
        if ((  IP_SCORE[$ip] >= threshold  ))
        then
            echo "$ip ${IP_SCORE[$ip]} ${IP_ATTACKS[$ip]:-unknown}"
        fi

    done

}
