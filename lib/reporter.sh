#!/usr/bin/env bash
# ============================================
# reporter.sh — Report generation
# ============================================
# Depends on:
#   - colors.sh
#   - analyzer.sh
#   - security.sh
#   - config/thresholds.conf
# ============================================

# ============================================
# Header
# ============================================
report_header() {
    local log_file="${1:-unknown}"
    local file_size
    file_size=$(awk 'END{print NR}' "$log_file" 2>/dev/null || echo "0")
    echo ""
    echo -e "${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║           ERROR COUNTER — LOG ANALYSIS REPORT             ║${NC}"
    echo -e "${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BLUE}File:${NC}        $log_file"
    echo -e "  ${BLUE}Lines:${NC}       $file_size"
    echo -e "  ${BLUE}Analyzed:${NC}    $TOTAL_REQUESTS"
    echo -e "  ${BLUE}Skipped:${NC}     $(get_skipped_lines)"
    echo -e "  ${BLUE}Empty:${NC}       $(get_empty_lines)"
    echo -e "  ${BLUE}Generated:${NC}   $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
}

# ============================================
# Overview
# ============================================
report_overview() {
    echo -e "${BOLD}═══════════════════ OVERVIEW ═══════════════════${NC}"
    echo ""
    printf "  %-25s %s\n" "Total requests:" "$(get_total_requests)"
    printf "  %-25s %s\n" "Unique IPs:" "$(get_unique_ip_count)"
    printf "  %-25s %s\n" "Unique endpoints:" "$(get_unique_endpoint_count)"
    printf "  %-25s %s\n" "Unique statuses:" "$(get_unique_status_count)"
    printf "  %-25s %s\n" "Unique methods:" "$(get_unique_method_count)"
    printf "  %-25s %s\n" "Unique user agents:" "$(get_unique_ua_count)"
    echo ""
}
# ============================================
# Status codes
# ============================================
report_status_codes() {
    local total_4xx total_5xx
    total_4xx=$(get_4xx_count)
    total_5xx=$(get_5xx_count)

    echo -e "${BOLD}═══════════════════ STATUS CODES ═══════════════════${NC}"
    echo ""
    printf " %-12s %-10s %s\n" "CODE" "COUNT" "PERCENT"
    echo " ────────────────────────────────────"

    local total="$TOTAL_REQUESTS"

    while IFS=' ' read -r code count
    do
        local percent=0
        if ((  total > 0  ))
        then
            percent=$(( count * 100 / total  ))
        fi

        local color="$NC"
        if [[ "$code" =~ ^5  ]]
        then
            color="$RED"
        fi
        if [[  "$code" =~ ^4 ]]
        then
            color="$YELLOW"
        fi
        if [[  "$code" =~ ^3  ]]
        then
            color="$CYAN"
        fi
        if [[ "$code"  =~ ^2  ]]
        then
            color="$GREEN"
        fi

        printf "  ${color}%-12s %-10d %d%%${NC}\n" "$code" "$count" "$percent"
    done < <(dump_status_counts | sort -k2 -rn)
    echo ""
    printf "  ${YELLOW}4xx errors:${NC}  %d\n" "$total_4xx"
    printf "  ${RED}5xx errors:${NC} %d\n"  "$total_5xx"
    echo ""
}
# ============================================
# Top endpoints
# ============================================
report_top_endpoints() {
    local n="${1:-${TOP_ENDPOINTS:-10}}"

    echo -e "${BOLD}═══════════════════ TOP ENDPOINTS ═══════════════════${NC}"
    echo ""
    printf "  %-50s %s\n" "PATH" "REQUESTS"
    echo " ─────────────────────────────────────────────────────"

    while IFS=' ' read -r path count
    do
        local display="$path"
        if (( ${#display} > 47 ))
        then
            display="${display:0:44}..."
        fi
        printf "  %-50s %d\n" "$display" "$count"
    done < <(dump_path_counts | sort -k2 -rn | head -n "$n")

    echo ""
}

# ============================================
# Security analysis
# ============================================
report_security() {
    local total_attacks
    total_attacks=$(get_total_attacks)

    echo -e "${BOLD}═══════════════════ SECURITY ANALYSIS ═══════════════════${NC}"
    echo ""

    if (( total_attacks == 0   ))
    then
        echo -e "${GREEN}No attacks detected${NC}"
        echo ""
        return
    fi

    printf "  %-25s %s\n" "Total attacks:" "$total_attacks"
    printf "  %-25s %s\n" "Attacking IPs:" "$(get_attacking_ip_count)"
    echo ""
    printf "  %-25s %-10s %s\n" "ATTACK TYPE" "COUNT" "SEVERITY"
    echo " ────────────────────────────────────────────────────"

    _report_attack_row "SQL Injection"          "$(get_sqli_total)"         "CRITICAL"
    _report_attack_row "Command Injection"      "$(get_cmd_total)"          "CRITICAL"
    _report_attack_row "RFI"                    "$(get_rfi_total)"          "CRITICAL"
    _report_attack_row "Log4Shell"              "$(get_log4shell_total)"    "CRITICAL"
    _report_attack_row "Shellshock"             "$(get_shellshock_total)"   "CRITICAL"
    _report_attack_row "XSS"                    "$(get_xss_total)"          "HIGH"
    _report_attack_row "Path Traversal"         "$(get_traversal_total)"    "HIGH"
    _report_attack_row "SSRF"                   "$(get_ssrf_total)"         "HIGH"
    _report_attack_row "XXE"                    "$(get_xxe_total)"          "HIGH"
    _report_attack_row "NoSQl Injection"        "$(get_nosql_total)"        "HIGH"
    _report_attack_row "SSTI"                   "$(get_ssti_total)"         "HIGH"
    _report_attack_row "Sensitive Files"        "$(get_sensitive_total)"    "MEDIUM"
    _report_attack_row "CRLF Injection"         "$(get_crlf_total)"         "MEDIUM"
    _report_attack_row "Open Redirect"          "$(get_openredir_total)"    "LOW"
    _report_attack_row "Scanner/Bot"            "$(get_scanner_total)"      "INFO"

    echo ""
}
_report_attack_row() {
    local name="$1"
    local count="$2"
    local severity="$3"

    ((count == 0)) && return

    local color="$NC"
    case "$severity" in
        CRITICAL) color="$RED" ;;
        HIGH)     color="$YELLOW" ;;
        MEDIUM)   color="$CYAN" ;;
        LOW)      color="$GREEN" ;;
        INFO)     color="$BLUE" ;;
    esac
    printf "  ${color}%-25s %-10s (%s)${NC}\n" "$name" "$count" "$severity"
}
# ============================================
# Suspicious IPs
# ============================================
report_suspicious_ips() {
    local threshold="${1:-${SUSPICIOUS_SCORE_THRESHOLD:-10}}"
    local critical="${2:-${CRITICAL_SCORE_THRESHOLD:-30}}"
    local suspicious
    suspicious=$(dump_suspicious_ips "$threshold")

    [[ -z "$suspicious"  ]] && return

    # If every suspicious IP is already in the CRITICAL section, skip entirely.
    local has_non_critical=0
    while IFS=' ' read -r _ip _score _attacks
    do
        if (( _score < critical ))
        then
            has_non_critical=1
            break
        fi
    done <<< "$suspicious"
    (( has_non_critical )) || return 0

    echo -e "${BOLD}═══════════════════ SUSPICIOUS IPs ═══════════════════${NC}"
    echo -e "  (score >= $threshold, below $critical)"
    echo ""
    printf "  %-40s %-8s %s\n" "IP" "SCORE" "ATTACK TYPE"
    echo "  ────────────────────────────────────────────────────"

    echo "$suspicious" | sort -k2 -rn | while IFS=' ' read -r ip score attacks
    do
        (( score >= critical )) && continue
        printf "  ${YELLOW}%-40s %-8s %s${NC}\n" "$ip" "$score" "$attacks"
    done
    echo ""
}
# ============================================
# Critical IPs
# ============================================
report_critical_ips() {
    local threshold="${1:-${CRITICAL_SCORE_THRESHOLD:-30}}"
    local critical
    critical=$(dump_critical_ips "$threshold")

    [[  -z  "$critical"  ]] && return

    echo -e "${BOLD}${RED}═══════════════════  CRITICAL THREATS ═══════════════════${NC}"
    echo -e "  (score >= $threshold) - IMMEDIATE ACTION REQUIRED"
    echo ""
    printf "  ${RED}%-40s %-8s %s${NC}\n" "IP" "SCORE" "ATTACK TYPES"
    echo "  ────────────────────────────────────────────────────"
    echo "$critical" | sort -k2 -rn | while IFS=' ' read -r ip score attacks
    do
        printf "  ${RED}%-40s %-8s %s${NC}\n" "$ip" "$score" "$attacks"
    done
    echo ""
}

# ============================================
# Anomalies
# ============================================
report_anomalies() {
    local anomaly_status_total anomaly_method_total
    anomaly_status_total=$(get_anomaly_status_total)
    anomaly_method_total=$(get_anomaly_method_total)

    (( anomaly_status_total == 0  && anomaly_method_total == 0 )) && return

    echo -e "${BOLD}═══════════════════ ANOMALIES ═══════════════════${NC}"
    echo ""

    if (( anomaly_status_total > 0  ))
    then
        printf "  ${YELLOW}Invalid status codes: %d${NC}\n" "$anomaly_status_total"
        while IFS=' ' read -r status count
        do
            printf "  %-20s %d\n" "$status" "$count"
        done < <(dump_anomaly_statuses | sort -k2 -rn | head -5)
    fi
    echo ""

    if ((  anomaly_method_total > 0  ))
    then
        printf "  ${YELLOW}Invalid methods: %d${NC}\n" "$anomaly_method_total"
        while IFS=' ' read -r method count
        do
            printf "  %-20s %d\n" "$method" "$count"
        done < <(dump_anomaly_methods | sort -k2 -rn | head -5)
        echo ""
    fi
}

# ============================================
# Footer
# ============================================
report_footer() {
    local total_attack
    total_attack=$(get_total_attacks)

    echo -e "${BOLD}═══════════════════ END OF REPORT ═══════════════════${NC}"
    echo ""

    if (( total_attack > 0  ))
    then
        echo -e "  ${RED}$total_attack attacks detected - action required${NC}"
        echo -e "  ${YELLOW}Recommendation: block attacker IPs, patch vulnerabilities${NC}"
    else
        echo -e "  ${GREEN}No threats detected${NC}"
    fi
    echo ""
}

# ============================================
# Generate full report
# ============================================
generate_report() {
    local log_file="${1:-unknown}"
    local suspicious="${2:-${SUSPICIOUS_SCORE_THRESHOLD:-10}}"
    local critical="${3:-${CRITICAL_SCORE_THRESHOLD:-30}}"


    report_header "$log_file"
    report_overview
    report_status_codes
    report_top_endpoints
    report_security
    report_suspicious_ips "$suspicious" "$critical"
    report_critical_ips "$critical"
    report_anomalies
    report_footer

}
