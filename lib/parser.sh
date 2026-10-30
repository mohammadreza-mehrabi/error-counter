#!/usr/bin/env bash
# ============================================
# parser.sh — Nginx/Apache log parser
# ============================================
# Supports: IPv4, IPv6, Apache "-" size, ident/authuser any.
# Not supported: Common Log Format (without referer/UA).
# ============================================

if [[ -z "${LOG_PATTERN:-}" ]]; then
    readonly LOG_PATTERN='^([0-9a-fA-F:.]+) ([^ ]+) ([^ ]+) \[([^]]+)\] "([A-Z]+) ([^ ]+) HTTP/[0-9.]+" ([0-9]{3}) ([0-9]+|-) "([^"]*)" "([^"]*)"$'
fi

# Parsed fields (global)
LOG_IP=""
LOG_IDENT=""
LOG_AUTHUSER=""
LOG_TIMESTAMP=""
LOG_METHOD=""
LOG_PATH=""
LOG_STATUS=""
LOG_SIZE=""
LOG_REFERER=""
LOG_USER_AGENT=""

reset_parsed_fields() {
    LOG_IP=""
    LOG_IDENT=""
    LOG_AUTHUSER=""
    LOG_TIMESTAMP=""
    LOG_METHOD=""
    LOG_PATH=""
    LOG_STATUS=""
    LOG_SIZE=""
    LOG_REFERER=""
    LOG_USER_AGENT=""
}

parse_log_line() {
    local line="$1"
    reset_parsed_fields

    if [[ "$line" =~ $LOG_PATTERN ]]; then
        LOG_IP="${BASH_REMATCH[1]}"
        LOG_IDENT="${BASH_REMATCH[2]}"
        LOG_AUTHUSER="${BASH_REMATCH[3]}"
        LOG_TIMESTAMP="${BASH_REMATCH[4]}"
        LOG_METHOD="${BASH_REMATCH[5]}"
        LOG_PATH="${BASH_REMATCH[6]}"
        LOG_STATUS="${BASH_REMATCH[7]}"
        LOG_SIZE="${BASH_REMATCH[8]}"
        LOG_REFERER="${BASH_REMATCH[9]}"
        LOG_USER_AGENT="${BASH_REMATCH[10]}"
        return 0
    fi
    return 1
}
