#!/usr/bin/env bash
# ============================================
# validators.sh — Input validation functions
# ============================================

is_ipv4() {
    local ip="$1"
    local octet='(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    [[ "$ip" =~ ^(${octet}\.){3}${octet}$ ]]
}

is_ipv6() {
    local ip="$1"
    ip="${ip%%%*}"

    [[ "$ip" == *:* ]] || return 1
    [[ "$ip" =~ ^[0-9a-fA-F:.]+$ ]] || return 1

    [[ "$ip" == *:::* ]] && return 1
    [[ "$ip" == :* && "$ip" != ::* ]] && return 1
    [[ "$ip" == *: && "$ip" != *:: ]] && return 1

    local colons="${ip//[^:]/}"
    local n=${#colons}

    if [[ "$ip" == *.* ]]; then
        (( n >= 2 && n <= 6 )) || return 1
    elif [[ "$ip" == *::* ]]; then
        (( n >= 2 && n <= 8 )) || return 1
    else
        (( n == 7 )) || return 1
    fi
    return 0
}

is_valid_ip() {
    local ip="$1"
    is_ipv4 "$ip" || is_ipv6 "$ip"
}

is_valid_file() {
    local file="$1"
    [[ -f "$file" && -r "$file" ]]
}

is_positive_int() {
    local num="$1"
    [[ "$num" =~ ^[1-9][0-9]*$ ]]
}

is_non_negative_int() {
    local num="$1"
    [[ "$num" =~ ^[0-9]+$ ]]
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

is_http_status() {
    local code="$1"
    [[ "$code" =~ ^[1-5][0-9]{2}$ ]]
}

is_http_method() {
    local method="$1"
    case "$method" in
        GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}
