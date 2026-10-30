#!/usr/bin/env bash
# ============================================
# error_counter.sh — Nginx/Apache log analyzer
# ============================================
# Main entry point. Parses args, validates input,
# processes logs, and generates a report.
#
# Usage:
#   error_counter.sh <log_file> [OPTIONS]
#
# Options:
#   -o FILE    Save report to file (instead of stdout)
#   -s N       Suspicious threshold (default: from config)
#   -c N       Critical threshold (default: from config)
#   -h         Show help
#   -V         Show version
# ============================================

set -euo pipefail

# ============================================
# Shell options (global, set once)
# ============================================
# nocasematch: security patterns are matched case-insensitively
# (SQL keywords can be lowercase, scanner UAs mixed-case, /.ENV vs /.env).
# Set ONCE here to avoid per-line `shopt -p` subshells in detect_attacks
# and _quickcheck_danger (each cost ~1.5ms; ~130K calls per 100K log).
shopt -s nocasematch

# ============================================
# Version
# ============================================
readonly VERSION="1.0.0"

# ============================================
# Bash version check (needs 4.4+ for nameref + set -u on arrays)
# ============================================
if (( BASH_VERSINFO[0] < 4 )) || \
   { (( BASH_VERSINFO[0] == 4 )) && (( BASH_VERSINFO[1] < 4 )); }; then
    echo "error-counter: bash 4.4+ required (found ${BASH_VERSION})" >&2
    exit 1
fi

# ============================================
# Locate script and libs
# ============================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"
CONFIG_DIR="${SCRIPT_DIR}/../config"

# Installed mode: switch on a specific expected file, not the directory
# (e.g. /usr/local/lib exists but /usr/local/lib/error-counter may not).
# Installed layout: $PREFIX/bin/error-counter + $PREFIX/lib/error-counter/
if [[ ! -f "${LIB_DIR}/colors.sh" ]]; then
    LIB_DIR="${SCRIPT_DIR}/../lib/error-counter"
fi
if [[ ! -f "${LIB_DIR}/colors.sh" ]]; then
    LIB_DIR="/usr/local/lib/error-counter"
fi

if [[ ! -f "${CONFIG_DIR}/patterns.conf" ]]; then
    CONFIG_DIR="${SCRIPT_DIR}/../etc/error-counter"
fi
if [[ ! -f "${CONFIG_DIR}/patterns.conf" ]]; then
    CONFIG_DIR="/usr/local/etc/error-counter"
fi

# ============================================
# Pre-source existence checks
# ============================================
# We can't use log_error yet (it lives in logging.sh), so use plain echo >&2.
for _f in colors.sh logging.sh validators.sh parser.sh analyzer.sh security.sh reporter.sh; do
    if [[ ! -f "${LIB_DIR}/${_f}" ]]; then
        echo "error-counter: missing library: ${LIB_DIR}/${_f}" >&2
        exit 1
    fi
done
unset _f

for _f in patterns.conf thresholds.conf; do
    if [[ ! -f "${CONFIG_DIR}/${_f}" ]]; then
        echo "error-counter: missing config: ${CONFIG_DIR}/${_f}" >&2
        exit 1
    fi
done
unset _f

# ============================================
# Load libraries
# ============================================
# shellcheck source=/dev/null
source "${LIB_DIR}/colors.sh"
# shellcheck source=/dev/null
source "${LIB_DIR}/logging.sh"
# shellcheck source=/dev/null
source "${LIB_DIR}/validators.sh"
# shellcheck source=/dev/null
source "${LIB_DIR}/parser.sh"
# shellcheck source=/dev/null
source "${LIB_DIR}/analyzer.sh"
# shellcheck source=/dev/null
source "${LIB_DIR}/security.sh"
# shellcheck source=/dev/null
source "${LIB_DIR}/reporter.sh"

# ============================================
# Load config
# ============================================
# shellcheck source=/dev/null
source "${CONFIG_DIR}/thresholds.conf"
# shellcheck source=/dev/null
source "${CONFIG_DIR}/patterns.conf"

# Sanity: patterns.conf must define CATEGORY_SEVERITY
# Otherwise _record_attack will underflow silently.
if ! declare -p CATEGORY_SEVERITY &>/dev/null; then
    log_error "patterns.conf did not define CATEGORY_SEVERITY (corrupt config?)"
    exit 1
fi
# ============================================
# Defaults (after config load)
# ============================================
: "${SUSPICIOUS_SCORE_THRESHOLD:=10}"
: "${CRITICAL_SCORE_THRESHOLD:=30}"
: "${TOP_ENDPOINTS:=10}"

# ============================================
# Variables
# ============================================
log_file=""
output_file=""
suspicious_threshold="$SUSPICIOUS_SCORE_THRESHOLD"
critical_threshold="$CRITICAL_SCORE_THRESHOLD"

# ============================================
# Help
# ============================================
show_help() {
    local exit_code="${1:-0}"
    cat << EOF
error-counter — Nginx/Apache log analyzer

Usage:
  $0 <log_file> [OPTIONS]

Options:
  -o FILE    Save report to file (instead of stdout)
  -s N       Suspicious score threshold (default: $SUSPICIOUS_SCORE_THRESHOLD)
  -c N       Critical score threshold (default: $CRITICAL_SCORE_THRESHOLD)
  -h         Show this help
  -V         Show version

Examples:
  $0 access.log
  $0 access.log -o report.txt
  $0 access.log -s 15 -c 40
  $0 access.log -o report.txt -s 20

EOF
    exit "$exit_code"
}

# ============================================
# Version
# ============================================
show_version() {
    echo "error-counter v$VERSION"
    exit 0
}

# ============================================
# Parse args
# ============================================
while [[ $# -gt 0  ]]
do
    case "$1" in
        -h|--help)
            show_help 0
            ;;
        -V|--version)
            show_version
            ;;
        -o|--output)
            if [[ -z "${2:-}"  ]]
            then
                log_error "Option $1 requires an argument"
                exit 1
            fi
            output_file="$2"
            shift 2
            ;;
        -s|--suspicious)
            if [[  -z "${2:-}"  ]]
            then
                log_error "Option $1 requires an argument"
                exit 1
            fi
            if ! is_positive_int "$2"
            then
                log_error "Threshold must be a positive integer: $2"
                exit 1
            fi
            suspicious_threshold="$2"
            shift 2
            ;;
        -c|--critical)
            if [[  -z "${2:-}"  ]]
            then
                log_error "Option $1 requires an argument"
                exit 1
            fi
            if ! is_positive_int "$2"
            then
                log_error "Threshold must be positive integer: $2"
                exit 1
            fi
            critical_threshold="$2"
            shift 2
            ;;
        -*)
            log_error "Unknown option: $1"
            show_help 1
            ;;
        *)
            if [[  -z "$log_file"  ]]
            then
                log_file="$1"
            else
                log_error "Multiple log files not supported"
                exit 1
            fi
            shift
            ;;
    esac
done

# ============================================
# Validate input
# ============================================
if [[ -z "$log_file"  ]]
then
    log_error "No log file provided"
    show_help 1
fi

if ! is_valid_file "$log_file"
then
    log_error "File not found or not readable: $log_file"
    exit 1
fi

# ============================================
# Validate output file (before redirection)
# ============================================
if [[ -n "$output_file" ]]; then
    if [[ -e "$output_file" ]]; then
        if [[ ! -w "$output_file" ]]; then
            log_error "Output file not writable: $output_file"
            exit 1
        fi
    else
        if [[ ! -w "$(dirname "$output_file")" ]]; then
            log_error "Cannot create output file: $output_file"
            exit 1
        fi
    fi
fi

# ============================================
# Cleanup on exit (waits for tee to flush)
# ============================================
cleanup() {
    local exit_code=$?
    if [[ -n "${TEE_PID:-}" ]]; then
        wait "$TEE_PID" 2>/dev/null || true
    fi
    exit "$exit_code"
}
trap cleanup EXIT INT TERM

# ============================================
# Setup output redirection (with tee sync)
# ============================================
TEE_PID=""
if [[ -n "$output_file"  ]]
then
    exec > >(tee -- "$output_file")
    TEE_PID=$!
fi

# ============================================
# Reset state
# ============================================
reset_analysis
reset_security

# ============================================
# Process log file
# ============================================
log_info "Processing: $log_file"

while IFS= read -r line
do
    if [[ -z "$line"  ]]
    then
        EMPTY_LINES=$((EMPTY_LINES + 1))
        continue
    fi


    if ! parse_log_line "$line"
    then
        SKIPPED_LINES=$((SKIPPED_LINES + 1))
        continue
    fi

    if ! analyze_current_line
    then
        SKIPPED_LINES=$((SKIPPED_LINES + 1))
        continue
    fi

    detect_attacks
done < "$log_file"

log_info "Processing complete"

if (( SKIPPED_LINES > 0 )); then
    log_warn "$SKIPPED_LINES line(s) skipped (unparseable or invalid IP)"
fi
# ============================================
# Generate report
# ============================================
generate_report "$log_file" "$suspicious_threshold" "$critical_threshold"

# ============================================
# Exit code based on threats
# ============================================
total_attacks=$(get_total_attacks)
if (( total_attacks > 0  ))
then
    exit 2  # threats detected
else
    exit 0  # clean
fi
