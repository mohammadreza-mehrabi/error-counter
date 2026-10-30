#!/usr/bin/env bash
# ============================================
# analyzer.sh — Log data aggregation
# ============================================
# Depends on:
#   - parser.sh    (LOG_* globals)
#   - validators.sh (is_valid_ip, is_http_status, is_http_method)
# ============================================

# ============================================
# Data containers
# ============================================
if [[ -z "${STATUS_COUNT+x}" ]]; then
    declare -A STATUS_COUNT=()
    declare -A IP_COUNT=()
    declare -A PATH_COUNT=()
    declare -A METHOD_COUNT=()
    declare -A UA_COUNT=()
    declare -A ANOMALY_STATUS_COUNT=()
    declare -A ANOMALY_METHOD_COUNT=()
fi

if [[ -z "${TOTAL_REQUESTS+x}" ]]; then
    TOTAL_REQUESTS=0
    TOTAL_ERRORS_4XX=0
    TOTAL_ERRORS_5XX=0
    SKIPPED_LINES=0
    EMPTY_LINES=0
fi
# ============================================
# reset_analysis
# ============================================
reset_analysis() {
    STATUS_COUNT=()
    IP_COUNT=()
    PATH_COUNT=()
    METHOD_COUNT=()
    UA_COUNT=()

    ANOMALY_STATUS_COUNT=()
    ANOMALY_METHOD_COUNT=()

    TOTAL_REQUESTS=0
    TOTAL_ERRORS_4XX=0
    TOTAL_ERRORS_5XX=0
    SKIPPED_LINES=0
    EMPTY_LINES=0

}

# ============================================
# analyze_current_line
# ============================================
analyze_current_line() {
    # 1. IP: strict
    if ! is_valid_ip "$LOG_IP"
    then
        return 1
    fi
    ((TOTAL_REQUESTS += 1))
    ((IP_COUNT["$LOG_IP"] += 1))
    # 2. Status
    if [[ -n "$LOG_STATUS" ]]
    then
        ((STATUS_COUNT["$LOG_STATUS"] += 1))
        if is_http_status "$LOG_STATUS"
        then
            if [[  "$LOG_STATUS" =~ ^4[0-9]{2}$  ]]
            then
                ((TOTAL_ERRORS_4XX += 1))
            fi
            if [[ "$LOG_STATUS" =~ ^5[0-9]{2}$  ]]
            then
                ((TOTAL_ERRORS_5XX += 1))
            fi
        else
            ((ANOMALY_STATUS_COUNT["$LOG_STATUS"] += 1))
        fi
    fi
    # 3. Method
    if [[  -n "$LOG_METHOD"  ]]
    then
        ((METHOD_COUNT["$LOG_METHOD"] += 1))
        if ! is_http_method "$LOG_METHOD"
        then
            ((ANOMALY_METHOD_COUNT["$LOG_METHOD"] += 1))

        fi

    fi
    # 4. Path
    if [[ -n "$LOG_PATH" ]]
    then
        ((PATH_COUNT["$LOG_PATH"] += 1))
    fi
    # 5. UA
    if [[ -n "$LOG_USER_AGENT"  ]]
    then
        ((UA_COUNT["$LOG_USER_AGENT"] += 1))
    fi
    return 0
}
# ============================================
# Getters — scalar counts
# ============================================
get_total_requests() {
    echo "$TOTAL_REQUESTS"

}
get_4xx_count() {
    echo "$TOTAL_ERRORS_4XX"
}
get_5xx_count() {
    echo "$TOTAL_ERRORS_5XX"
}
# ============================================
# Getters — unique counts (per dimension)
# ============================================
get_unique_ip_count() {
    echo "${#IP_COUNT[@]}"
}
get_unique_endpoint_count() {
    echo "${#PATH_COUNT[@]}"
}
get_unique_status_count() {
    echo "${#STATUS_COUNT[@]}"
}
get_unique_method_count() {
    echo "${#METHOD_COUNT[@]}"
}
get_unique_ua_count() {
    echo "${#UA_COUNT[@]}"
}
# ============================================
# Getters — anomaly counts (unique keys)
# ============================================
get_anomaly_status_count() {
    echo "${#ANOMALY_STATUS_COUNT[@]}"
}
get_anomaly_method_count() {
    echo "${#ANOMALY_METHOD_COUNT[@]}"
}
get_anomaly_status_total() {
    local total
    total=0
    for status in "${!ANOMALY_STATUS_COUNT[@]}"
    do
        ((total += ANOMALY_STATUS_COUNT[$status]))
    done
    echo "$total"
}
get_anomaly_method_total() {
    local total
    total=0
    for method in "${!ANOMALY_METHOD_COUNT[@]}"
    do
        ((total += ANOMALY_METHOD_COUNT[$method]))
    done
    echo "$total"


}

get_skipped_lines() {
    echo "${SKIPPED_LINES:-0}"
}
get_empty_lines() {
    echo "${EMPTY_LINES:-0}"
}
# ============================================
# Dump functions — raw data (for piping)
# ============================================
# Usage: dump_* | sort -k2 -rn | head -10
# ============================================
dump_status_counts() {
    for status in "${!STATUS_COUNT[@]}"
    do
        echo "$status ${STATUS_COUNT[$status]}"
    done
}
dump_ip_counts() {
    for ip in "${!IP_COUNT[@]}"
    do
        echo "$ip ${IP_COUNT[$ip]}"
    done

}
dump_path_counts() {
    for path in "${!PATH_COUNT[@]}"
    do
        echo "$path ${PATH_COUNT[$path]}"
    done

}
dump_method_counts() {
    for method in "${!METHOD_COUNT[@]}"
    do
        echo "$method ${METHOD_COUNT[$method]}"
    done
}
dump_ua_counts() {
    for ua in "${!UA_COUNT[@]}"
    do
        echo "$ua ${UA_COUNT[$ua]}"
    done

}
dump_anomaly_statuses() {
    for status in "${!ANOMALY_STATUS_COUNT[@]}"
    do
        echo "$status ${ANOMALY_STATUS_COUNT[$status]}"
    done


}
dump_anomaly_methods() {
    for method in "${!ANOMALY_METHOD_COUNT[@]}"
    do
        echo "$method ${ANOMALY_METHOD_COUNT[$method]}"
    done

}
