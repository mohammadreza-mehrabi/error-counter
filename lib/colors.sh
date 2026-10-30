#!/usr/bin/env bash
# ============================================
# colors.sh — ANSI color definitions
# ============================================

if [[ -t 1 ]]; then
    export RED='\033[31m'
    export YELLOW='\033[33m'
    export GREEN='\033[32m'
    export BLUE='\033[34m'
    export CYAN='\033[36m'
    export BOLD='\033[1m'
    export NC='\033[0m'
else
    export RED=''
    export YELLOW=''
    export GREEN=''
    export BLUE=''
    export CYAN=''
    export BOLD=''
    export NC=''
fi
