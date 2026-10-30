#!/usr/bin/env bash
# ============================================
# install.sh — error-counter installer
# ============================================
# Usage:
#   sudo ./install.sh                     # install to /usr/local
#   sudo PREFIX=/opt/ec ./install.sh      # custom prefix
#   sudo ./install.sh --uninstall         # remove
# ============================================

set -euo pipefail

# ============================================
# Args
# ============================================
UNINSTALL=0
for arg in "$@"; do
    case "$arg" in
        -h|--help)
            cat <<EOH
Usage: $0 [--uninstall]

Environment:
  PREFIX=/path    Install prefix (default: /usr/local)

Examples:
  sudo ./install.sh
  sudo PREFIX=/opt/error-counter ./install.sh
  sudo ./install.sh --uninstall
EOH
            exit 0
            ;;
        --uninstall)
            UNINSTALL=1
            ;;
        *)
            echo "Unknown option: $arg" >&2
            echo "Usage: $0 [--uninstall]" >&2
            exit 1
            ;;
    esac
done

# ============================================
# Paths
# ============================================
PREFIX="${PREFIX:-/usr/local}"
BINDIR="${PREFIX}/bin"
LIBDIR="${PREFIX}/lib/error-counter"
CONFDIR="${PREFIX}/etc/error-counter"

# ============================================
# Bash version check
# ============================================
if (( BASH_VERSINFO[0] < 4 )) || \
   { (( BASH_VERSINFO[0] == 4 )) && (( BASH_VERSINFO[1] < 4 )); }; then
    echo "✗ error-counter requires bash 4.4+ (found $BASH_VERSION)" >&2
    echo "  On macOS: brew install bash" >&2
    exit 1
fi

# ============================================
# Locate source
# ============================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_BIN="${SCRIPT_DIR}/bin/error_counter.sh"
SRC_LIB="${SCRIPT_DIR}/lib"
SRC_CONF="${SCRIPT_DIR}/config"

if [[ ! -f "$SRC_BIN" ]]; then
    echo "✗ Cannot find bin/error_counter.sh relative to $0" >&2
    exit 1
fi

# ============================================
# Uninstall
# ============================================
if (( UNINSTALL )); then
    if [[ "$(id -u)" -ne 0 ]] && [[ "$PREFIX" == /usr* ]]; then
        echo "✗ Uninstall from $PREFIX requires sudo:" >&2
        echo "  sudo $0 --uninstall" >&2
        exit 1
    fi

        echo "Uninstalling error-counter from $PREFIX..."
    rm -f  "${BINDIR}/error-counter"
    rm -rf "$LIBDIR"
    rm -rf "$CONFDIR"

    # Clean up parent dirs (only for custom prefix, not system paths)
    if [[ "$PREFIX" != "/usr/local" && "$PREFIX" != "/usr" ]]; then
        rmdir "${LIBDIR%/*}" 2>/dev/null || true
        rmdir "${CONFDIR%/*}" 2>/dev/null || true
        rmdir "$BINDIR" 2>/dev/null || true
        rmdir "$PREFIX" 2>/dev/null || true
    fi

    echo "✓ Uninstalled"
    echo ""
    echo "  Note: config files in $CONFDIR were removed."
    exit 0
fi

# ============================================
# Sudo check
# ============================================
if [[ "$(id -u)" -ne 0 ]] && [[ "$PREFIX" == /usr* ]]; then
    echo "✗ Install to $PREFIX requires sudo:" >&2
    echo "  sudo $0" >&2
    echo "" >&2
    echo "  Or install to a writable prefix:" >&2
    echo "  PREFIX=~/.local $0" >&2
    exit 1
fi

# ============================================
# Install
# ============================================
echo "Installing error-counter to $PREFIX..."
echo ""

install -d "$BINDIR"
install -d "$LIBDIR"
install -d "$CONFDIR"

install -m 755 "$SRC_BIN" "${BINDIR}/error-counter"
echo "  ✓ ${BINDIR}/error-counter"

for lib in "${SRC_LIB}"/*.sh; do
    install -m 644 "$lib" "${LIBDIR}/"
    echo "  ✓ ${LIBDIR}/$(basename "$lib")"
done

for conf in "${SRC_CONF}"/*.conf; do
    target="${CONFDIR}/$(basename "$conf")"
    if [[ -f "$target" ]]; then
        echo "  ⚠  $target exists — not overwriting"
    else
        install -m 644 "$conf" "$target"
        echo "  ✓ $target"
    fi
done

# ============================================
# Verify
# ============================================
echo ""
echo "Verifying installation..."

if [[ ! -x "${BINDIR}/error-counter" ]]; then
    echo "✗ Installation failed — binary not executable" >&2
    exit 1
fi

if ! "${BINDIR}/error-counter" --version >/dev/null 2>&1; then
    echo "✗ Installed binary fails to run" >&2
    exit 1
fi

version=$("${BINDIR}/error-counter" --version 2>&1)
echo "  ✓ $version"

# ============================================
# PATH warning
# ============================================
if ! command -v error-counter >/dev/null 2>&1; then
    echo ""
    echo "  ⚠  ${BINDIR} is not in PATH"
    echo "     Add to ~/.bashrc:"
    echo "       export PATH=\"${BINDIR}:\$PATH\""
fi

# ============================================
# Success
# ============================================
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  ✓ error-counter installed successfully"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  Binary:    ${BINDIR}/error-counter"
echo "  Libraries: ${LIBDIR}/"
echo "  Config:    ${CONFDIR}/"
echo ""
echo "  Try:"
echo "    error-counter /var/log/nginx/access.log"
echo ""
echo "  Uninstall:"
echo "  sudo $0 --uninstall"
echo ""
