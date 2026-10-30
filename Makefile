# ============================================
# Makefile — error-counter
# ============================================
# Targets:
#   make check       Syntax check all .sh files
#   make test        Run smoke tests
#   make lint        Run shellcheck (if available)
#   make install     Install to $(PREFIX) (default: /usr/local)
#   make uninstall   Remove installation
#   make clean       Remove test artifacts
#   make help        This message
# ============================================

PREFIX      ?= /usr/local
BINDIR      ?= $(PREFIX)/bin
LIBDIR      ?= $(PREFIX)/lib/error-counter
CONFDIR     ?= $(PREFIX)/etc/error-counter

SCRIPT      := bin/error_counter.sh
LIBS        := $(wildcard lib/*.sh)
CONFS       := config/patterns.conf config/thresholds.conf

.PHONY: all install uninstall test lint check clean help

all: check

# ============================================
# Install
# ============================================
install:
	@if [ "$$(id -u)" -ne 0 ] && [ "$(PREFIX)" = "/usr/local" ]; then \
		echo "✗ Installing to /usr/local requires sudo:"; \
		echo "    sudo make install"; \
		echo ""; \
		echo "  Or install to a custom prefix:"; \
		echo "    make install PREFIX=/opt/error-counter"; \
		exit 1; \
	fi
	@echo "Installing error-counter to $(PREFIX)..."
	install -d "$(DESTDIR)$(BINDIR)"
	install -d "$(DESTDIR)$(LIBDIR)"
	install -d "$(DESTDIR)$(CONFDIR)"
	install -m 755 "$(SCRIPT)" "$(DESTDIR)$(BINDIR)/error-counter"
	install -m 644 $(LIBS)  "$(DESTDIR)$(LIBDIR)/"
	@for conf in $(CONFS); do \
		target="$(DESTDIR)$(CONFDIR)/$$(basename "$$conf")"; \
		if [ -f "$$target" ]; then \
			echo "  ⚠  $$target exists — skipping"; \
		else \
			install -m 644 "$$conf" "$$target"; \
			echo "  ✓ $$target"; \
		fi; \
	done
	@echo ""
	@echo "✓ Installed"
	@echo ""
	@echo "Try:"
	@echo "  error-counter /var/log/nginx/access.log"

uninstall:
	@echo "Removing error-counter from $(PREFIX)..."
	rm -f  "$(DESTDIR)$(BINDIR)/error-counter"
	rm -rf "$(DESTDIR)$(LIBDIR)"
	rm -rf "$(DESTDIR)$(CONFDIR)"
	@echo "✓ Uninstalled"

# ============================================
# Checks
# ============================================
check:
	@echo "Syntax check:"
	@for f in $(SCRIPT) $(LIBS); do \
		bash -n "$$f" && echo "  ✓ $$f" || { echo "  ✗ $$f"; exit 1; }; \
	done
	@for f in $(CONFS); do \
		bash -n "$$f" && echo "  ✓ $$f" || { echo "  ✗ $$f"; exit 1; }; \
	done

# ============================================
# Smoke tests
# ============================================
test: check
	@echo ""
	@echo "Smoke tests:"
	@echo "  [1] --version"
	@./$(SCRIPT) --version > /dev/null || { echo "    ✗ failed"; exit 1; }
	@echo "    ✓ ok"
	@echo "  [2] --help"
	@./$(SCRIPT) --help > /dev/null || { echo "    ✗ failed"; exit 1; }
	@echo "    ✓ ok"
	@echo "  [3] no argument → exit 1"
	@./$(SCRIPT) > /dev/null 2>&1; code=$$?; \
		[ "$$code" -eq 1 ] && echo "    ✓ ok" || { echo "    ✗ expected exit 1, got $$code"; exit 1; }
	@echo "  [4] missing file → exit 1"
	@./$(SCRIPT) /nonexistent-ec-test > /dev/null 2>&1; code=$$?; \
		[ "$$code" -eq 1 ] && echo "    ✓ ok" || { echo "    ✗ expected exit 1, got $$code"; exit 1; }
	@echo "  [5] clean log → exit 0"
	@echo '192.168.1.1 - - [ts] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"' > /tmp/_ec_clean.log
	@./$(SCRIPT) /tmp/_ec_clean.log > /dev/null 2>&1; code=$$?; \
		[ "$$code" -eq 0 ] && echo "    ✓ ok" || { echo "    ✗ expected exit 0, got $$code"; exit 1; }
	@echo "  [6] attack log → exit 2"
	@printf '%s\n' \
		"192.168.1.1 - - [ts] \"GET /?id=1'OR'1'='1 HTTP/1.1\" 200 100 \"-\" \"UA\"" \
		"192.168.1.1 - - [ts] \"GET /?id=1'OR'1'='1 HTTP/1.1\" 200 100 \"-\" \"UA\"" \
		"192.168.1.1 - - [ts] \"GET /?id=1'OR'1'='1 HTTP/1.1\" 200 100 \"-\" \"UA\"" \
		> /tmp/_ec_attack.log
	@./$(SCRIPT) /tmp/_ec_attack.log > /dev/null 2>&1; code=$$?; \
		[ "$$code" -eq 2 ] && echo "    ✓ ok" || { echo "    ✗ expected exit 2, got $$code"; exit 1; }
	@echo "  [7] IPv6 parse"
	@echo '2001:db8::1 - - [ts] "GET / HTTP/1.1" 200 100 "-" "UA"' > /tmp/_ec_v6.log
	@./$(SCRIPT) /tmp/_ec_v6.log 2>&1 | grep -q "Total requests:           1" \
		|| { echo "    ✗ IPv6 not parsed"; exit 1; }
	@echo "    ✓ ok"
	@echo "  [8] Apache '-' size"
	@echo '192.168.1.1 - - [ts] "HEAD / HTTP/1.1" 304 - "-" "UA"' > /tmp/_ec_dash.log
	@./$(SCRIPT) /tmp/_ec_dash.log 2>&1 | grep -q "Total requests:           1" \
		|| { echo "    ✗ Apache '-' not parsed"; exit 1; }
	@echo "    ✓ ok"
	@echo "  [9] Line accounting (Analyzed + Skipped + Empty = Lines)"
	@if [ ! -f tests/fixtures/access.log ]; then \
		echo "    ⚠  tests/fixtures/access.log not found — skipping"; \
	else \
		report=$$(./$(SCRIPT) tests/fixtures/access.log 2>/dev/null); \
		L=$$(echo "$$report" | grep "Lines:" | head -1 | awk '{print $$2}'); \
		A=$$(echo "$$report" | grep "Analyzed:" | head -1 | awk '{print $$2}'); \
		S=$$(echo "$$report" | grep "Skipped:" | head -1 | awk '{print $$2}'); \
		E=$$(echo "$$report" | grep "Empty:" | head -1 | awk '{print $$2}'); \
		if [ $$((A + S + E)) -eq "$$L" ]; then \
			echo "    ✓ ok ($$L = $$A + $$S + $$E)"; \
		else \
			echo "    ✗ mismatch: $$A + $$S + $$E ≠ $$L"; \
			exit 1; \
		fi; \
	fi
	@rm -f /tmp/_ec_*.log
	@echo ""
	@echo "✓ All smoke tests passed"

# ============================================
# Lint
# ============================================
lint:
	@if command -v shellcheck >/dev/null 2>&1; then \
		echo "Running shellcheck..."; \
		shellcheck -x $(SCRIPT) $(LIBS); \
		echo "✓ Clean"; \
	else \
		echo "⚠ shellcheck not installed — skipping"; \
		echo "  Install: apt install shellcheck"; \
	fi

# ============================================
# Clean
# ============================================
clean:
	rm -f /tmp/_ec_*.log report*.txt
	@echo "✓ Cleaned"

# ============================================
# Help
# ============================================
help:
	@echo "error-counter — Makefile targets"
	@echo ""
	@echo "  make check       Syntax check all .sh files"
	@echo "  make test        Run smoke tests (9 checks)"
	@echo "  make lint        Run shellcheck"
	@echo "  make install     Install to \$$PREFIX (default: /usr/local)"
	@echo "  make uninstall   Remove installation"
	@echo "  make clean       Remove test artifacts"
	@echo "  make help        This message"
	@echo ""
	@echo "Variables:"
	@echo "  PREFIX=/path     Install prefix (default: /usr/local)"
	@echo "  DESTDIR=/path    Staging directory (for packaging)"
	@echo ""
	@echo "Examples:"
	@echo "  sudo make install"
	@echo "  make install PREFIX=/opt/error-counter"
	@echo "  make test"
