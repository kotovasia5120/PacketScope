.DEFAULT_GOAL := test
# OmniRush's WSL sandbox provides the pinned interpreter inside the workspace.
# Prefer it automatically, then a system python3.12, while keeping an explicit
# `make PYTHON=...` override available for CI and local development.
PINNED_PYTHON := .runtime/cpython-3.12.7-linux-x86_64-gnu/bin/python3.12
PYTHON ?= $(if $(wildcard $(PINNED_PYTHON)),$(PINNED_PYTHON),$(if $(shell command -v python3.12 2>/dev/null),python3.12,python3))

.PHONY: test serve wheel check-runtime

check-runtime:
	@$(PYTHON) -c 'import sys; expected=(3, 12, 7); actual=sys.version_info[:3]; sys.exit("PacketScope requires Python 3.12.7; found %s" % (".".join(map(str, actual))) if actual != expected else 0)'

test: check-runtime
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v

wheel: check-runtime
	SOURCE_DATE_EPOCH=$${SOURCE_DATE_EPOCH:-315532800} $(PYTHON) -m pip wheel --no-deps --no-build-isolation . --wheel-dir dist

serve:
	$(PYTHON) -m packetscope.cli serve --host "$${PACKETSCOPE_HOST:-127.0.0.1}" --port "$${PACKETSCOPE_PORT:-8765}"
