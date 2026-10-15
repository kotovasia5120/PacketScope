.DEFAULT_GOAL := test
PYTHON ?= python3

.PHONY: test serve wheel check-runtime

check-runtime:
	@$(PYTHON) -c 'import sys; expected=(3, 12, 7); actual=sys.version_info[:3]; sys.exit("PacketScope requires Python 3.12.7; found %s" % (".".join(map(str, actual))) if actual != expected else 0)'

test: check-runtime
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v

wheel: check-runtime
	$(PYTHON) -m pip wheel --no-deps --no-build-isolation . --wheel-dir dist

serve:
	$(PYTHON) -m packetscope.cli serve --host "$${PACKETSCOPE_HOST:-127.0.0.1}" --port "$${PACKETSCOPE_PORT:-8765}"
