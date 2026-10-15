.PHONY: test serve

test:
	python3 -m unittest discover -s tests -p 'test_*.py' -v

serve:
	python3 -m packetscope.cli serve --host "$${PACKETSCOPE_HOST:-127.0.0.1}" --port "$${PACKETSCOPE_PORT:-8765}"
