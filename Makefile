.PHONY: install test lint demo serve
install: ; pip install -e ".[anchor,dev]" ruff
test: ; python -m pytest -q -W ignore::DeprecationWarning
lint: ; ruff check src
demo: ; fr demo --anchor rfc3161
serve: ; fr serve --anchor rfc3161
