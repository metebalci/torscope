.DEFAULT_GOAL = build

VENV = venv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip

.PHONY: test lint dist-clean build upload update-authorities

lint:
	$(VENV)/bin/black --check src
	$(VENV)/bin/ruff check src
	$(VENV)/bin/mypy src
	$(VENV)/bin/pylint src

test: lint
	$(VENV)/bin/pytest

dist-clean:
	rm -rf dist

build: dist-clean
	$(PYTHON) -m build

upload: dist-clean build
	$(PYTHON) -m twine upload dist/*

update-authorities:
	$(PYTHON) scripts/update_authorities.py
