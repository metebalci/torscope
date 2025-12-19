.DEFAULT_GOAL = build

.PHONY: test lint dist-clean build upload update-authorities

lint:
	black --check src
	ruff check src
	mypy src
	pylint src

test: lint
	pytest

dist-clean:
	rm -rf dist

build: dist-clean
	python -m build

upload: dist-clean build
	python -m twine upload dist/*

update-authorities:
	python scripts/update_authorities.py
