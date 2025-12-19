.DEFAULT_GOAL = build

.PHONY: test dist-clean build upload update-authorities

test:
	black --check src
	mypy src
	pylint src
	pytest

dist-clean:
	rm -rf dist

build: dist-clean
	python -m build

upload: dist-clean build
	python -m twine upload dist/*

update-authorities:
	python scripts/update_authorities.py
