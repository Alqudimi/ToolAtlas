.PHONY: install test lint format typecheck audit security build demo

install:
	python -m pip install -e '.[dev]'

test:
	pytest -q --cov=toolatlas --cov-report=term-missing --cov-fail-under=85

lint:
	ruff check src tests

format:
	ruff format --check src tests

typecheck:
	mypy src

audit:
	python -m pip check
	python -m compileall -q src

security:
	bandit -q -r src
	pip-audit --skip-editable

build:
	python -m build

demo:
	toolatlas scan examples/catalog.json --format terminal || test $$? -eq 3
	toolatlas policy examples/catalog.json --output /tmp/toolatlas-policy.json
