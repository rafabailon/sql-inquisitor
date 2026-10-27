PYTHON ?= python3
RUFF ?= ruff

.PHONY: help install test coverage lint lab clean

help:
	@echo "SQL Inquisitor development targets"
	@echo "  make install   Install the package and development tools"
	@echo "  make test      Run the full pytest suite"
	@echo "  make coverage  Run pytest with branch coverage"
	@echo "  make lint      Run the ruff linter"
	@echo "  make lab       Start the vulnerable lab on port 8080"
	@echo "  make clean     Remove caches and build artefacts"

install:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest -q

coverage:
	$(PYTHON) -m pytest -q --cov=src --cov-report=term-missing

lint:
	$(RUFF) check src tests

lab:
	$(PYTHON) tests/target_server.py --port 8080

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache .coverage .coverage.* htmlcov build dist
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type d -name "*.egg-info" -prune -exec rm -rf {} +
