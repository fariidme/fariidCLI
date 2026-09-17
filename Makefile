# Fariid Tech Security AI — development Makefile
SHELL := /bin/bash
PY ?= python3
VENV := .venv
PIP := $(VENV)/bin/pip
PYBIN := $(VENV)/bin/python
CLI := $(VENV)/bin/fariid-sec

.PHONY: help venv install install-dev install-pdf test test-cov lint format typecheck doctor build clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

venv: ## Create virtualenv
	$(PY) -m venv $(VENV)

install: venv ## Install in editable mode
	$(PIP) install -e .

install-dev: venv ## Install with dev dependencies
	$(PIP) install -e ".[dev]"

install-pdf: venv ## Install with PDF report support
	$(PIP) install -e ".[pdf]"

test: ## Run test suite
	$(PYBIN) -m pytest

test-cov: ## Run tests with coverage
	$(PYBIN) -m pytest --cov=fariid_sec --cov-report=term-missing

lint: ## Run ruff lint
	$(VENV)/bin/ruff check fariid_sec tests

format: ## Run ruff format
	$(VENV)/bin/ruff format fariid_sec tests

typecheck: ## Run mypy
	$(VENV)/bin/mypy fariid_sec

doctor: ## Run CLI self-check
	$(CLI) doctor

build: ## Build wheel + sdist
	$(PYBIN) -m pip install --upgrade build && $(PYBIN) -m build

clean: ## Remove build artifacts
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
