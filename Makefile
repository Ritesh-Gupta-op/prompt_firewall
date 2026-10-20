SHELL := /bin/bash
PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
BOOTSTRAP_PYTHON ?= python3.11

.PHONY: test test-backend setup lint typecheck check format run dev-backend lock build

test: test-backend

test-backend:
	$(PYTHON) -m pytest -c backend/pyproject.toml backend/tests -q

setup:
	$(BOOTSTRAP_PYTHON) scripts/bootstrap.py

lint:
	$(PYTHON) -m ruff check backend/src backend/tests

typecheck:
	$(PYTHON) -m mypy --config-file backend/pyproject.toml backend/src

check: test lint typecheck

format:
	$(PYTHON) -m ruff format backend/src backend/tests

run:
	$(PYTHON) -m uvicorn promptfirewall.main:app --app-dir backend/src --host 127.0.0.1 --port 8000

dev-backend:
	$(PYTHON) -m uvicorn promptfirewall.main:app --app-dir backend/src --reload

lock:
	CUSTOM_COMPILE_COMMAND="make lock" $(PYTHON) -m piptools compile --quiet --allow-unsafe --extra dev --generate-hashes --strip-extras --no-emit-index-url --no-emit-trusted-host --output-file requirements-dev.lock backend/pyproject.toml
	CUSTOM_COMPILE_COMMAND="make lock" $(PYTHON) -m piptools compile --quiet --allow-unsafe --constraint requirements-dev.lock --generate-hashes --strip-extras --no-emit-index-url --no-emit-trusted-host --output-file requirements.lock backend/pyproject.toml

build:
	$(PYTHON) -m build --wheel --no-isolation --outdir dist backend
