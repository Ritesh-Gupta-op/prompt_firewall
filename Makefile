SHELL := /bin/bash
PYTHON ?= python3

.PHONY: test test-backend lint typecheck format dev-backend

test: test-backend

test-backend:
	$(PYTHON) -m pytest backend/tests -q

lint:
	$(PYTHON) -m ruff check backend/src backend/tests

typecheck:
	$(PYTHON) -m mypy backend/src

format:
	$(PYTHON) -m ruff format backend/src backend/tests

dev-backend:
	$(PYTHON) -m uvicorn promptfirewall.main:app --app-dir backend/src --reload
