SHELL := /bin/bash
PYTHON ?= python3

.PHONY: test test-backend test-frontend lint typecheck build dev-backend dev-frontend format

test: test-backend test-frontend

test-backend:
	$(PYTHON) -m pytest backend/tests -q

test-frontend:
	npm --prefix frontend run test -- --run

lint:
	$(PYTHON) -m ruff check backend/src backend/tests
	npm --prefix frontend run lint

typecheck:
	$(PYTHON) -m mypy backend/src
	npm --prefix frontend run typecheck

build:
	npm --prefix frontend run build

format:
	$(PYTHON) -m ruff format backend/src backend/tests

dev-backend:
	$(PYTHON) -m uvicorn promptfirewall.main:app --app-dir backend/src --reload

dev-frontend:
	npm --prefix frontend run dev
