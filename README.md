# PromptFirewall

PromptFirewall is a reproducible, offline-first security test bench for LLM-powered applications. It measures controlled prompt-injection and tool-abuse scenarios against a deliberately vulnerable AcmeCorp Support Assistant, then compares them with a deterministic defense pipeline.

The default installation has no paid model or external service dependency. It uses a deterministic mock model, keyword retrieval, SQLite, and sandboxed mock tools. Optional provider adapters are isolated and never required by the test suite.

## Core vertical slice

1. Run the deterministic backend test bench.
2. Optionally start the FastAPI HTTP API.
3. Send a normal support question and a canary-disclosure attack.
4. Compare defense profiles and the resulting trace and outcome.
5. Launch a small experiment and inspect persisted metrics.

## Requirements

- Python 3.11.2 (see `.python-version`)
- Docker is optional; the checked-in `Dockerfile` and `docker-compose.yml` document container deployment.

## Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
pip install -e 'backend[dev]'
cp .env.example .env
```

## Run

```bash
make dev-backend       # optional HTTP API at http://localhost:8000
```

The benchmark core does not require HTTP. The optional FastAPI adapter exposes the
backend routes under `/api`, plus `/docs` and `/health`.

## Checks

```bash
make test              # offline backend tests
make lint
make typecheck
```

The backend test command uses only the deterministic mock adapter. Optional provider-backed tests are explicitly marked and skipped without credentials. In-process experiment jobs do not automatically recover an interrupted model call after process termination; run records preserve the interruption as an error.

## Docker

```bash
docker compose up --build
```

Docker is optional and is not required for the local test command. PostgreSQL is an optional deployment target through `PROMPTFIREWALL_DATABASE_URL`; SQLite is the default.

## Safety boundary

All customer data, secrets, emails, refunds, files, and HTTP targets are synthetic or local. The vulnerable profile relaxes application policy only; host filesystem, network, and real-world side-effect boundaries remain enforced. Do not point this benchmark at a real customer system.

## Repository map

- `backend/src/promptfirewall/contracts`: typed API and execution contracts.
- `backend/src/promptfirewall/victim_app`: AcmeCorp assistant, retrieval, memory, and mock tools.
- `backend/src/promptfirewall/attacks`: attack and benign catalogs plus deterministic mutations.
- `backend/src/promptfirewall/defenses`: composable input, context, prompt, tool, and output controls.
- `backend/src/promptfirewall/harness`: isolated run execution and experiment jobs.
- `backend/src/promptfirewall/judges`, `metrics`, `reports`: observable evaluation and evidence.
- `docs`: architecture, decisions, status, and limitations.
