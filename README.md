# PromptFirewall backend

A backend-only prompt firewall with a reproducible security evaluation harness.
There is no frontend. Python services are independent of the optional FastAPI
adapter; SQLite stores runs, decisions, traces, and experiment results.

## Implemented behavior

- One shared enforcement path for chat and experiments: input normalization and
  heuristics, context filtering, prompt hardening, deterministic tool policy, and
  output scanning. Chat defaults to `full-stack`.
- Fresh run-local memory, refund ledger, and filesystem sandbox. Model-proposed
  side effects cannot grant themselves trusted approval.
- Bounded experiment workers, persistent progress, cooperative cancellation,
  terminal failure records, and interrupted-job marking after restart.
- Ordered traces, observable security/utility judges, metrics with denominators
  and confidence intervals, and JSON/Markdown reports containing evidence.
- 39 synthetic attacks and 30 fixture-backed benign cases, five profiles, multi-turn
  delivery, RAG/tool-output/memory delivery, deterministic mutations, and replay.
- Offline mock model plus OpenAI-compatible and Anthropic adapters. Provider
  configuration is honored; failures never silently fall back to a mock.
- Optional service API key; mandatory when `PROMPTFIREWALL_ENV=production`.

This is **not a guarantee against every prompt injection**. The bundled victim is
a synthetic support assistant, tools are sandboxed, and filters are heuristic.
Fixture marker detection is a test signature, not general-model security evidence.
See [architecture](docs/ARCHITECTURE.md), [verification](docs/IMPLEMENTATION_STATUS.md),
and [limitations](docs/KNOWN_LIMITATIONS.md).

## Reproducible setup

Run the commands below from the repository root. A clean Linux machine needs
**either** Docker Engine with the Compose plugin **or** Python **3.11.2** with
`venv`/`ensurepip` support and GNU Make. Docker is the self-contained path when
the host does not already have the exact Python version; no host Python, compiler,
database server, or global Python packages are needed for that path.

Both Docker base images pin Python 3.11.2 and its multi-platform image digest.
Runtime and development dependencies are pinned with SHA-256 hashes in
`requirements.lock` and `requirements-dev.lock`. The Linux images install binary
wheels only, so no unlisted compiler/system-package build dependencies are used.

### Local Python setup

```bash
make setup
```

`make setup` verifies `.python-version`, creates a project-local `.venv`, installs
the hash-locked dependencies, and installs the backend without resolving more
dependencies. It fails clearly on a different Python patch version or incompatible
existing virtualenv and does not delete it. If Python 3.11.2 is available under a
different executable name, use `make setup BOOTSTRAP_PYTHON=python`.

No environment file or credentials are needed for the default mock. `.env.example`
documents every setting. Private `.env` and `.env.*` files are ignored by Git and
Docker; `.env.example` contains placeholders only and remains checked in.
After dependencies are installed, tests and wheel builds work offline.

## Checks and build

```bash
make test       # one offline test command; unit, integration, provider mock tests
make check      # tests + Ruff + strict mypy
make build      # dist/promptfirewall-0.1.0-py3-none-any.whl
```

The test suite ignores local model/database configuration and rejects real HTTP
transports. Live provider credentials are neither required nor used. `make lock`
regenerates both hash-locked dependency sets using the pinned pip-tools version;
this maintenance operation requires package-index access.

## Run and deploy

Local Python, after `make setup`:

```bash
make run
# Local API: http://localhost:8000; schema: /openapi.json; documentation: /docs
```

`make dev-backend` is the optional auto-reloading development command. `make run`
uses one process without reload and binds only to loopback.

### Docker-only clean Linux build, test, and run

These commands need Docker, not a local Python installation. Initial image builds
need network access to the image registry and package index. The built test image
runs the same pytest suite with networking disabled.

```bash
docker compose build
docker build --target test -t promptfirewall:test .
docker run --rm --network none promptfirewall:test
docker compose up -d
docker compose ps
# Stop without deleting the database volume:
docker compose down
```

Compose binds **127.0.0.1:8000**, persists SQLite in a named volume, and allows
in-flight work to drain on shutdown. The image installs locked wheels, runs as
UID 10001, and includes a health check. No host filesystem paths or secrets are
embedded in the image. `/health` is liveness, not a database readiness check.

For a service deployment, run one process per database, configure
`PROMPTFIREWALL_ENV=production` and `PROMPTFIREWALL_API_KEY` through the deployment
secret store, and place the service behind TLS and ingress request/rate limits.
Send the key in `X-API-Key`; all HTTP routes except `/health` require it when
configured. The API is for trusted backend operators, not direct customer access:
`identity` fields select synthetic test identities and do not authenticate users.

Only SQLite/single-process operation is verified. Do not run multiple Uvicorn
processes against the same job database: startup recovery assumes exclusive
process ownership. Docker execution and live providers must be verified in their
target environment; see the status document for checks actually run locally.
The rebuild audit and clean-source verification are in
[`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md).

## Backend interface

| Route | Purpose |
|---|---|
| `POST /api/victim/chat` | Firewall-protected support request; safe response, decisions, traces |
| `POST /api/victim/test-run` | Execute one attack or benign case through the same enforcement core |
| `POST /api/experiments` | Validate and queue a bounded case/profile/repetition matrix |
| `GET /api/experiments/{id}` | Durable progress and terminal state |
| `POST /api/experiments/{id}/cancel` | Cooperative, idempotent cancellation |
| `GET /api/experiments/{id}/runs` | Per-run outcomes |
| `GET /api/runs/{id}` and `/traces` | Result, evidence, errors, ordered events |
| `GET /api/experiments/{id}/metrics` | Metrics over eligible finished runs |
| `GET /api/experiments/{id}/report` | JSON; `?format=markdown` for Markdown |
| `GET /api/catalogs/attacks`, `/benign`, `/defense-profiles` | Typed catalogs |

The HTTP-independent entry points are `promptfirewall.firewall.FirewallService`,
`promptfirewall.defenses.DefensePipeline`, and
`promptfirewall.harness.ExperimentRunner`. The harness defaults to an in-memory
repository for library callers; the HTTP worker uses the SQLite bridge.

Chat requests are isolated, not a persistent conversation service. A session ID
is trace metadata; benchmark multi-turn cases retain history only within one run.
`none` and `tool-controls-only` both retain identical mandatory sandbox tool
controls; their equality is deliberate, not evidence of an added mitigation.
