# Reproducibility audit

Audit target: clean Linux source checkout, backend-only PromptFirewall.

## Requirement checklist

| Requirement | Status | Evidence / implementation |
|---|---|---|
| Git repository with commits | PASS | Git history contains the implementation and reproducibility commits; working tree is checked before commit. |
| Dependency lockfile | PASS | `requirements.lock` and `requirements-dev.lock` contain exact pins plus SHA-256 hashes. Runtime pins are shared by the dev lock. |
| Runtime pinned | PASS | `.python-version` is exactly `3.11.2`; Docker builder/runtime bases use the same pinned version and digest. |
| Dockerfile builds and runs | IMPLEMENTED / LOCAL CHECK BLOCKED | Multi-stage builder, offline test target, non-root runtime, healthcheck, locked binary wheels, and Uvicorn default are defined. Docker is unavailable in this environment; CI runs `docker build`, `docker run --network none`, and the HTTP smoke test. |
| One test command | PASS | `make test` is the single offline test entry point; `make check` adds lint/typecheck. The Docker test target runs the same pytest command. |
| README setup/run/test steps | PASS | Root `README.md` has Docker-only and local Python setup, test, build, run, Compose, shutdown, and API commands. |
| `.env.example`, no secrets | PASS | `.env.example` documents canonical settings with mock/local safe defaults and placeholders. Private `.env`/`.env.*` are ignored and excluded from Docker. |
| No machine absolute paths | PASS | Repository scan found no `/home/`, `/Users/`, or Windows-user paths in tracked project files. Paths are derived from source locations or are container/project-relative. |

## Clean-source verification performed

The tracked source was exported to a fresh directory with no `.git` metadata,
then verified independently of the original project environment:

```bash
make setup
make check
make build
.venv/bin/python -m pip check
make run
```

Observed results:

- `make setup`: created a project-local environment and installed from the hash
  lock without dependency resolution beyond the lock.
- `make check`: **331 tests passed**, Ruff passed, strict mypy passed on 73 source
  files, with one existing upstream TestClient deprecation warning.
- `make build`: wheel built successfully.
- Runtime-only installation from `requirements.lock` plus the wheel passed import,
  firewall, and `pip check` smoke tests.
- `make run`: `/health` passed; a prompt-injection chat returned `blocked: true`;
  the resulting run was persisted and readable through the API.

The source export used only project-relative paths. Dependency wheels were already
available in the local package cache for this offline verification; a new machine
needs package-index access for the first `make setup` or Docker image build unless
the wheel/cache is preloaded.

## Exact clean-machine commands

### Docker path — no host Python required

```bash
git clone <repository-url> promptfirewall
cd promptfirewall
docker compose build
docker build --target test -t promptfirewall:test .
docker run --rm --network none promptfirewall:test
docker compose up -d
curl --fail http://127.0.0.1:8000/health
docker compose down
```

`docker compose down` preserves the named database volume. Use
`docker compose down -v` only when intentionally deleting persisted runs.

### Local Python path

```bash
git clone <repository-url> promptfirewall
cd promptfirewall
make setup
make test
make build
make run
```

The local API listens at `http://127.0.0.1:8000`. Stop it with `Ctrl-C`.

## Non-claims

Docker and live provider execution are not locally verified because Docker and
provider credentials are unavailable in the current environment. Docker build,
offline test-container execution, and health/firewall smoke are configured in CI.
The default model is synthetic/offline and does not establish real-provider
security effectiveness.
