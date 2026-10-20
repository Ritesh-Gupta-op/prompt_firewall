# PromptFirewall backend

The Python-only backend exposes `FirewallService`, `DefensePipeline`, and
`ExperimentRunner` without requiring HTTP. FastAPI is the optional service adapter.
From the repository root, install `requirements-dev.lock` with `--require-hashes`,
then install `backend` with `--no-deps --no-build-isolation -e`. `make check` runs
the offline unit/integration/provider-transport tests, lint, and strict typecheck.
The root `README.md` contains exact setup, run, build, and deployment steps.
