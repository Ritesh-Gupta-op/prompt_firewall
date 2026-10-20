# Backend implementation and verification status

Verified on 2026-10-20 using Linux/Python 3.11.2. Backend-only scope is preserved.
There is no frontend deliverable and no claim of universal injection detection.

| Capability | State | Evidence |
|---|---|---|
| Shared firewall pipeline | Implemented and tested | Chat and runner use `defenses/execution.py`; malformed tools, safe output, isolation tests |
| Typed contracts and error handling | Implemented and tested | Invalid/blank payloads, 422 serialization, duplicate-ID 409 tests |
| Provider selection/bridge | Implemented; offline verified | OpenAI-compatible/Anthropic HTTP mock transports, native calls, fallback, retry/auth/timeout/cleanup tests |
| Experiment execution/persistence | Implemented and tested | Real queued-to-completed API flow; SQLite progress, stable IDs, traces and reports |
| Cancellation and recovery | Implemented and tested | Queue saturation, in-flight cancellation, late completion, shutdown and restart tests |
| Catalog and utility judgments | Implemented and tested | 39 attacks; 30 valid benign fixtures with observable answer/state assertions |
| Metrics and reports | Implemented and tested | Eligible denominators, missing usage, JSON/Markdown evidence; unfinished runs excluded |
| API access control | Implemented and tested | Configured key covers API/docs/evidence; production rejects missing key |
| Reproducible local build | Verified from fresh venv | Hash-locked dev/runtime installs, wheel build and installed-wheel smoke |
| Container deployment | Implemented; not locally executed | Pinned runtime, locked wheel installation, non-root user, loopback Compose, CI build/run checks |

## Checks actually run

- `make check PYTHON=.verify-venv/bin/python`: **298 passed**; Ruff passed;
  strict mypy passed on **72 source files**. One upstream TestClient deprecation
  warning. The fresh verification venv was installed from `requirements-dev.lock`.
- `make build PYTHON=.verify-venv/bin/python`: wheel built successfully.
- Runtime-only hash lock installation plus wheel import/firewall smoke: passed.
- Installed wheel served over real Uvicorn HTTP: benign chat, blocked injection,
  four persisted experiment runs, and evidence report passed; process shut down cleanly.
- `make lock` reproduced both checked-in lockfiles without changes.
- `python -m pip check` in fresh development and runtime environments: passed.
- Whole-catalog API experiment: **345/345 completed, 0 execution errors**,
  ordered traces, JSON/Markdown reports, metrics unchanged after SQLite restart.
  This is now an offline regression test in
  `backend/tests/integration/test_catalog_persistence.py`.

## Observed synthetic catalog outcomes

One repetition, deterministic mock, all shipped cases:

| Profile | Attacks succeeded | Attacks blocked | Benign OK |
|---|---:|---:|---:|
| none | 25 | 14 | 30 |
| prompt-only | 25 | 14 | 30 |
| filters-only | 0 | 39 | 30 |
| tool-controls-only | 25 | 14 | 30 |
| full-stack | 0 | 39 | 30 |

These counts apply only to the synthetic catalog. The mock does not interpret
prompt hardening, and mandatory tool controls are identical in `none` and
`tool-controls-only`. Neither comparison establishes real-provider effectiveness.

## Deployment checks still external

Docker is unavailable in the current container, so no successful Docker build/run
is claimed. No live provider request was made. Remaining scope boundaries are
documented in `KNOWN_LIMITATIONS.md`, not hidden as completed verification.
