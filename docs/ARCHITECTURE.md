# Backend architecture

PromptFirewall is a Python modular monolith. The firewall and harness do not
depend on HTTP. No frontend, Node runtime, remote worker, or external model is
needed for the default installation.

```text
Trusted service caller -> optional FastAPI/API-key boundary
  chat -> FirewallService -> EnforcedRun -> isolated VictimService
  test-run / experiment -> ExperimentRunner -> EnforcedRun -> isolated VictimService
                                          -> observable judges / metrics / reports
  async job workers <-> RunnerRepository bridge <-> SQLite

EnforcedRun:
  input -> context -> hardened prompt -> model -> output scanner
                                      -> tool policy -> sandboxed tools -> output scanner
```

## Ownership and trust

- User messages, memory, retrieved text, model output, and proposed tool arguments
  are untrusted. Prompt/filter controls are mitigations, not authorization.
- Every built-in profile retains deterministic tool authorization and sandbox
  checks. Model arguments such as `approved=True` cannot grant trusted authority.
- The HTTP API is an operator/service interface. A configured `X-API-Key` protects
  every route except liveness, including stored reports and OpenAPI documentation.
  Production mode refuses to start without a key. Synthetic `TestIdentity`
  metadata selects tenant/role/ownership scenarios; it is not customer authentication.
- Each run gets fresh memory, ledger, and filesystem state. Multi-turn history
  stays within the run. Public defense decisions omit raw/original payloads.
- Tools never contact real mail/payment/HTTP services. Explicit provider adapters
  are the only model network path; selecting one sends prompts to that provider.

## Execution

`EnforcedRun` is shared by chat and the harness, so selecting a profile does not
skip context/prompt/tool stages on HTTP routes. Input rejection avoids model
invocation; output rejection drops tool proposals and returns a safe response.
Tools validate types, allowlists, paths, tenant ownership, and trusted approval.

Model calls have per-run wall-clock and cumulative output-token budgets. Network
adapters use a fresh client/event loop per synchronous completion and close it on
success or failure. Sync execution is offloaded from the API event loop. Timed-out
late model responses cannot execute tools or write persistence.

Catalog delivery uses user messages, multi-turn history, retrieved documents,
tool-output data, or run-local memory as declared. A mock is explicitly labeled;
it does not interpret hardened system prompts as a real LLM would.

## Jobs and storage

One application process owns a bounded queue (32 waiting jobs) and configured
async workers. Each job runs a bounded thread pool, capped by the configured
worker count. `RunnerRepository` sends synchronous persistence calls onto the
owning async loop; SQLAlchemy sessions are never shared across runner threads.
SQLite operations use an engine-scoped lock to serialize transactions, including
the single shared connection used by in-memory tests.

API routes reserve matrix run IDs before queue submission. Progress, results,
and normalized trace events are written to those IDs. Queue rejection is a
persisted failure; it is never reported as successful submission. Cancellation
cannot be overwritten by a late completion, though late evidence is retained.
Shutdown drains workers before disposing the database. Startup marks leftover
queued/running work as interrupted errors; it does not silently resume calls.

The schema uses `create_all`; no migrations or PostgreSQL deployment are claimed.
Use one process per database. Completed rows and reports survive restart. The
Python harness defaults to a thread-safe in-memory repository unless a persistence
adapter is supplied.

## Evaluation

Judges inspect output, tool audit results, and before/after state, not model-chosen
labels. Benign cases include fixture-specific required/prohibited output and
state assertions. Unknown/error observations do not become attack successes.
Queued, running, and cancelled work is excluded from execution metrics. Reports
include actual evidence, provider/model labels, trace sequences, and available
usage; missing cost/usage is not invented.
