# Scope and remaining deployment limitations

## Security interpretation

- This is a backend firewall and controlled evaluation system, not proof that all
  prompt injections are detected. Normalization/signature filters can miss novel
  attacks and can block legitimate instructions. A regression test intentionally
  records a real false positive rather than relabeling it as success.
- The mock is deterministic and explicitly labeled. It does not reason about
  hardened prompts. Catalog outcomes measure this synthetic control flow only;
  exact attack-marker signatures are not independent real-model security tests.
- The included support victim and every tool are synthetic. Real application
  tools require their own authenticated identity, approval, isolation, and audit
  integration. `TestIdentity` is operator-selected test metadata, not login.
- API-key authentication is service-wide, not per-user/tenant authorization. The
  API includes explicit vulnerable profiles and evidence export for trusted
  operators. Keep it behind TLS and ingress limits; do not expose it to end users.

## Operational boundaries

- SQLite with one API process is the supported configuration. The queue is
  in-process, bounded to 32 waiting experiments; worker count limits concurrent
  jobs and per-job parallelism. A durable distributed queue/multi-process lease
  system and PostgreSQL migrations are not included.
- Restart preserves completed records and marks unfinished work as interrupted;
  it does not resume or retry provider calls automatically. Cancellation is
  cooperative; already-started provider calls may still incur usage.
- Uncooperative synchronous custom models cannot be killed safely. At most 16
  model-call slots are available; timed-out late responses are discarded and
  cannot trigger tools. HTTP adapters also enforce deadlines and close clients.
- Chat creates fresh run-local state. Session IDs do not provide durable
  conversation memory. Multi-turn benchmark cases retain history within a run.
- Retrieval is deterministic keyword matching, not embeddings. Benign judgments
  use explicit fixture assertions, not an LLM semantic correctness judge.
- Dependency locks target Linux/Python 3.11.2, the existing pinned toolchain.
  Runtime/security updates require a reviewed lock refresh and verification.
- Live providers and Docker execution have not been verified locally. Provider
  serialization/retries/errors have offline mock-transport coverage. Docker
  build/run checks are configured in CI; that CI run was not executed here.
- Starlette emits one deprecation warning for the currently locked httpx-based
  TestClient; tests pass. No dependencies were switched just to hide the warning.
