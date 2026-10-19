# PromptFirewall architecture

PromptFirewall is a modular monolith. FastAPI is the only process boundary in the default installation; the victim assistant is a separate service object with explicit request/context/tool interfaces. Experiment jobs run in a bounded asyncio worker pool and persist every run and trace event in SQLite.

```text
React dashboard -> FastAPI routes -> experiment service
                                  -> harness runner
                                  -> victim assistant
                                  -> defense pipeline
                                  -> judges / metrics / reports
                                  -> SQLite repositories
```

## Trust boundaries

- User messages, retrieved documents, memory entries, model output, and model-proposed tools are untrusted.
- Authenticated test identity and role are structured request metadata; natural-language claims cannot change them.
- Tool authorization is deterministic and runs before every side effect.
- The filesystem, email, refund, and network tools are local mock implementations.
- Judges consume persisted observable events and isolated state snapshots; the model cannot select its own outcome.

## Storage

The MVP uses SQLAlchemy 2 async models and creates the SQLite schema on startup. Repository interfaces keep persistence behind `storage`. Alembic configuration is included for future schema migrations; startup creation keeps a clean offline checkout immediately runnable. PostgreSQL works with an async SQLAlchemy URL after applying migrations in a deployment environment.

## Execution

An experiment expands to a validated matrix of cases × defense profiles × repetitions. Each run gets a unique ID, a fresh victim state, deterministic seed, and ordered trace events. A failure is persisted as `execution_error` rather than being converted to a security result. Cancellation is cooperative and leaves unstarted runs cancelled.

## Design language

The dashboard uses a dark incident-response workspace: near-black navy surfaces, cyan telemetry accents, amber uncertainty, and red only for real findings. Cards are information-dense but preserve a clear narrative: posture, live traces, then evidence.
