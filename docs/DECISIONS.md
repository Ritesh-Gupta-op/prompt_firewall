# Architecture decisions

## ADR-001: deterministic offline model first

The default `mock` model is deterministic and explicitly labeled as a mock inference. This keeps tests reproducible and avoids credentials. OpenAI, Anthropic, and Ollama integrations can implement the same adapter later without changing the harness.

## ADR-002: SQLite plus in-process jobs for MVP

SQLite and an asyncio worker pool keep the product simple to run locally. Jobs and runs are durable records, but an in-process worker cannot recover an in-flight provider request after process death. The limitation is surfaced in reports.

## ADR-003: tools are the hard boundary

Prompt hardening and filters are experimental mitigations. Tool authorization, path validation, destination allowlists, and state isolation are deterministic and cannot be bypassed by model output.

## ADR-004: observable judges

The initial judges use exact canaries, structured tool audit events, and before/after snapshots. Optional model judges are not used to make the core security result.

## ADR-005: keyword retrieval fallback

Retrieval records `keyword` as its backend. A vector backend may be added behind the same interface, but no embedding download is required for the default suite.
