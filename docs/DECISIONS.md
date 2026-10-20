# Architecture decisions

## ADR-001: deterministic offline model first

The default `mock` model is deterministic and explicitly labeled. The provider-neutral
bridge supports the implemented OpenAI-compatible and Anthropic adapters without
changing enforcement. Tests use mock HTTP transports, not paid calls. No Ollama
integration or live-provider effectiveness is claimed.

## ADR-002: SQLite plus in-process jobs for MVP

SQLite and lifecycle-managed asyncio workers keep deployment single-process.
Worker threads persist through an async repository bridge. Runs are durable;
startup marks unfinished calls as interrupted rather than pretending to resume.

## ADR-003: tools are the hard boundary

Prompt hardening and filters are experimental mitigations. Tool authorization, path validation, destination allowlists, and state isolation are deterministic and cannot be bypassed by model output.

## ADR-004: observable judges

The initial judges use exact canaries, structured tool audit events, and before/after snapshots. Optional model judges are not used to make the core security result.

## ADR-005: keyword retrieval fallback

Retrieval records `keyword` as its backend. A vector backend may be added behind the same interface, but no embedding download is required for the default suite.

## ADR-006: one backend enforcement implementation

Chat, single catalog tests, and experiment matrices share `EnforcedRun`. HTTP
routes do not implement a weaker input/output-only defense path. Defense decisions
carry action metadata, never a retained original output containing rejected data.

## ADR-007: trusted service boundary

The optional API is for trusted backend operators. Service API keys protect both
execution and evidence exports, and are required in production mode. Synthetic
identity metadata remains separate from authentication. No frontend or customer
account system is introduced.
