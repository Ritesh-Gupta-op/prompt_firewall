# Known limitations

- The mock model exercises application control flow and should not be presented as a benchmark of a real provider model.
- In-process jobs do not resume automatically after process termination.
- Keyword retrieval is deterministic but less semantically capable than embeddings.
- No provider credentials are available in the default environment, so optional provider integrations are unverified locally.
- SQLite is suitable for local use and small demonstrations; production deployments should use PostgreSQL and a durable worker.
- Confidence intervals are only shown when a metric has enough eligible observations; small demonstrations remain uncertain.
- The initial attack and benign catalog is intentionally synthetic and should be expanded before making general claims.
