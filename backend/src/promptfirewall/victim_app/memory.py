"""Run- and session-scoped conversation memory with no persistence dependency."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MemoryEntry:
    key: str
    value: str
    source: str = "user"


class MemoryStore:
    """In-memory state keyed by both run and session.

    The key is deliberately not just a user ID.  A new run cannot observe
    another run's memory, and sessions in one run cannot observe one another.
    """

    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], list[MemoryEntry]] = {}

    @staticmethod
    def _key(run_id: str, session_id: str) -> tuple[str, str]:
        if not run_id.strip() or not session_id.strip():
            raise ValueError("run_id and session_id are required")
        return run_id, session_id

    def read(self, run_id: str, session_id: str) -> tuple[MemoryEntry, ...]:
        return tuple(self._entries.get(self._key(run_id, session_id), ()))

    def write(
        self,
        run_id: str,
        session_id: str,
        key: str,
        value: str,
        *,
        source: str = "user",
    ) -> MemoryEntry:
        if not key.strip() or not value.strip():
            raise ValueError("memory key and value must be non-empty")
        entry = MemoryEntry(key=key.strip(), value=value, source=source)
        bucket = self._entries.setdefault(self._key(run_id, session_id), [])
        bucket[:] = [existing for existing in bucket if existing.key != entry.key]
        bucket.append(entry)
        return entry

    def clear_run(self, run_id: str) -> None:
        for key in tuple(self._entries):
            if key[0] == run_id:
                del self._entries[key]

    def clear(self) -> None:
        self._entries.clear()


ConversationMemory = MemoryStore


__all__ = ["ConversationMemory", "MemoryEntry", "MemoryStore"]
