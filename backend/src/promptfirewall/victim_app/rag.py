"""Deterministic keyword-only retrieval over synthetic documents."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from promptfirewall.contracts.models import TestIdentity
from promptfirewall.victim_app.fixtures import (
    DEFAULT_FIXTURES,
    SyntheticDocument,
    SyntheticFixtures,
)

_WORD_RE = re.compile(r"[a-z0-9][a-z0-9_-]*")


@dataclass(frozen=True)
class RetrievalResult:
    document: SyntheticDocument
    score: int
    matched_keywords: tuple[str, ...]

    @property
    def document_id(self) -> str:
        return self.document.document_id


class KeywordRetriever:
    """A bounded, local retriever; it never fetches a URL or executes content."""

    def __init__(self, fixtures: SyntheticFixtures = DEFAULT_FIXTURES) -> None:
        self.fixtures = fixtures

    def retrieve(
        self,
        query: str,
        *,
        tenant_id: str | None = None,
        identity: TestIdentity | None = None,
        limit: int = 3,
    ) -> tuple[RetrievalResult, ...]:
        if limit <= 0:
            return ()
        if identity is not None:
            tenant_id = identity.tenant_id
        query_words = set(_WORD_RE.findall(query.casefold()))
        candidates: list[RetrievalResult] = []
        for document in self.fixtures.documents.values():
            if tenant_id is not None and document.tenant_id != tenant_id:
                continue
            document_words = set(document.keywords) | set(
                _WORD_RE.findall(document.content.casefold())
            )
            matched = tuple(sorted(query_words & document_words))
            if matched:
                candidates.append(
                    RetrievalResult(
                        document=document,
                        score=len(matched),
                        matched_keywords=matched,
                    )
                )
        candidates.sort(key=lambda result: (-result.score, result.document_id))
        return tuple(candidates[:limit])

    def retrieve_documents(
        self,
        query: str,
        *,
        tenant_id: str | None = None,
        limit: int = 3,
    ) -> tuple[SyntheticDocument, ...]:
        return tuple(
            result.document
            for result in self.retrieve(query, tenant_id=tenant_id, limit=limit)
        )


RagKeywordRetriever = KeywordRetriever


def build_retriever(documents: Iterable[SyntheticDocument]) -> KeywordRetriever:
    """Create a retriever from an explicit fixture subset for isolated tests."""

    docs = tuple(documents)
    fixtures = SyntheticFixtures(documents={document.document_id: document for document in docs})
    return KeywordRetriever(fixtures)


__all__ = [
    "KeywordRetriever",
    "RagKeywordRetriever",
    "RetrievalResult",
    "build_retriever",
]
