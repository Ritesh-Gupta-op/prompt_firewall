"""Self-contained synthetic AcmeCorp support-assistant victim application."""

from promptfirewall.victim_app.fixtures import (
    CANARY_ALPHA,
    CANARY_RAG,
    CANARY_SYSTEM,
    DEFAULT_FIXTURES,
    SyntheticDocument,
    SyntheticFixtures,
    SyntheticOrder,
    SyntheticTicket,
)
from promptfirewall.victim_app.memory import ConversationMemory, MemoryEntry, MemoryStore
from promptfirewall.victim_app.model import (
    DeterministicMockModel,
    DeterministicMockModelAdapter,
    MockModelAdapter,
)
from promptfirewall.victim_app.rag import KeywordRetriever, RagKeywordRetriever, RetrievalResult
from promptfirewall.victim_app.service import (
    AcmeSupportAssistant,
    VictimApplication,
    VictimRequest,
    VictimRunResult,
    VictimService,
)
from promptfirewall.victim_app.tools import (
    APPROVED_EMAIL_RECIPIENTS,
    MockTools,
    RefundLedgerEntry,
    SandboxedMockTools,
)

__all__ = [
    "APPROVED_EMAIL_RECIPIENTS",
    "AcmeSupportAssistant",
    "CANARY_ALPHA",
    "CANARY_RAG",
    "CANARY_SYSTEM",
    "ConversationMemory",
    "DEFAULT_FIXTURES",
    "DeterministicMockModel",
    "DeterministicMockModelAdapter",
    "KeywordRetriever",
    "MemoryEntry",
    "MemoryStore",
    "MockModelAdapter",
    "MockTools",
    "RagKeywordRetriever",
    "RefundLedgerEntry",
    "RetrievalResult",
    "SandboxedMockTools",
    "SyntheticDocument",
    "SyntheticFixtures",
    "SyntheticOrder",
    "SyntheticTicket",
    "VictimApplication",
    "VictimRequest",
    "VictimRunResult",
    "VictimService",
]
