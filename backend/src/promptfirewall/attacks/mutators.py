"""Deterministic, bounded payload mutation operators."""

from __future__ import annotations

import base64 as _base64
import codecs
from collections.abc import Callable, Sequence

from promptfirewall.contracts.attacks import AttackDefinition, Mutation

MutationOperator = Callable[[str], str]

MUTATION_OPERATORS: tuple[str, ...] = (
    "casing",
    "whitespace",
    "paraphrase",
    "unicode",
    "split",
    "base64",
    "rot13",
)
DEFAULT_MUTATION_BUDGET = len(MUTATION_OPERATORS)
MAX_MUTATION_BUDGET = 32


def casing(payload: str) -> str:
    """Swap letter case without changing punctuation or digits."""

    return payload.swapcase()


def whitespace(payload: str) -> str:
    """Add deterministic line breaks around word boundaries."""

    words = payload.split(" ")
    return "\n".join(words)


_PARAPHRASE_RULES: tuple[tuple[str, str], ...] = (
    ("Ignore all previous instructions", "Disregard every earlier direction"),
    ("Ignore previous instructions", "Disregard earlier directions"),
    ("disclose", "reveal"),
    ("Disclose", "Reveal"),
    ("call the local", "invoke the local"),
    ("Call the local", "Invoke the local"),
    ("without approval", "without obtaining confirmation"),
    ("hidden", "private"),
    ("synthetic", "fixture-only"),
)


def paraphrase(payload: str) -> str:
    """Apply a fixed phrase substitution table, with a stable fallback."""

    result = payload
    for source, replacement in _PARAPHRASE_RULES:
        result = result.replace(source, replacement)
    if result == payload:
        return f"In other words, {payload}"
    return result


_UNICODE_CONFUSABLES = str.maketrans(
    {
        "a": "а",  # Cyrillic small a
        "e": "е",  # Cyrillic small ie
        "o": "о",  # Cyrillic small o
        "i": "і",  # Cyrillic small byelorussian-ukrainian i
        "c": "с",  # Cyrillic small es
    }
)


def unicode(payload: str) -> str:
    """Replace a small, fixed set of ASCII letters with homoglyphs."""

    return payload.translate(_UNICODE_CONFUSABLES)


def split(payload: str) -> str:
    """Insert a zero-width separator between words while preserving text order."""

    return "\u2063".join(payload.split(" "))


def base64(payload: str) -> str:
    """Encode the complete UTF-8 payload as ASCII base64."""

    return _base64.b64encode(payload.encode("utf-8")).decode("ascii")


base64_encode = base64


def rot13(payload: str) -> str:
    """Apply the standard deterministic ROT13 transform."""

    return codecs.encode(payload, "rot_13")


_OPERATORS: dict[str, MutationOperator] = {
    "casing": casing,
    "whitespace": whitespace,
    "paraphrase": paraphrase,
    "unicode": unicode,
    "split": split,
    "base64": base64,
    "rot13": rot13,
}


def apply_operator(payload: str, operator: str) -> str:
    """Apply one named operator and reject unknown operators explicitly."""

    try:
        mutation = _OPERATORS[operator]
    except KeyError as exc:
        raise ValueError(f"unknown mutation operator: {operator}") from exc
    return mutation(payload)


def _bounded_budget(budget: int) -> int:
    if isinstance(budget, bool) or not isinstance(budget, int) or budget < 1:
        raise ValueError("mutation budget must be a positive integer")
    return min(budget, MAX_MUTATION_BUDGET)


def generate_mutations(
    attack: AttackDefinition,
    *,
    budget: int = DEFAULT_MUTATION_BUDGET,
    operators: Sequence[str] | None = None,
    seed: int = 0,
) -> tuple[Mutation, ...]:
    """Generate at most ``budget`` deterministic single-operator mutations.

    Operators are applied in the order supplied by ``operators`` (or the
    canonical order above).  No random state is consulted, and a duplicate
    payload is emitted only once.  The seed is retained as provenance in the
    contract and in the stable mutation ID; it does not make output random.
    """

    bounded_budget = _bounded_budget(budget)
    selected = tuple(MUTATION_OPERATORS if operators is None else operators)
    unknown = [operator for operator in selected if operator not in _OPERATORS]
    if unknown:
        raise ValueError(f"unknown mutation operator: {unknown[0]}")

    mutations: list[Mutation] = []
    seen_payloads: set[str] = set()
    for operator in selected:
        if len(mutations) >= bounded_budget:
            break
        mutated_payload = apply_operator(attack.payload_template, operator)
        if mutated_payload == attack.payload_template or mutated_payload in seen_payloads:
            continue
        seen_payloads.add(mutated_payload)
        mutations.append(
            Mutation(
                mutation_id=f"{attack.id}--{operator}--{seed}",
                parent_attack_id=attack.id,
                payload=mutated_payload,
                operators=[operator],
                seed=seed,
            )
        )
    return tuple(mutations)


def mutate_attack(
    attack: AttackDefinition,
    *,
    budget: int = DEFAULT_MUTATION_BUDGET,
    operators: Sequence[str] | None = None,
    seed: int = 0,
) -> tuple[Mutation, ...]:
    """Compatibility-friendly alias for :func:`generate_mutations`."""

    return generate_mutations(attack, budget=budget, operators=operators, seed=seed)


__all__ = [
    "DEFAULT_MUTATION_BUDGET",
    "MAX_MUTATION_BUDGET",
    "MUTATION_OPERATORS",
    "apply_operator",
    "base64",
    "base64_encode",
    "casing",
    "generate_mutations",
    "mutate_attack",
    "paraphrase",
    "rot13",
    "split",
    "unicode",
    "whitespace",
]
