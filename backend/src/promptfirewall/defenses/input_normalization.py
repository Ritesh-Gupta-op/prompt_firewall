"""Low-risk canonicalization for untrusted input."""

from __future__ import annotations

import re
import unicodedata

from promptfirewall.contracts.defenses import (
    DefenseAction,
    DefenseContext,
    DefenseDecision,
    DefensePayload,
    DefenseStage,
)
from promptfirewall.defenses.base import Defense, make_decision, replace_payload

_INVISIBLE_CHARS = dict.fromkeys(
    ord(character)
    for character in (
        "\u00ad",  # soft hyphen
        "\u034f",  # combining grapheme joiner
        "\u061c",  # Arabic letter mark
        "\u180e",  # Mongolian vowel separator
        "\u200b",  # zero-width space
        "\u200c",  # zero-width non-joiner
        "\u200d",  # zero-width joiner
        "\u2060",  # word joiner
        "\u2061",  # function application
        "\u2062",  # invisible times
        "\u2063",  # invisible separator
        "\u2064",  # invisible plus
        "\ufeff",  # zero-width no-break space
    )
)

# The map is deliberately small and one-way.  It makes common fixture
# homoglyph attacks observable without attempting to transliterate arbitrary
# user languages.
_HOMOGLYPH_TRANSLATION = str.maketrans(
    {
        "Α": "A",
        "Β": "B",
        "Ε": "E",
        "Ζ": "Z",
        "Η": "H",
        "Ι": "I",
        "Κ": "K",
        "Μ": "M",
        "Ν": "N",
        "Ο": "O",
        "Ρ": "P",
        "Τ": "T",
        "Υ": "Y",
        "Χ": "X",
        "а": "a",
        "с": "c",
        "е": "e",
        "о": "o",
        "р": "p",
        "х": "x",
        "у": "y",
        "і": "i",
        "ј": "j",
    }
)


def normalize_text(value: str) -> str:
    """Normalize Unicode and whitespace while preserving readable content."""

    if not isinstance(value, str):
        raise TypeError("input content must be a string")
    normalized = unicodedata.normalize("NFKC", value)
    normalized = normalized.translate(_INVISIBLE_CHARS).translate(_HOMOGLYPH_TRANSLATION)
    return re.sub(r"\s+", " ", normalized).strip()


class InputNormalizer(Defense):
    """Canonicalize user input before heuristic matching."""

    defense_id = "input-normalization"
    stage = DefenseStage.INPUT

    def evaluate(self, payload: DefensePayload, context: DefenseContext) -> DefenseDecision:
        del context
        if not isinstance(payload.content, str):
            return make_decision(
                self,
                DefenseAction.BLOCK,
                "invalid_input_content",
                metadata={"expected": "string"},
            )
        normalized = normalize_text(payload.content)
        changed = normalized != payload.content
        output = replace_payload(
            payload,
            normalized,
            original_content=payload.content if changed else None,
            metadata={"normalized": changed},
        )
        return make_decision(
            self,
            DefenseAction.SANITIZE if changed else DefenseAction.ALLOW,
            "input_normalized" if changed else "input_already_normalized",
            payload=output,
            metadata={"normalized": changed},
        )


InputNormalization = InputNormalizer
InputNormalizationDefense = InputNormalizer


__all__ = [
    "InputNormalization",
    "InputNormalizationDefense",
    "InputNormalizer",
    "normalize_text",
]
