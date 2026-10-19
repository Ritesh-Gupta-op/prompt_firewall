"""Defense implementations and the supported benchmark profiles."""

from __future__ import annotations

from collections.abc import Iterable

from promptfirewall.contracts.defenses import DefenseProfile
from promptfirewall.defenses.base import Defense
from promptfirewall.defenses.context_filtering import ContextFilter
from promptfirewall.defenses.input_heuristic import InputHeuristic
from promptfirewall.defenses.input_normalization import InputNormalizer
from promptfirewall.defenses.output_scanner import OutputScanner
from promptfirewall.defenses.prompt_profiles import PromptProfile
from promptfirewall.defenses.tool_policy import ToolPolicy

PROFILE_NONE = "none"
PROFILE_PROMPT_ONLY = "prompt-only"
PROFILE_FILTERS_ONLY = "filters-only"
PROFILE_TOOL_CONTROLS_ONLY = "tool-controls-only"
PROFILE_FULL_STACK = "full-stack"
PROFILE_IDS = (
    PROFILE_NONE,
    PROFILE_PROMPT_ONLY,
    PROFILE_FILTERS_ONLY,
    PROFILE_TOOL_CONTROLS_ONLY,
    PROFILE_FULL_STACK,
)

_TOOL = "tool-policy"
_PROMPT = "prompt-profile"
_FILTERS = ("input-normalization", "input-heuristic", "context-filter", "output-scanner")

DEFAULT_PROFILES: tuple[DefenseProfile, ...] = (
    DefenseProfile(
        id=PROFILE_NONE,
        name="None",
        description="No experimental prompt or filter defenses; host tool safety remains active.",
        enabled_defenses=[_TOOL],
        prompt_mode="none",
    ),
    DefenseProfile(
        id=PROFILE_PROMPT_ONLY,
        name="Prompt only",
        description="Add a hardened system prompt while retaining deterministic host tool safety.",
        enabled_defenses=[_PROMPT, _TOOL],
        prompt_mode="hardened",
    ),
    DefenseProfile(
        id=PROFILE_FILTERS_ONLY,
        name="Filters only",
        description="Normalize and filter input, context, and output with host tool safety.",
        enabled_defenses=[*_FILTERS, _TOOL],
        prompt_mode="none",
    ),
    DefenseProfile(
        id=PROFILE_TOOL_CONTROLS_ONLY,
        name="Tool controls only",
        description="Use deterministic tool authorization without prompt or content filters.",
        enabled_defenses=[_TOOL],
        prompt_mode="none",
    ),
    DefenseProfile(
        id=PROFILE_FULL_STACK,
        name="Full stack",
        description="Use prompt hardening, content filters, and deterministic host tool safety.",
        enabled_defenses=[_PROMPT, *_FILTERS, _TOOL],
        prompt_mode="hardened",
    ),
)


class DefenseRegistry:
    """Resolve defenses and immutable profile definitions by stable ID."""

    def __init__(
        self,
        defenses: Iterable[Defense] | None = None,
        profiles: Iterable[DefenseProfile] = DEFAULT_PROFILES,
    ) -> None:
        self._defenses: dict[str, Defense] = {}
        self._profiles: dict[str, DefenseProfile] = {}
        if defenses is None:
            defenses = _default_defenses()
        for defense in defenses:
            self.register(defense)
        for profile in profiles:
            self.register_profile(profile)

    def register(self, defense: Defense) -> None:
        if defense.defense_id in self._defenses:
            raise ValueError(f"defense already registered: {defense.defense_id}")
        self._defenses[defense.defense_id] = defense

    def register_profile(self, profile: DefenseProfile) -> None:
        profile_id = _normalize_profile_id(profile.id)
        if profile_id in self._profiles:
            raise ValueError(f"profile already registered: {profile.id}")
        missing = set(profile.enabled_defenses) - set(self._defenses)
        if missing:
            raise ValueError(f"profile references unregistered defenses: {sorted(missing)}")
        self._profiles[profile_id] = profile.model_copy(update={"id": profile_id})

    def get(self, defense_id: str) -> Defense:
        try:
            return self._defenses[defense_id]
        except KeyError as error:
            raise KeyError(f"unknown defense: {defense_id}") from error

    def get_profile(self, profile_id: str) -> DefenseProfile:
        normalized = _normalize_profile_id(profile_id)
        try:
            return self._profiles[normalized]
        except KeyError as error:
            raise KeyError(f"unknown defense profile: {profile_id}") from error

    def defenses_for(self, profile: str | DefenseProfile) -> tuple[Defense, ...]:
        resolved = self.get_profile(profile) if isinstance(profile, str) else profile
        return tuple(self.get(defense_id) for defense_id in resolved.enabled_defenses)

    def profiles(self) -> tuple[DefenseProfile, ...]:
        return tuple(
            self._profiles[profile_id]
            for profile_id in PROFILE_IDS
            if profile_id in self._profiles
        )

    def defense_ids(self) -> tuple[str, ...]:
        return tuple(self._defenses)


def _normalize_profile_id(profile_id: str) -> str:
    normalized = profile_id.strip().casefold().replace("_", "-")
    return normalized


def create_default_registry() -> DefenseRegistry:
    return DefenseRegistry(defenses=_default_defenses())


def _default_defenses() -> tuple[Defense, ...]:
    return (
        InputNormalizer(),
        InputHeuristic(),
        ContextFilter(),
        PromptProfile(),
        ToolPolicy(),
        OutputScanner(),
    )


DEFAULT_REGISTRY = create_default_registry()
DEFENSE_PROFILES = DEFAULT_PROFILES


def get_profile(profile_id: str) -> DefenseProfile:
    return DEFAULT_REGISTRY.get_profile(profile_id)


def get_defense(defense_id: str) -> Defense:
    return DEFAULT_REGISTRY.get(defense_id)


__all__ = [
    "DEFAULT_PROFILES",
    "DEFAULT_REGISTRY",
    "DefenseRegistry",
    "PROFILE_FILTERS_ONLY",
    "PROFILE_FULL_STACK",
    "PROFILE_IDS",
    "PROFILE_NONE",
    "PROFILE_PROMPT_ONLY",
    "PROFILE_TOOL_CONTROLS_ONLY",
    "create_default_registry",
    "get_defense",
    "get_profile",
]
