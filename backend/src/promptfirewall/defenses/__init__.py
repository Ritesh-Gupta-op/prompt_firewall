"""Composable input, context, prompt, tool, and output defenses."""

from promptfirewall.defenses.base import Defense
from promptfirewall.defenses.context_filtering import ContextFilter, filter_context_items
from promptfirewall.defenses.input_heuristic import (
    HeuristicSignal,
    InputHeuristic,
    InputHeuristicDefense,
    find_signals,
)
from promptfirewall.defenses.input_normalization import (
    InputNormalizationDefense,
    InputNormalizer,
    normalize_text,
)
from promptfirewall.defenses.output_scanner import OutputScanner, OutputScannerDefense, scan_text
from promptfirewall.defenses.pipeline import DefensePipeline, PipelineResult
from promptfirewall.defenses.prompt_profiles import (
    PROMPT_PROFILE_INSTRUCTIONS,
    PromptProfile,
    build_prompt,
)
from promptfirewall.defenses.registry import (
    DEFAULT_PROFILES,
    DEFAULT_REGISTRY,
    DEFENSE_PROFILES,
    PROFILE_FILTERS_ONLY,
    PROFILE_FULL_STACK,
    PROFILE_IDS,
    PROFILE_NONE,
    PROFILE_PROMPT_ONLY,
    PROFILE_TOOL_CONTROLS_ONLY,
    DefenseRegistry,
    create_default_registry,
    get_defense,
    get_profile,
)
from promptfirewall.defenses.tool_policy import ToolPolicy

__all__ = [
    "DEFAULT_PROFILES",
    "DEFAULT_REGISTRY",
    "DEFENSE_PROFILES",
    "Defense",
    "DefensePipeline",
    "DefenseRegistry",
    "HeuristicSignal",
    "InputHeuristic",
    "InputHeuristicDefense",
    "InputNormalizationDefense",
    "InputNormalizer",
    "PROMPT_PROFILE_INSTRUCTIONS",
    "PROFILE_FILTERS_ONLY",
    "PROFILE_FULL_STACK",
    "PROFILE_IDS",
    "PROFILE_NONE",
    "PROFILE_PROMPT_ONLY",
    "PROFILE_TOOL_CONTROLS_ONLY",
    "PipelineResult",
    "PromptProfile",
    "ToolPolicy",
    "ContextFilter",
    "OutputScanner",
    "OutputScannerDefense",
    "build_prompt",
    "create_default_registry",
    "filter_context_items",
    "find_signals",
    "get_defense",
    "get_profile",
    "normalize_text",
    "scan_text",
]
