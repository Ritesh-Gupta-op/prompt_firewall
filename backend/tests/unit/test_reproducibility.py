"""Offline metadata contracts, also runnable in a Git-free export or Docker /build.

Alongside backend/, the test image needs .python-version, Dockerfile,
requirements.lock, requirements-dev.lock, and .env.example at the source root.
Only these public files and backend/pyproject.toml are read; no Git or pip is run.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass, field
from io import StringIO
from pathlib import Path, PurePosixPath, PureWindowsPath
from unittest.mock import patch

import pytest
from dotenv import dotenv_values
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version
from pydantic import AliasChoices

from promptfirewall.config import Settings

ROOT = Path(__file__).resolve().parents[3]
LOCKFILES = ("requirements.lock", "requirements-dev.lock")


def _metadata(relative_path: str) -> str:
    path = ROOT / relative_path
    assert path.is_file(), f"Missing {relative_path}; include it at the exported source root"
    return path.read_text(encoding="utf-8")


def _logical_lines(relative_path: str) -> Iterator[tuple[int, str]]:
    """Join backslash continuations without treating comments as requirements."""
    pending: list[str] = []
    start = 0
    for number, raw in enumerate(_metadata(relative_path).splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = re.split(r"\s+#", line, maxsplit=1)[0].rstrip()
        if not pending:
            start = number
        continued = line.endswith("\\")
        pending.append(line[:-1].rstrip() if continued else line)
        if not continued:
            yield start, " ".join(pending)
            pending.clear()
    assert not pending, f"{relative_path}:{start}: unterminated continuation"


def _registry_requirement(text: str, location: str) -> Requirement:
    try:
        requirement = Requirement(text)
    except InvalidRequirement:
        pytest.fail(f"{location}: expected a named requirement, not an editable/path/URL or option")
    assert requirement.url is None, f"{location}: dependency URLs/local paths are not portable"
    return requirement


def _locked_versions(relative_path: str) -> dict[str, Version]:
    versions: dict[str, Version] = {}
    for number, line in _logical_lines(relative_path):
        location = f"{relative_path}:{number}"
        requirement_text, *hashes = re.split(r"\s+(?=--hash(?:=|\s))", line)
        requirement = _registry_requirement(requirement_text, location)
        pins = list(requirement.specifier)
        assert len(pins) == 1 and pins[0].operator == "==" and "*" not in pins[0].version, (
            f"{location}: {requirement.name} must have one exact == pin"
        )
        assert hashes, f"{location}: {requirement.name} has no artifact hashes"
        assert all(re.fullmatch(r"--hash(?:=|\s+)sha256:[0-9a-fA-F]{64}", h) for h in hashes), (
            f"{location}: expected SHA-256 hash options only"
        )
        name = canonicalize_name(requirement.name)
        assert name not in versions, f"{location}: duplicate pin for {name}"
        versions[name] = Version(pins[0].version)
    assert versions, f"{relative_path} must not be empty"
    return versions


@dataclass
class DockerStage:
    base: str
    name: str
    instructions: list[tuple[str, str]] = field(default_factory=list)


def _docker_stages() -> list[DockerStage]:
    stages: list[DockerStage] = []
    for number, line in _logical_lines("Dockerfile"):
        instruction, arguments = line.split(maxsplit=1)
        if instruction.upper() == "FROM":
            match = re.fullmatch(
                r"(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", arguments, re.IGNORECASE,
            )
            assert match, f"Dockerfile:{number}: cannot parse FROM"
            stages.append(DockerStage(match[1], (match[2] or "").lower()))
        elif stages:
            stages[-1].instructions.append((instruction.upper(), arguments))
    assert stages, "Dockerfile must declare build stages"
    return stages


def _default_command(stage: DockerStage) -> list[str]:
    commands = [value for instruction, value in stage.instructions if instruction == "CMD"]
    assert commands, f"Docker {stage.name} stage must have a default CMD"
    command = commands[-1]
    return json.loads(command) if command.startswith("[") else shlex.split(command)


def test_python_pin_is_exact_and_matches_both_docker_bases() -> None:
    pin = _metadata(".python-version").strip()
    assert re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", pin), (
        ".python-version must contain exactly one major.minor.patch version"
    )
    pyproject = tomllib.loads(_metadata("backend/pyproject.toml"))
    assert Version(pin) in SpecifierSet(pyproject["project"]["requires-python"])
    python_bases = [stage.base for stage in _docker_stages() if stage.base.startswith("python:")]
    assert len(python_bases) == 2, "Expected Python bases for builder and runtime"
    for base in python_bases:
        assert re.fullmatch(
            rf"python:{re.escape(pin)}(?:-[A-Za-z0-9_.-]+)?(?:@sha256:[0-9a-fA-F]{{64}})?", base,
        ), f"Docker base {base} must match .python-version ({pin})"


def test_docker_test_target_inherits_builder_and_runtime_remains_default() -> None:
    stages = _docker_stages()
    test_stages = [stage for stage in stages if stage.name == "test"]
    assert len(test_stages) == 1, "Add a Docker test target: FROM builder AS test"
    test_stage = test_stages[0]
    assert test_stage.base.lower() == "builder", "The test target must reuse builder dependencies"
    assert any(stage.name == "builder" for stage in stages[:stages.index(test_stage)])
    assert any(Path(token).name == "pytest" for token in _default_command(test_stage)), (
        "The Docker test target CMD must run pytest"
    )
    runtime = stages[-1]
    assert runtime.name == "runtime", "The final/default Docker target must remain runtime"
    command = _default_command(runtime)
    assert any(Path(token).name == "uvicorn" for token in command)
    assert "promptfirewall.main:app" in command


@pytest.mark.parametrize("lockfile", LOCKFILES)
def test_lockfiles_have_only_exact_registry_pins_with_hashes(lockfile: str) -> None:
    _locked_versions(lockfile)


def test_runtime_pins_are_identical_in_the_development_lock() -> None:
    runtime = _locked_versions("requirements.lock")
    development = _locked_versions("requirements-dev.lock")
    missing = runtime.keys() - development.keys()
    assert not missing, f"Runtime packages missing from requirements-dev.lock: {sorted(missing)}"
    mismatches = {
        name: (str(version), str(development[name]))
        for name, version in runtime.items() if development[name] != version
    }
    assert not mismatches, f"Runtime/development pin mismatches: {mismatches}"


@pytest.mark.parametrize("group", ["runtime", "dev", "build"])
def test_direct_pyproject_requirements_are_satisfied_by_the_appropriate_lock(group: str) -> None:
    pyproject = tomllib.loads(_metadata("backend/pyproject.toml"))
    requirements = {
        "runtime": pyproject["project"]["dependencies"],
        "dev": pyproject["project"]["optional-dependencies"]["dev"],
        "build": pyproject["build-system"]["requires"],
    }[group]
    lockfile = "requirements.lock" if group == "runtime" else "requirements-dev.lock"
    versions = _locked_versions(lockfile)
    assert requirements, f"The {group} dependency group must not be empty"
    for text in requirements:
        requirement = _registry_requirement(text, f"backend/pyproject.toml ({group})")
        name = canonicalize_name(requirement.name)
        assert name in versions, f"{requirement.name} ({group}) is missing from {lockfile}"
        assert versions[name] in requirement.specifier, (
            f"{lockfile}: {name}=={versions[name]} does not satisfy {requirement} ({group})"
        )


def test_env_example_documents_every_canonical_settings_field() -> None:
    assignments = set(re.findall(
        r"^\s*(?:#\s*)?(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=",
        _metadata(".env.example"), re.MULTILINE,
    ))
    case_sensitive = Settings.model_config.get("case_sensitive", False)
    if not case_sensitive:
        assignments = {name.upper() for name in assignments}
    missing = {}
    for name, info in Settings.model_fields.items():
        alias = info.validation_alias or info.alias
        if isinstance(alias, AliasChoices):
            alias = alias.choices[0]
        canonical = alias or f"{Settings.model_config.get('env_prefix', '')}{name}"
        assert isinstance(canonical, str), f"{name} needs a string environment alias"
        if not case_sensitive:
            canonical = canonical.upper()
        if canonical not in assignments:
            missing[name] = canonical
    assert not missing, f".env.example needs active or commented assignments for: {missing}"


@pytest.mark.parametrize("use_example", [False, True], ids=["defaults", "env-example"])
def test_settings_have_safe_offline_defaults(
    use_example: bool, monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment: dict[str, str] = {}
    if use_example:
        # Explicit stream and disabled interpolation prevent dotenv discovery and
        # expansion of secrets from the caller's environment.
        values = dotenv_values(stream=StringIO(_metadata(".env.example")), interpolate=False)
        for name, value in values.items():
            assert value is not None, f".env.example: {name} needs an assignment"
            assert "$" not in value, f".env.example: {name} must not depend on ambient variables"
            environment[name] = value
    monkeypatch.setitem(Settings.model_config, "secrets_dir", None)
    with patch.dict(os.environ, environment, clear=True):
        settings = Settings(_env_file=None)
    assert settings.environment == "development"
    assert settings.model_provider == "mock"
    assert settings.model_name
    assert settings.api_key is None, "Default configuration must not include a service credential"
    assert settings.model_api_key is None, (
        "Default configuration must not include a model credential"
    )
    assert not settings.model_base_url, "Default mock configuration must not select a live endpoint"
    prefix = "sqlite+aiosqlite:///"
    assert settings.database_url.startswith(prefix), "Default database must be local SQLite"
    database = settings.database_url.removeprefix(prefix)
    assert database and not PurePosixPath(database).is_absolute()
    assert not PureWindowsPath(database).drive and ".." not in PurePosixPath(database).parts, (
        "Default database must be in-memory or a portable project-relative path"
    )
