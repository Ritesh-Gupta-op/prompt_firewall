from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock

import pytest

PIN = "3.11.2"


@pytest.fixture
def bootstrap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    script = Path(__file__).resolve().parents[3] / "scripts" / "bootstrap.py"
    spec = importlib.util.spec_from_file_location("project_bootstrap", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(module.platform, "python_version", lambda: PIN)
    (tmp_path / ".python-version").write_text(f"{PIN}\n", encoding="utf-8")
    (tmp_path / "requirements-dev.lock").write_text("# fixture lock\n", encoding="utf-8")
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / "pyproject.toml").write_text("", encoding="utf-8")
    return module


def create_environment(path: Path, *, with_pip: bool) -> None:
    assert with_pip
    (path / "bin").mkdir(parents=True)
    (path / "bin" / "python").touch()
    (path / "pyvenv.cfg").write_text(f"version = {PIN}\n", encoding="utf-8")


@pytest.fixture
def processes(bootstrap: ModuleType, monkeypatch: pytest.MonkeyPatch) -> tuple[Mock, Mock]:
    create = Mock(side_effect=create_environment)
    run = Mock(return_value=subprocess.CompletedProcess(
        args=[], returncode=0, stdout=f"{PIN}\n{bootstrap.PROJECT_ROOT / '.venv'}\n",
    ))
    monkeypatch.setattr(bootstrap.venv, "create", create)
    monkeypatch.setattr(bootstrap.subprocess, "run", run)
    return create, run


@pytest.mark.parametrize("existing", [False, True])
def test_setup_installs_locked_dependencies_then_editable_package(
    bootstrap: ModuleType, processes: tuple[Mock, Mock], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], existing: bool,
) -> None:
    create, run = processes
    environment = tmp_path / ".venv"
    if existing:
        create_environment(environment, with_pip=True)
        (environment / "keep.txt").write_text("existing work", encoding="utf-8")
    # The script must use its own project root, not the caller's current directory.
    monkeypatch.chdir(tmp_path / "backend")

    assert bootstrap.main() == 0

    if existing:
        create.assert_not_called()
        assert (environment / "keep.txt").read_text(encoding="utf-8") == "existing work"
    else:
        create.assert_called_once_with(environment, with_pip=True)
    assert run.call_count == 3
    probe, locked, editable = run.call_args_list
    assert probe.args[0][0] == str(environment / "bin" / "python")
    for call in (probe, locked, editable):
        assert call.kwargs["check"] is True
        assert call.kwargs["cwd"] == tmp_path
    for call in (locked, editable):
        command = call.args[0]
        assert command[:4] == [str(environment / "bin" / "python"), "-I", "-m", "pip"]
        assert "--require-virtualenv" in command
        assert "--isolated" in command
    assert locked.args[0][-3:] == [
        "--require-hashes", "-r", str(tmp_path / "requirements-dev.lock"),
    ]
    assert editable.args[0][-4:] == [
        "--no-deps", "--no-build-isolation", "-e", str(tmp_path / "backend"),
    ]
    assert "Setup complete" in capsys.readouterr().out


@pytest.mark.parametrize("actual", ["3.11.1", "3.11.3", "3.12.0", "3.11.2rc1"])
def test_pin_mismatch_fails_before_creating_or_installing(
    bootstrap: ModuleType, processes: tuple[Mock, Mock], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], actual: str,
) -> None:
    create, run = processes
    monkeypatch.setattr(bootstrap.platform, "python_version", lambda: actual)

    assert bootstrap.main() == 1

    create.assert_not_called()
    run.assert_not_called()
    assert not (tmp_path / ".venv").exists()
    error = capsys.readouterr().err
    assert f"requires Python {PIN}" in error
    assert f"running Python {actual}" in error
    assert "BOOTSTRAP_PYTHON" in error


def test_existing_wrong_venv_is_preserved_without_installing(
    bootstrap: ModuleType, processes: tuple[Mock, Mock], tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    create, run = processes
    environment = tmp_path / ".venv"
    create_environment(environment, with_pip=True)
    marker = environment / "keep.txt"
    marker.write_text("existing work", encoding="utf-8")
    run.return_value.stdout = f"3.11.1\n{environment}\n"

    assert bootstrap.main() == 1

    create.assert_not_called()
    run.assert_called_once()
    assert marker.read_text(encoding="utf-8") == "existing work"
    assert (environment / "bin" / "python").is_file()
    error = capsys.readouterr().err
    assert f".venv uses Python 3.11.1, but .python-version requires Python {PIN}" in error
    assert "preserved" in error


@pytest.mark.parametrize("pin", ["", "3.11", "3.11.2\n3.12.0"])
def test_invalid_pin_fails_without_changes(
    bootstrap: ModuleType, processes: tuple[Mock, Mock], tmp_path: Path,
    capsys: pytest.CaptureFixture[str], pin: str,
) -> None:
    create, run = processes
    (tmp_path / ".python-version").write_text(pin, encoding="utf-8")

    assert bootstrap.main() == 1

    create.assert_not_called()
    run.assert_not_called()
    assert "exact major.minor.patch" in capsys.readouterr().err


@pytest.mark.parametrize(
    "missing", [".python-version", "requirements-dev.lock", "backend/pyproject.toml"],
)
def test_missing_inputs_fail_before_creating_or_installing(
    bootstrap: ModuleType, processes: tuple[Mock, Mock], tmp_path: Path,
    capsys: pytest.CaptureFixture[str], missing: str,
) -> None:
    create, run = processes
    (tmp_path / missing).unlink()

    assert bootstrap.main() == 1

    create.assert_not_called()
    run.assert_not_called()
    assert missing in capsys.readouterr().err


@pytest.mark.parametrize("kind", ["file", "directory", "symlink"])
def test_invalid_existing_environment_is_preserved(
    bootstrap: ModuleType, processes: tuple[Mock, Mock], tmp_path: Path,
    capsys: pytest.CaptureFixture[str], kind: str,
) -> None:
    create, run = processes
    environment = tmp_path / ".venv"
    if kind == "symlink":
        environment.symlink_to(tmp_path / "absent", target_is_directory=True)
    elif kind == "directory":
        environment.mkdir()
    else:
        environment.write_text("existing work", encoding="utf-8")

    assert bootstrap.main() == 1

    create.assert_not_called()
    run.assert_not_called()
    if kind == "symlink":
        assert environment.is_symlink()
    elif kind == "directory":
        assert environment.is_dir()
    else:
        assert environment.read_text(encoding="utf-8") == "existing work"
    assert "preserved" in capsys.readouterr().err


@pytest.mark.parametrize("valid_output", [False, True])
def test_unverified_or_nonlocal_interpreter_cannot_install(
    bootstrap: ModuleType, processes: tuple[Mock, Mock], tmp_path: Path,
    capsys: pytest.CaptureFixture[str], valid_output: bool,
) -> None:
    _, run = processes
    run.return_value.stdout = f"{PIN}\n{tmp_path}\n" if valid_output else "unexpected output\n"

    assert bootstrap.main() == 1

    run.assert_called_once()
    assert "preserved" in capsys.readouterr().err


@pytest.mark.parametrize("stage", ["create", "probe", "locked", "editable"])
def test_failures_stop_setup_and_report_nonzero_status(
    bootstrap: ModuleType, processes: tuple[Mock, Mock],
    capsys: pytest.CaptureFixture[str], stage: str,
) -> None:
    create, run = processes
    if stage == "create":
        create.side_effect = OSError("venv creation failed")
        expected_calls = 0
    else:
        expected_calls = {"probe": 1, "locked": 2, "editable": 3}[stage]
        failure = subprocess.CalledProcessError(7, ["fixture-command"], stderr="fixture failure")
        run.side_effect = [run.return_value] * (expected_calls - 1) + [failure]

    assert bootstrap.main() == 1

    assert run.call_count == expected_calls
    output = capsys.readouterr()
    assert "Setup complete" not in output.out
    assert "Setup failed:" in output.err
    if stage == "create":
        assert "venv creation failed" in output.err
    else:
        assert "status 7" in output.err
        assert "fixture failure" in output.err
