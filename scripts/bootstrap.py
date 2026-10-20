"""Bootstrap the pinned development environment using only the standard library."""

from __future__ import annotations

import platform
import re
import shlex
import subprocess
import sys
import venv
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class BootstrapError(RuntimeError):
    """A setup prerequisite failed without permission to replace existing work."""


def bootstrap() -> None:
    required = (PROJECT_ROOT / ".python-version").read_text(encoding="utf-8").strip()
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", required) is None:
        raise BootstrapError(".python-version must contain an exact major.minor.patch version.")
    actual = platform.python_version()
    if actual != required:
        raise BootstrapError(
            f".python-version requires Python {required}; bootstrap is running Python {actual}. "
            "Select the pinned interpreter with make setup BOOTSTRAP_PYTHON=<interpreter>."
        )

    lockfile = PROJECT_ROOT / "requirements-dev.lock"
    package = PROJECT_ROOT / "backend"
    for prerequisite in (lockfile, package / "pyproject.toml"):
        if not prerequisite.is_file():
            raise BootstrapError(f"Required project file is missing: {prerequisite}")

    environment = PROJECT_ROOT / ".venv"
    if environment.is_symlink():
        raise BootstrapError(".venv must be a project-local directory, not a symlink; preserved.")
    if not environment.exists():
        venv.create(environment, with_pip=True)

    python = environment / "bin" / "python"
    if not (environment / "pyvenv.cfg").is_file() or not python.is_file():
        raise BootstrapError(".venv is incomplete or is not a virtual environment; preserved.")
    result = subprocess.run(
        [
            str(python), "-I", "-c",
            "import platform, sys; print(platform.python_version()); print(sys.prefix)",
        ],
        check=True,
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
    )
    details = result.stdout.splitlines()
    if len(details) != 2:
        raise BootstrapError("Could not verify .venv Python version and prefix; preserved.")
    version, prefix = details
    if version != required:
        raise BootstrapError(
            f".venv uses Python {version}, but .python-version requires Python {required}. "
            "Existing .venv preserved; move it aside yourself before rerunning setup."
        )
    if Path(prefix).resolve() != environment.resolve():
        raise BootstrapError(".venv/bin/python does not use the project-local .venv; preserved.")

    pip = [
        str(python), "-I", "-m", "pip", "--isolated", "--disable-pip-version-check",
        "--require-virtualenv", "--no-input", "install",
    ]
    subprocess.run(
        [*pip, "--require-hashes", "-r", str(lockfile)], check=True, cwd=PROJECT_ROOT,
    )
    subprocess.run(
        [*pip, "--no-deps", "--no-build-isolation", "-e", str(package)],
        check=True,
        cwd=PROJECT_ROOT,
    )


def main() -> int:
    try:
        bootstrap()
    except subprocess.CalledProcessError as exc:
        print(
            f"Setup failed: command {shlex.join(exc.cmd)} exited with status {exc.returncode}.",
            file=sys.stderr,
        )
        if exc.stderr:
            print(exc.stderr.strip(), file=sys.stderr)
        return 1
    except (BootstrapError, OSError) as exc:
        print(f"Setup failed: {exc}", file=sys.stderr)
        return 1
    print("Setup complete: .venv is ready. Run make test or make run.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
