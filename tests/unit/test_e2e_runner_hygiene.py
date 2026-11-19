"""Hygiene tests for the container E2E runner script (Task M27).

Verifies that ``uv build`` and local wheel staging in
``tests/e2e_containers/run_e2e.sh`` only run when ``INSTALL_SOURCE=wheel``,
while the Docker build context is always prepared.
"""

from __future__ import annotations

import dataclasses
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_E2E = REPO_ROOT / "tests" / "e2e_containers" / "run_e2e.sh"
NO_WHEEL_MSG = "uv build did not produce a verity_redteam_core wheel"

UV_STUB = """#!/usr/bin/env bash
set -euo pipefail
echo "uv $*" >> "${HARNESS_LOG:?}"
if [ "${1:-}" = "build" ]; then
  if [ -n "${HARNESS_PREBUILD_LISTING:-}" ]; then
    find . -maxdepth 4 -name 'verity_redteam_core-*.whl' -print | sort \\
      > "$HARNESS_PREBUILD_LISTING"
  fi
  if [ "${HARNESS_UV_CREATE_WHEEL:-1}" = "1" ]; then
    mkdir -p dist
    touch "dist/verity_redteam_core-${HARNESS_UV_VERSION:-9.9.9}-py3-none-any.whl"
  fi
fi
"""

DOCKER_STUB = """#!/usr/bin/env bash
set -euo pipefail
echo "docker $*" >> "${HARNESS_LOG:?}"
if [ "${1:-}" = "compose" ]; then
  for arg in "$@"; do
    if [ "$arg" = "build" ]; then
      if [ -d "${HARNESS_STAGE_DIR:?}" ]; then
        ls -1 "$HARNESS_STAGE_DIR" | sort > "${HARNESS_STAGE_LISTING:?}"
      else
        echo "MISSING" > "${HARNESS_STAGE_LISTING:?}"
      fi
      break
    fi
  done
fi
exit 0
"""


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


@dataclasses.dataclass
class _Harness:
    """Isolated, stubbed execution environment for ``run_e2e.sh``."""

    script: Path
    workdir: Path
    script_dir: Path
    log: Path
    env: dict[str, str]

    def stage_dir(self) -> Path:
        return self.script_dir / ".build_dist"

    def run(self, **env_overrides: str) -> subprocess.CompletedProcess[str]:
        run_env = self.env.copy()
        run_env.update(env_overrides)
        return subprocess.run(
            ["bash", str(self.script)],
            cwd=self.workdir,
            env=run_env,
            capture_output=True,
            text=True,
            check=False,
        )

    def invocations(self) -> list[str]:
        return self.log.read_text(encoding="utf-8").splitlines()


def _make_harness(tmp_path: Path) -> _Harness:
    script_dir = tmp_path / "tests" / "e2e_containers"
    script_dir.mkdir(parents=True)
    script = script_dir / "run_e2e.sh"
    shutil.copy2(RUN_E2E, script)
    (script_dir / "docker-compose.verify.yml").write_text(
        "services: {}\n", encoding="utf-8"
    )

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_executable(bin_dir / "uv", UV_STUB)
    _write_executable(bin_dir / "docker", DOCKER_STUB)

    log = tmp_path / "invocations.log"
    log.write_text("", encoding="utf-8")

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    env["HARNESS_LOG"] = str(log)
    env["HARNESS_STAGE_DIR"] = str(script_dir / ".build_dist")
    env["HARNESS_STAGE_LISTING"] = str(tmp_path / "stage.listing")
    env["HARNESS_PREBUILD_LISTING"] = str(tmp_path / "prebuild.listing")
    env.pop("INSTALL_SOURCE", None)
    return _Harness(
        script=script,
        workdir=tmp_path,
        script_dir=script_dir,
        log=log,
        env=env,
    )


def _seed_stale_artifacts(harness: _Harness) -> None:
    dist = harness.workdir / "dist"
    dist.mkdir()
    (dist / "verity_redteam_core-0.0.0-py3-none-any.whl").touch()
    stage = harness.stage_dir()
    stage.mkdir(parents=True, exist_ok=True)
    (stage / "verity_redteam_core-0.0.0-py3-none-any.whl").touch()


def _read_listing(path: Path) -> list[str]:
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8").split()


@pytest.fixture()
def script_text() -> str:
    return RUN_E2E.read_text(encoding="utf-8")


def _require_index(text: str, needle: str) -> int:
    idx = text.find(needle)
    assert idx != -1, f"missing {needle!r} in run_e2e.sh"
    return idx


def test_script_guards_uv_build(script_text: str) -> None:
    guard = _require_index(script_text, 'if [ "$INSTALL_SOURCE" = "wheel" ]; then')
    end = script_text.find("\nfi\n", guard)
    assert end != -1, "wheel branch is not closed"
    assert guard < _require_index(script_text, "uv build") < end


def test_script_creates_stage_dir_before_compose_build(script_text: str) -> None:
    mkdir_idx = _require_index(script_text, 'mkdir -p "$BUILD_DIST"')
    build_idx = _require_index(script_text, 'docker compose -f "$COMPOSE_FILE" build')
    assert mkdir_idx < build_idx


def test_script_removes_stale_wheels_before_build(script_text: str) -> None:
    uv_idx = _require_index(script_text, "uv build")
    assert (
        _require_index(script_text, 'rm -f "$REPO_ROOT"/dist/verity_redteam_core-*.whl')
        < uv_idx
    )
    assert (
        _require_index(script_text, 'rm -f "$BUILD_DIST"/verity_redteam_core-*.whl')
        < uv_idx
    )


def test_script_passes_install_source_build_arg(script_text: str) -> None:
    assert '--build-arg INSTALL_SOURCE="$INSTALL_SOURCE"' in script_text


def test_pypi_mode_skips_build_and_staging(tmp_path: Path) -> None:
    harness = _make_harness(tmp_path)
    _seed_stale_artifacts(harness)
    result = harness.run(INSTALL_SOURCE="pypi", HARNESS_UV_CREATE_WHEEL="0")
    assert result.returncode == 0, result.stderr

    invocations = harness.invocations()
    assert not any(line.startswith("uv ") for line in invocations)

    assert any(
        " build " in line
        and "--build-arg INSTALL_SOURCE=pypi" in line
        for line in invocations
    )

    stage_listing = tmp_path / "stage.listing"
    assert stage_listing.exists()
    assert _read_listing(stage_listing) == []


@pytest.mark.parametrize("install_source", ["wheel", "", None])
def test_wheel_mode_builds_and_stages_fresh_wheel(
    tmp_path: Path, install_source: str | None
) -> None:
    harness = _make_harness(tmp_path)
    _seed_stale_artifacts(harness)

    overrides = {"HARNESS_UV_VERSION": "9.9.9"}
    if install_source is not None:
        overrides["INSTALL_SOURCE"] = install_source
    result = harness.run(**overrides)
    assert result.returncode == 0, result.stderr

    prebuild_listing = tmp_path / "prebuild.listing"
    assert prebuild_listing.exists()
    assert _read_listing(prebuild_listing) == []

    invocations = harness.invocations()
    uv_idx = next(i for i, line in enumerate(invocations) if line.startswith("uv build"))
    build_idx = next(
        i
        for i, line in enumerate(invocations)
        if " build " in line and "--build-arg INSTALL_SOURCE=wheel" in line
    )
    assert uv_idx < build_idx

    stage_listing = tmp_path / "stage.listing"
    assert stage_listing.exists()
    assert _read_listing(stage_listing) == [
        "verity_redteam_core-9.9.9-py3-none-any.whl"
    ]


def test_wheel_mode_fails_fast_when_no_wheel(tmp_path: Path) -> None:
    harness = _make_harness(tmp_path)
    result = harness.run(INSTALL_SOURCE="wheel", HARNESS_UV_CREATE_WHEEL="0")
    assert result.returncode != 0
    assert NO_WHEEL_MSG in result.stderr


def test_script_passes_bash_syntax_check() -> None:
    result = subprocess.run(
        ["bash", "-n", str(RUN_E2E)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_script_passes_shellcheck_if_available() -> None:
    shellcheck = shutil.which("shellcheck")
    if shellcheck is None:
        pytest.skip("shellcheck not installed")
    result = subprocess.run(
        [shellcheck, str(RUN_E2E)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
