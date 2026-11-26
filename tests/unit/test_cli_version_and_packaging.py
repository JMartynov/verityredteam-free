"""Unit tests for CLI --version flags and uvx/PyPI packaging metadata."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

import verity
from verity.cli import build_parser

REPO_ROOT = Path(__file__).resolve().parents[2]
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"


def test_pyproject_entrypoints_and_urls() -> None:
    """AC-30.1: pyproject.toml exposes dual uvx scripts and project URLs."""
    with PYPROJECT_PATH.open("rb") as handle:
        data = tomllib.load(handle)

    project = data["project"]
    scripts = project["scripts"]
    assert scripts["verity"] == "verity.cli:main"
    assert scripts["verity-redteam-core"] == "verity.cli:main"
    assert "unknown-alias" not in scripts

    urls = project["urls"]
    for key in ("Homepage", "Repository", "Documentation", "Issues"):
        assert key in urls, f"Missing [project.urls].{key}"
        assert isinstance(urls[key], str)
        assert urls[key].startswith("https://")
        assert len(urls[key]) > len("https://")


@pytest.mark.parametrize("flag", ["--version", "-V"])
def test_cli_version_flags(capsys: pytest.CaptureFixture[str], flag: str) -> None:
    """AC-30.2: --version and -V print `verity <__version__>` and exit 0."""
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args([flag])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert captured.out == f"verity {verity.__version__}\n"


def test_cli_invalid_version_flag_exits_two() -> None:
    """Negative control: unrecognized version flag exits with code 2."""
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--invalid-version-flag"])
    assert exc.value.code == 2
