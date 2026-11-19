"""Documentation parity guard enforcing README fidelity to the Verity CLI."""

from __future__ import annotations

import argparse
import re
import shlex
import tomllib
from pathlib import Path
from typing import Any

import pytest

from verity.cli import build_parser

REPO_ROOT = Path(__file__).resolve().parents[2]
README_PATH = REPO_ROOT / "README.md"
EXTENSIBILITY_PATH = REPO_ROOT / "docs" / "extensibility.md"

_FENCE_RE = re.compile(r"```(?P<lang>[A-Za-z0-9_+-]*)\r?\n(?P<body>.*?)```", re.DOTALL)
_LINK_RE = re.compile(r"!?\[[^\]]*\]\((?P<target>[^)]+)\)")
_STALE_PACKAGE_RE = re.compile(r"\bverity-core\b")
_SHELL_LANGS = {"bash", "sh", "console", "shell"}
_SNAPSHOT_DIR = REPO_ROOT / "tests" / "e2e_containers" / "snapshots"
_DEMO_TAPE_PATH = REPO_ROOT / "docs" / "assets" / "demo.tape"
_DEMO_GIF_PATH = REPO_ROOT / "docs" / "assets" / "demo.gif"
_ELLIPSIS_RULE_RE = re.compile(r"\b(?:VERITY|SEC)-[A-Z0-9_-]*…")

_BADGE_LINE_RE = re.compile(
    r"^\[!\[(?P<alt>[^\]]*)\]\((?P<image>[^)]+)\)\]\((?P<target>[^)]+)\)\s*$"
)
_PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"
_HERO_LINE_LIMIT = 8
_TAGLINE_PREFIX = "Catch poisoned MCP servers"

_HERO_BADGES: dict[str, tuple[str, str]] = {
    "pypi": (
        "https://img.shields.io/pypi/v/verity-redteam-core.svg",
        "https://pypi.org/project/verity-redteam-core/",
    ),
    "python": (
        "https://img.shields.io/badge/python-3.12%2B-blue.svg",
        "https://pypi.org/project/verity-redteam-core/",
    ),
    "license": (
        "https://img.shields.io/badge/License-Apache_2.0-blue.svg",
        "LICENSE",
    ),
    "ci": (
        "https://github.com/JMartynov/verityredteam-free/actions/workflows/ci.yml/badge.svg",
        "https://github.com/JMartynov/verityredteam-free/actions/workflows/ci.yml",
    ),
}

_HERO_BADGE_CASES = [
    pytest.param(image, target, id=name)
    for name, (image, target) in _HERO_BADGES.items()
]

STATIC_RULE_IDS = (
    "VERITY-STATIC-INJECTION-OVERRIDE",
    "VERITY-STATIC-INJECTION-DELIMITER",
    "VERITY-STATIC-TOOL-POISONING",
    "VERITY-STATIC-EXFIL-WEBHOOK",
    "VERITY-STATIC-EXFIL-COVERT",
    "VERITY-STATIC-METADATA-SSRF",
    "VERITY-STATIC-CREDENTIAL-HARVESTING",
    "VERITY-STATIC-SHELL-DROPPER",
    "VERITY-STATIC-SHELL-REVERSE-PIPE",
    "VERITY-STATIC-CODE-EXECUTION",
    "VERITY-STATIC-SHELL-DESTRUCTIVE",
    "VERITY-STATIC-SQL-INJECTION-SCHEMA",
    "VERITY-STATIC-SCRIPT-INJECTION-XSS",
)

AST_RULE_IDS = (
    "VERITY-AST-CWE-94-EVAL",
    "VERITY-AST-CWE-94-COMPILE",
    "VERITY-AST-CWE-78-SHELL",
    "VERITY-AST-CWE-78-SYSTEM",
    "VERITY-AST-CWE-22-TRAVERSAL",
    "VERITY-AST-CWE-502-PICKLE",
    "VERITY-AST-CWE-502-YAML",
    "VERITY-AST-CWE-79-XSS",
    "VERITY-AST-CWE-862-BOLA",
)

DEMO_CWES = ("CWE-89", "CWE-639", "CWE-943", "CWE-94")

KEY_FLAGS = (
    "--config-file",
    "--schema-file",
    "--path",
    "--fail-on-findings",
    "--offline",
    "--command",
    "--url",
    "--sql",
    "--demo",
    "--format",
    "--output",
    "--transport",
)


def _find_subparsers(
    parser: argparse.ArgumentParser,
) -> argparse._SubParsersAction | None:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action
    return None


def _collect_cli_surface() -> dict[str, dict[str, Any]]:
    parser = build_parser()
    subparsers = _find_subparsers(parser)
    assert subparsers is not None, "CLI must expose subcommands"

    surface: dict[str, dict[str, Any]] = {}
    for name, subparser in subparsers.choices.items():
        options: set[str] = set()
        choices: dict[str, tuple[str, ...]] = {}
        for action in subparser._actions:
            options.update(action.option_strings)
            if action.choices is not None and action.option_strings:
                choices[action.option_strings[0]] = tuple(
                    str(choice) for choice in action.choices
                )
        surface[name] = {"options": options, "choices": choices}
    return surface


def _readme_hero_lines() -> list[str]:
    return README_PATH.read_text(encoding="utf-8").splitlines()[:_HERO_LINE_LIMIT]


def _parse_badge_lines(lines: list[str]) -> dict[str, tuple[str, int]]:
    parsed: dict[str, tuple[str, int]] = {}
    for index, line in enumerate(lines):
        match = _BADGE_LINE_RE.match(line)
        if match is not None:
            parsed[match.group("image")] = (match.group("target"), index)
    return parsed


def _split_command_line(line: str) -> list[str] | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    line = re.sub(r"\s+#.*$", "", line).strip()
    line = line.lstrip("$").strip()
    if not line:
        return None
    try:
        tokens = shlex.split(line)
    except ValueError:
        return None

    while tokens and "=" in tokens[0] and not tokens[0].startswith("verity"):
        tokens = tokens[1:]

    if len(tokens) >= 2 and tokens[0] == "uv" and tokens[1] == "run":
        tokens = tokens[2:]
    elif tokens and tokens[0] == "uvx":
        try:
            start = tokens.index("verity")
        except ValueError:
            return None
        tokens = tokens[start:]

    if not tokens or tokens[0] != "verity":
        return None
    return tokens


def _extract_text_block(markdown: str, anchor: str) -> str:
    assert anchor in markdown, f"README must contain the anchor {anchor!r}"
    start = markdown.index(anchor)
    for match in _FENCE_RE.finditer(markdown, start):
        if (match.group("lang") or "").lower() == "text":
            return match.group("body")
    pytest.fail(f"No fenced text block after anchor {anchor!r}")


def _assert_matches_snapshot(block: str, snapshot_name: str) -> None:
    snapshot = (_SNAPSHOT_DIR / snapshot_name).read_text(encoding="utf-8")
    assert block.rstrip("\n") == snapshot.rstrip("\n"), (
        f"README block must match {snapshot_name} verbatim"
    )


def _extract_verity_commands(markdown: str) -> list[list[str]]:
    commands: list[list[str]] = []
    for match in _FENCE_RE.finditer(markdown):
        lang = (match.group("lang") or "").lower()
        if lang not in _SHELL_LANGS:
            continue
        body = match.group("body").replace("\\\n", " ")
        for raw in body.splitlines():
            tokens = _split_command_line(raw)
            if tokens:
                commands.append(tokens)
    return commands


def test_cli_surface_exposes_expected_commands_and_formats() -> None:
    surface = _collect_cli_surface()
    assert {"scan", "test", "serve"} <= set(surface)
    assert "markdown" in surface["scan"]["choices"]["--format"]
    assert "json" in surface["test"]["choices"]["--format"]
    assert {"stdio", "sse", "http"} <= set(surface["serve"]["choices"]["--transport"])


def test_readme_cli_commands_are_valid() -> None:
    parser = build_parser()
    commands = _extract_verity_commands(README_PATH.read_text(encoding="utf-8"))
    assert commands, "README must show at least one runnable verity command"
    for tokens in commands:
        try:
            parser.parse_args(tokens[1:])
        except SystemExit as exc:  # argparse raises SystemExit on invalid invocations
            pytest.fail(
                f"README documents an invalid CLI command: {' '.join(tokens)!r} "
                f"(argparse exit code {exc.code})"
            )


def test_no_stale_package_references() -> None:
    for path in (README_PATH, EXTENSIBILITY_PATH):
        text = path.read_text(encoding="utf-8")
        assert not _STALE_PACKAGE_RE.search(text), (
            f"{path.name} references the retired 'verity-core' package"
        )


@pytest.mark.parametrize(("image", "target"), _HERO_BADGE_CASES)
def test_readme_hero_badges_present_and_valid(image: str, target: str) -> None:
    hero_lines = _readme_hero_lines()
    hero_text = "\n".join(hero_lines)

    h1_index = next(
        (index for index, line in enumerate(hero_lines) if line.startswith("# ")),
        None,
    )
    tagline_index = next(
        (
            index
            for index, line in enumerate(hero_lines)
            if line.startswith(_TAGLINE_PREFIX)
        ),
        None,
    )
    assert h1_index is not None, "README hero must open with an H1 title"
    assert tagline_index is not None, "README hero tagline must stay within 8 lines"
    assert h1_index < tagline_index

    parsed = _parse_badge_lines(hero_lines)
    assert len(parsed) == len(_HERO_BADGES), (
        f"README hero must show {len(_HERO_BADGES)} badges, found {len(parsed)}"
    )
    badge_line_count = sum(
        1 for line in hero_lines if _BADGE_LINE_RE.match(line) is not None
    )
    assert badge_line_count == len(_HERO_BADGES), (
        f"README hero must contain exactly {len(_HERO_BADGES)} badge lines, "
        f"found {badge_line_count}"
    )
    hero_images = [img for img, _ in _HERO_BADGES.values()]
    assert set(parsed) == set(hero_images), (
        "README hero badges mismatch: expected "
        f"{hero_images!r}, found {sorted(parsed)!r}"
    )
    badge_indices = [parsed[img][1] for img in hero_images]
    assert badge_indices == sorted(badge_indices), (
        "README hero badges must appear in order: " + ", ".join(_HERO_BADGES)
    )
    assert image in parsed, f"README hero is missing the badge {image!r}"
    actual_target, badge_index = parsed[image]
    assert actual_target == target
    assert h1_index < badge_index < tagline_index
    assert _LINK_RE.search(hero_lines[badge_index]) is not None

    if not target.startswith(("http://", "https://", "mailto:", "#")):
        assert (REPO_ROOT / target).is_file(), (
            f"Badge target {target!r} does not resolve"
        )

    assert not _STALE_PACKAGE_RE.search(hero_text)
    assert (REPO_ROOT / ".github" / "workflows" / "ci.yml").is_file()


def test_readme_hero_badges_match_wheel_metadata() -> None:
    with _PYPROJECT_PATH.open("rb") as handle:
        pyproject = tomllib.load(handle)
    project = pyproject.get("project", {})
    hero_text = "\n".join(_readme_hero_lines())

    name = project.get("name")
    assert name == "verity-redteam-core"
    assert f"img.shields.io/pypi/v/{name}.svg" in hero_text

    requires_python = project.get("requires-python", "")
    floor = re.match(r">=?\s*(\d+)\.(\d+)", requires_python)
    assert floor is not None, f"Unparsable requires-python: {requires_python!r}"
    major, minor = floor.groups()
    assert f"python-{major}.{minor}%2B" in hero_text, (
        f"README Python badge must advertise {major}.{minor}+"
    )

    license_field = project.get("license", "")
    if isinstance(license_field, dict):
        license_field = license_field.get("text", "")
    assert license_field == "Apache-2.0"
    assert "License-Apache_2.0" in hero_text


def test_demo_asset_is_retired_svg_replaced_by_gif() -> None:
    text = README_PATH.read_text(encoding="utf-8")
    assert "docs/assets/demo.gif" in text
    assert (REPO_ROOT / "docs" / "assets" / "demo.gif").is_file()
    assert "docs/assets/demo.svg" not in text
    assert not (REPO_ROOT / "docs" / "assets" / "demo.svg").exists()


def test_relative_links_and_media_resolve() -> None:
    for path in (README_PATH, EXTENSIBILITY_PATH):
        text = path.read_text(encoding="utf-8")
        for match in _LINK_RE.finditer(text):
            raw = match.group("target").strip()
            target = raw.split()[0].strip("\"'")
            if not target or target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            relative = target.split("#", 1)[0]
            if not relative:
                continue
            resolved = (path.parent / relative).resolve()
            assert resolved.exists(), (
                f"Broken relative link {relative!r} in {path.name}"
            )


def test_readme_documents_free_capabilities() -> None:
    text = README_PATH.read_text(encoding="utf-8")
    for subcommand in ("verity scan", "verity test", "verity serve"):
        assert subcommand in text
    for flag in KEY_FLAGS:
        assert flag in text, f"README must document {flag}"
    assert "SqlSecurityGuard" in text
    for rule_id in STATIC_RULE_IDS + AST_RULE_IDS:
        assert rule_id in text, f"README must document rule {rule_id}"
    for cwe in DEMO_CWES:
        assert cwe in text, f"README must document demo CWE {cwe}"


def test_readme_workstation_table_matches_snapshot() -> None:
    text = README_PATH.read_text(encoding="utf-8")
    block = _extract_text_block(text, "Verified Result:")
    _assert_matches_snapshot(block, "01_workstation_scan.txt")


def test_readme_schema_table_matches_snapshot() -> None:
    text = README_PATH.read_text(encoding="utf-8")
    block = _extract_text_block(text, "Offline schema screen output")
    _assert_matches_snapshot(block, "02_schema_scan.txt")


def test_readme_has_no_ellipsized_rule_ids() -> None:
    text = README_PATH.read_text(encoding="utf-8")
    match = _ELLIPSIS_RULE_RE.search(text)
    assert match is None, f"README contains an ellipsized rule ID: {match.group(0)!r}"
    for rule_id in STATIC_RULE_IDS:
        assert rule_id in text, f"README must document rule {rule_id}"


def test_demo_tape_scene4_uses_full_demo() -> None:
    text = _DEMO_TAPE_PATH.read_text(encoding="utf-8")
    marker = "# Scene 4:"
    assert marker in text, "demo.tape must keep the Scene 4 marker"
    scene4 = text.split(marker, 1)[1]
    assert 'Type "verity test --demo"' in scene4
    assert "--target" not in scene4


def test_demo_gif_present_and_not_stale() -> None:
    assert _DEMO_GIF_PATH.is_file(), "docs/assets/demo.gif must exist"
    assert "docs/assets/demo.gif" in README_PATH.read_text(encoding="utf-8")
