"""Documentation parity guard enforcing README fidelity to the Verity CLI."""

from __future__ import annotations

import argparse
import re
import shlex
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest

from verity.cli import build_parser

REPO_ROOT = Path(__file__).resolve().parents[2]
README_PATH = REPO_ROOT / "README.md"
EXTENSIBILITY_PATH = REPO_ROOT / "docs" / "extensibility.md"
AGENTS_PATH = REPO_ROOT / "AGENTS.md"

_FENCE_RE = re.compile(r"```(?P<lang>[A-Za-z0-9_+-]*)\r?\n(?P<body>.*?)```", re.DOTALL)
_LINK_RE = re.compile(r"!?\[[^\]]*\]\((?P<target>[^)]+)\)")
_STALE_PACKAGE_RE = re.compile(r"\bverity-core\b")
_SHELL_LANGS = {"bash", "sh", "console", "shell"}
_YAML_LANGS = {"yaml", "yml"}
_YAML_RUN_RE = re.compile(r"^\s*(?:-\s*)?run:\s*(?P<rest>.*)$")
_YAML_BLOCK_SCALAR_MARKERS = {"|", ">", "|-", ">-", "|+", ">+"}
_LINE_CONTINUATION_RE = re.compile(r"\\\r?\n")
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

TASK_BOARD_PATH = REPO_ROOT / "TASK_BOARD.md"
_PROJECT_5_URL = "https://github.com/users/JMartynov/projects/5"
_PROJECT_ITEM_ID_RE = re.compile(r"PVTI_[A-Za-z0-9_-]{10,}")
_TASK_MATRIX_ROW_RE = re.compile(r"^\| \*\*M(?P<number>\d+)\*\* \|")
_TASK_SECTION_RE = re.compile(r"^### M(?P<number>\d+):", re.MULTILINE)
_INLINE_SPEC_MARKER = "Inline below"


def _parse_task_matrix_rows(text: str) -> dict[int, dict[str, Any]]:
    rows: dict[int, dict[str, Any]] = {}
    for line in text.splitlines():
        match = _TASK_MATRIX_ROW_RE.match(line)
        if match is None:
            continue
        number = int(match.group("number"))
        assert number not in rows, (
            f"TASK_BOARD.md defines the Task Matrix row M{number} twice"
        )
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        rows[number] = {
            "line": line,
            "cells": cells,
            "spec": cells[3] if len(cells) > 3 else "",
            "item_ids": _PROJECT_ITEM_ID_RE.findall(line),
        }
    return rows


def _parse_task_sections(text: str) -> dict[int, str]:
    matches = list(_TASK_SECTION_RE.finditer(text))
    sections: dict[int, str] = {}
    for index, match in enumerate(matches):
        number = int(match.group("number"))
        assert number not in sections, (
            f"TASK_BOARD.md defines the detailed section M{number} twice"
        )
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        sections[number] = text[match.start() : end]
    return sections


def _single_project_item_id(text: str, label: str) -> str:
    item_ids = _PROJECT_ITEM_ID_RE.findall(text)
    assert len(item_ids) == 1, (
        f"{label} must state exactly one PVTI_... item id, found {item_ids!r}"
    )
    return item_ids[0]


_TASK_BOARD_TEXT = TASK_BOARD_PATH.read_text(encoding="utf-8")
_TASK_MATRIX_ROWS = _parse_task_matrix_rows(_TASK_BOARD_TEXT)
_TASK_SECTIONS = _parse_task_sections(_TASK_BOARD_TEXT)
_TASK_MATRIX_ROW_CASES = [
    pytest.param(number, row, id=f"M{number}")
    for number, row in sorted(_TASK_MATRIX_ROWS.items())
]
_TASK_SECTION_CASES = [
    pytest.param(number, section, id=f"M{number}")
    for number, section in sorted(_TASK_SECTIONS.items())
]


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


def _yaml_command_lines(body: str) -> list[str]:
    """Flatten a YAML fence into candidate command lines (unwraps ``run:``)."""
    lines: list[str] = []
    for raw in _LINE_CONTINUATION_RE.sub(" ", body).splitlines():
        match = _YAML_RUN_RE.match(raw)
        if match is None:
            lines.append(raw)
            continue
        rest = match.group("rest").strip()
        if rest and rest not in _YAML_BLOCK_SCALAR_MARKERS:
            lines.append(rest)
    return lines


def _iter_fence_commands(markdown: str, langs: set[str]) -> list[list[str]]:
    commands: list[list[str]] = []
    for match in _FENCE_RE.finditer(markdown):
        lang = (match.group("lang") or "").lower()
        if lang not in langs:
            continue
        body = match.group("body")
        candidates = (
            _yaml_command_lines(body)
            if lang in _YAML_LANGS
            else _LINE_CONTINUATION_RE.sub(" ", body).splitlines()
        )
        for raw in candidates:
            tokens = _split_command_line(raw)
            if tokens:
                commands.append(tokens)
    return commands


def _extract_verity_commands(markdown: str) -> list[list[str]]:
    return _iter_fence_commands(markdown, _SHELL_LANGS | _YAML_LANGS)


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


def test_yaml_backslash_continuations_are_unwrapped() -> None:
    markdown = "```yaml\n      run: |\n        verity scan \\\n          --offline\n```\n"
    assert _extract_verity_commands(markdown) == [["verity", "scan", "--offline"]]


def test_invalid_yaml_verity_command_is_rejected() -> None:
    markdown = "```yaml\nrun: verity scan --definitely-not-a-flag\n```\n"
    commands = _extract_verity_commands(markdown)
    assert commands == [["verity", "scan", "--definitely-not-a-flag"]]
    with pytest.raises(SystemExit):
        build_parser().parse_args(commands[0][1:])


def test_readme_yaml_snippet_commands_are_valid() -> None:
    parser = build_parser()
    markdown = README_PATH.read_text(encoding="utf-8")
    commands = _iter_fence_commands(markdown, _YAML_LANGS)
    assert commands, "README must document runnable verity commands in YAML fences"
    for tokens in commands:
        try:
            parser.parse_args(tokens[1:])
        except SystemExit as exc:  # argparse raises SystemExit on invalid invocations
            pytest.fail(
                f"README documents an invalid YAML CLI command: {' '.join(tokens)!r} "
                f"(argparse exit code {exc.code})"
            )


def test_yaml_hardening_preserves_shell_fence_commands() -> None:
    markdown = README_PATH.read_text(encoding="utf-8")
    shell_commands = _iter_fence_commands(markdown, _SHELL_LANGS)
    assert shell_commands, "README must keep runnable shell fence commands"
    combined = _extract_verity_commands(markdown)
    for tokens in shell_commands:
        assert tokens in combined, (
            f"YAML hardening dropped shell fence command: {' '.join(tokens)!r}"
        )
    assert len(combined) >= len(shell_commands)


def test_readme_has_no_stale_pypi_caveat() -> None:
    text = README_PATH.read_text(encoding="utf-8").lower()
    assert "not yet on pypi" not in text


def test_readme_documents_pypi_quickstart() -> None:
    text = README_PATH.read_text(encoding="utf-8")
    assert "pip install verity-redteam-core" in text
    assert "uvx --from verity-redteam-core" in text

    summary = "<summary>Install from source (contributors)</summary>"
    assert summary in text
    summary_index = text.index(summary)
    details_open = text.rindex("<details>", 0, summary_index)
    details_close = text.index("</details>", summary_index)
    assert details_open < summary_index < details_close
    assert text.index("pip install verity-redteam-core") < details_open
    assert "dist/*.whl" in text[details_open:details_close]


@pytest.mark.parametrize("path", [README_PATH, EXTENSIBILITY_PATH, AGENTS_PATH])
def test_no_stale_package_references(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert not _STALE_PACKAGE_RE.search(text), (
        f"{path.name} references the retired 'verity-core' package"
    )


def test_agents_md_documents_current_package_name() -> None:
    text = AGENTS_PATH.read_text(encoding="utf-8")
    assert "verity-redteam-core" in text, "AGENTS.md must name the current package"
    assert not _STALE_PACKAGE_RE.search(text), (
        "AGENTS.md references the retired 'verity-core' package"
    )


def test_agents_md_has_no_stale_task_range() -> None:
    text = AGENTS_PATH.read_text(encoding="utf-8")
    assert re.search("Tasks\\s+M1[\u2013-]M6", text) is None, (
        "AGENTS.md must not pin a stale task range"
    )
    assert "TASK_BOARD.md" in text, "AGENTS.md must point at TASK_BOARD.md"


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


def test_task_board_defines_matrix_rows_and_sections() -> None:
    assert _TASK_MATRIX_ROWS, "TASK_BOARD.md must define Task Matrix rows"
    assert _TASK_SECTIONS, "TASK_BOARD.md must define detailed M<n> sections"


@pytest.mark.parametrize(("number", "row"), _TASK_MATRIX_ROW_CASES)
def test_task_matrix_rows_carry_project_item_ids(
    number: int, row: dict[str, Any]
) -> None:
    item_ids = row["item_ids"]
    assert len(item_ids) == 1, (
        f"Matrix row M{number} must carry exactly one PVTI_... item id, "
        f"found {item_ids!r}"
    )
    assert _PROJECT_ITEM_ID_RE.fullmatch(item_ids[0]), (
        f"Matrix row M{number} item id {item_ids[0]!r} is malformed"
    )


@pytest.mark.parametrize(("number", "row"), _TASK_MATRIX_ROW_CASES)
def test_task_matrix_rows_link_to_project_5(
    number: int, row: dict[str, Any]
) -> None:
    item_id = _single_project_item_id(row["line"], f"Matrix row M{number}")
    expected = f"[View Item #M{number}]({_PROJECT_5_URL}) (`{item_id}`)"
    assert row["cells"][-1] == expected, (
        f"Matrix row M{number} must render its Project #5 cell as {expected!r}"
    )


@pytest.mark.parametrize(("number", "row"), _TASK_MATRIX_ROW_CASES)
def test_task_matrix_spec_links_resolve(
    number: int, row: dict[str, Any]
) -> None:
    spec = row["spec"]
    if spec.strip() == _INLINE_SPEC_MARKER:
        assert number in _TASK_SECTIONS, (
            f"Matrix row M{number} uses 'Inline below' without a matching "
            f"'### M{number}:' section"
        )
        return
    match = _LINK_RE.search(spec)
    assert match is not None, (
        f"Matrix row M{number} spec {spec!r} is neither a link nor 'Inline below'"
    )
    target = match.group("target").strip().split()[0].strip("\"'")
    assert not target.startswith(("http://", "https://", "mailto:", "#")), (
        f"Matrix row M{number} spec must resolve to a repository file, "
        f"got {target!r}"
    )
    resolved = (TASK_BOARD_PATH.parent / target).resolve()
    assert resolved.is_file(), (
        f"Matrix row M{number} spec link {target!r} does not resolve to a file"
    )
    tasks_dir = (TASK_BOARD_PATH.parent / "docs" / "tasks").resolve()
    assert tasks_dir in resolved.parents and resolved.suffix == ".md", (
        f"Matrix row M{number} spec link {target!r} must target docs/tasks/*.md"
    )


@pytest.mark.parametrize(("number", "section"), _TASK_SECTION_CASES)
def test_detailed_sections_carry_project_item_ids(
    number: int, section: str
) -> None:
    item_id = _single_project_item_id(section, f"Detailed section M{number}")
    assert _PROJECT_ITEM_ID_RE.fullmatch(item_id), (
        f"Detailed section M{number} item id {item_id!r} is malformed"
    )


def test_matrix_and_detailed_sections_are_in_sync() -> None:
    assert set(_TASK_MATRIX_ROWS) == set(_TASK_SECTIONS), (
        "Task Matrix rows and detailed M<n> sections must cover the same tasks"
    )
    for number in sorted(_TASK_MATRIX_ROWS):
        matrix_id = _single_project_item_id(
            _TASK_MATRIX_ROWS[number]["line"], f"Matrix row M{number}"
        )
        section_id = _single_project_item_id(
            _TASK_SECTIONS[number], f"Detailed section M{number}"
        )
        assert matrix_id == section_id, (
            f"Detailed section M{number} must state the matrix item id "
            f"{matrix_id!r}, found {section_id!r}"
        )


def test_project_item_ids_are_unique() -> None:
    matrix_ids: list[str] = [
        _single_project_item_id(row["line"], f"Matrix row M{number}")
        for number, row in sorted(_TASK_MATRIX_ROWS.items())
    ]
    assert len(matrix_ids) == len(set(matrix_ids)), (
        "Task Matrix rows must not repeat a PVTI_... item id"
    )

    section_ids: list[str] = [
        _single_project_item_id(section, f"Detailed section M{number}")
        for number, section in sorted(_TASK_SECTIONS.items())
    ]
    assert len(section_ids) == len(set(section_ids)), (
        "Detailed sections must not repeat a PVTI_... item id"
    )


_PORTAL_PAGES = (
    "docs/index.md",
    "docs/getting-started/installation.md",
    "docs/getting-started/quickstart.md",
    "docs/cli/reference.md",
    "docs/rules/catalog.md",
    "docs/guards/sql-security-guard.md",
    "docs/mcp/server-and-ides.md",
    "docs/extensibility.md",
    "docs/roadmap/index.md",
    "docs/changelog/tasks.md",
)
_PORTAL_MIN_LINES = 180
_MKDOCS_PATH = REPO_ROOT / "mkdocs.yml"
_PORTAL_BUILDER_PATH = REPO_ROOT / "scripts" / "build_docs_portal.py"
_PAGES_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "pages.yml"
_M38_SPEC_PATH = (
    REPO_ROOT / "docs" / "tasks" / "M38_web_documentation_portal_and_task_publisher.md"
)


def test_web_documentation_portal_structure() -> None:
    """AC-38.1: MkDocs config and all 10 portal pages exist with >= 180 lines."""
    assert _MKDOCS_PATH.is_file(), "mkdocs.yml must exist"
    mkdocs_text = _MKDOCS_PATH.read_text(encoding="utf-8")
    assert "name: material" in mkdocs_text
    assert "docs_dir: docs" in mkdocs_text

    for rel_path in _PORTAL_PAGES:
        page = REPO_ROOT / rel_path
        assert page.is_file(), f"Missing portal page: {rel_path}"
        lines = page.read_text(encoding="utf-8").splitlines()
        assert len(lines) >= _PORTAL_MIN_LINES, (
            f"{rel_path} has {len(lines)} lines; expected >= {_PORTAL_MIN_LINES}"
        )
        nav_rel = rel_path.removeprefix("docs/")
        assert nav_rel in mkdocs_text, f"mkdocs.yml nav must reference {nav_rel}"


@pytest.mark.parametrize("rel_path", _PORTAL_PAGES)
def test_portal_page_meets_minimum_depth(rel_path: str) -> None:
    """Every customer portal page must have at least 180 lines of documentation."""
    page = REPO_ROOT / rel_path
    assert page.is_file(), f"Missing portal page: {rel_path}"
    line_count = len(page.read_text(encoding="utf-8").splitlines())
    assert line_count >= _PORTAL_MIN_LINES, (
        f"{rel_path} must be >= {_PORTAL_MIN_LINES} lines (got {line_count})"
    )


def test_rule_catalog_parity() -> None:
    """AC-38.4: All 13 static and 9 AST rules appear with CWE & remediation in catalog."""
    catalog = (REPO_ROOT / "docs" / "rules" / "catalog.md").read_text(encoding="utf-8")
    for rule_id in (*STATIC_RULE_IDS, *AST_RULE_IDS):
        assert rule_id in catalog, f"{rule_id} missing from docs/rules/catalog.md"
    quickstart = (REPO_ROOT / "docs" / "getting-started" / "quickstart.md").read_text(
        encoding="utf-8"
    )
    assert "verity scan" in quickstart
    assert "verity test --demo" in quickstart
    for cwe in DEMO_CWES:
        assert cwe in quickstart, f"{cwe} missing from docs/getting-started/quickstart.md"


def test_task_spec_and_board_parity() -> None:
    """AC-38.3: M38 task spec and Project Board #5 item stay synced via portal generator."""
    assert _M38_SPEC_PATH.is_file(), "M38 task spec must exist"
    spec_text = _M38_SPEC_PATH.read_text(encoding="utf-8")
    assert "PVTI_lAHOD-xmQM4Br351zhLOM2U" in spec_text
    assert 38 in _TASK_MATRIX_ROWS
    assert 38 in _TASK_SECTIONS
    assert _PAGES_WORKFLOW_PATH.is_file(), ".github/workflows/pages.yml must exist"
    pages_text = _PAGES_WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "actions/checkout@v5" in pages_text
    assert "astral-sh/setup-uv@v6" in pages_text
    assert "mike deploy" in pages_text
    assert "mike set-default" in pages_text
    assert "lycheeverse/lychee-action" in pages_text


def test_portal_generator_check_passes_with_zero_drift() -> None:
    """Verify scripts/build_docs_portal.py --check exits 0 with zero drift."""
    proc = subprocess.run(
        [sys.executable, str(_PORTAL_BUILDER_PATH), "--check"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"--check failed:\n{proc.stdout}\n{proc.stderr}"


def test_benign_control_docs() -> None:
    """AC-38.5: Customer guides have zero stale package names and benign snippets scan clean."""
    from verity.scanner.static_rules import StaticRuleEvaluator

    customer_guides = [
        p
        for p in _PORTAL_PAGES
        if p not in ("docs/roadmap/index.md", "docs/changelog/tasks.md")
    ]
    offenders: list[str] = []
    for rel_path in customer_guides:
        text = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
        if _STALE_PACKAGE_RE.search(text):
            offenders.append(rel_path)
    assert not offenders, f"Stale verity-core reference in customer guides: {offenders}"

    benign_config = '{"mcpServers": {"notes": {"command": "uvx", "args": ["verity-redteam-core", "serve"], "env": {"API_KEY": "${YOUR_API_KEY}"}}}}'
    matches = StaticRuleEvaluator().scan_text(
        benign_config, target_type="config", target_name="benign", field_path="mcp.json"
    )
    assert matches == [], f"Benign control snippet triggered unexpected matches: {matches}"
