"""Documentation parity guard enforcing README fidelity to the Verity CLI."""

from __future__ import annotations

import argparse
import re
import shlex
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
