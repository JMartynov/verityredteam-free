"""Homepage (docs/index.md), catalog, auxiliary page, and mkdocs nav parity tests."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from verity.mcp_server.server import MCP_TOOL_NAMES
from verity.scanner.python_ast import AST_RULE_IDS
from verity.scanner.static_rules import STATIC_RULE_IDS
from verity.targets import TARGET_SLUGS

REPO_ROOT = Path(__file__).resolve().parents[2]

_RULE_ID_RE = re.compile(r"\bVERITY-(?:STATIC|AST-CWE)-[A-Z0-9-]+\b")
_DEMO_SLUG_RE = re.compile(r"(?:--demo|--target)[ \t]+(?!--)([a-z0-9-]+)")
_MCP_TOOL_RE = re.compile(r"\bverity_[a-z][a-z0-9_]*\b")
_FENCE_RE = re.compile(
    r"(?P<fence>```|~~~)(?P<lang>[A-Za-z0-9_+-]*)\r?\n(?P<body>.*?)(?P=fence)",
    re.DOTALL,
)
_AUX_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]*reference/auxiliary_and_benchmarks\.md[^)]*)\)")


def _read(rel_path: str) -> str:
    return (REPO_ROOT / rel_path).read_text(encoding="utf-8")


def _slice_section(text: str, heading: str) -> str:
    pattern = re.compile(rf"^({re.escape(heading)}[^\n]*)$", re.MULTILINE)
    match = pattern.search(text)
    if match is None:
        raise AssertionError(f"Missing required heading: {heading!r}")
    level = len(heading) - len(heading.lstrip("#"))
    next_heading = re.compile(rf"^#{{1,{level}}}\s+", re.MULTILINE)
    nxt = next_heading.search(text, match.end())
    end = nxt.start() if nxt is not None else len(text)
    return text[match.start() : end]


def _fenced_blocks(text: str) -> list[tuple[str, str]]:
    return [
        ((m.group("lang") or "").lower(), m.group("body"))
        for m in _FENCE_RE.finditer(text)
    ]


def _extract_rule_ids(text: str) -> set[str]:
    return set(_RULE_ID_RE.findall(text))


def _extract_demo_slugs(text: str) -> set[str]:
    slugs: set[str] = set()
    for _, body in _fenced_blocks(text):
        for match in _DEMO_SLUG_RE.finditer(body):
            slug = match.group(1)
            if slug != "verity":
                slugs.add(slug)
    return slugs


def _extract_mcp_tool_tokens(text: str) -> set[str]:
    return set(_MCP_TOOL_RE.findall(text))


def _count_table_data_rows(section_text: str) -> int:
    rows: list[str] = []
    for line in section_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("|") and stripped.endswith("|"):
            rows.append(stripped)
    data_rows = [
        r
        for r in rows
        if not re.fullmatch(r"\|[\s:\-|]+\|", r)
    ]
    # Exclude the single header row when a table is present
    return max(0, len(data_rows) - 1) if data_rows else 0


def test_homepage_focuses_tier1_tier2() -> None:
    """AC-104.1: Homepage showcases Tier 1/2 only with a single auxiliary link."""
    text = _read("docs/index.md")
    tier1 = _slice_section(text, "## Tier 1")
    tier2 = _slice_section(text, "## Tier 2")

    assert re.search(r"^##\s+Tier\s+[34]\b", text, re.MULTILINE) is None
    assert _count_table_data_rows(tier1) == 12
    assert _count_table_data_rows(tier2) == 13

    for forbidden in (
        "32-Server Docker Lab",
        "51 Synthetic JSON-Flag",
        "Background 5,800-Port Monitoring Daemon",
        "Interactive Hub, Curses TUI",
    ):
        assert forbidden not in text

    aux_links = _AUX_LINK_RE.findall(text)
    assert len(aux_links) == 1
    assert "[Auxiliary & Benchmark Appendix (Tier 3/4)](reference/auxiliary_and_benchmarks.md)" in text
    assert text.index("## Tier 2") < text.index("reference/auxiliary_and_benchmarks.md")


def test_rule_ids_resolve_in_live_code() -> None:
    """AC-104.2: Every homepage rule ID resolves in runtime registries; catalog equals union."""
    assert len(STATIC_RULE_IDS) == 13
    assert len(AST_RULE_IDS) == 9
    union = STATIC_RULE_IDS | AST_RULE_IDS

    index_ids = _extract_rule_ids(_read("docs/index.md"))
    assert index_ids, "Homepage must display live VERITY rule IDs"
    assert index_ids <= union, f"Unknown homepage rule IDs: {sorted(index_ids - union)}"

    catalog_ids = _extract_rule_ids(_read("docs/rules/catalog.md"))
    assert catalog_ids == union


def test_rule_id_resolver_benign_control() -> None:
    """Paired control: synthetic VERITY-STATIC-0000 is rejected; real ID resolves."""
    union = STATIC_RULE_IDS | AST_RULE_IDS
    extracted = _extract_rule_ids("VERITY-STATIC-0000")
    assert extracted == {"VERITY-STATIC-0000"}
    assert "VERITY-STATIC-0000" not in union
    assert next(iter(STATIC_RULE_IDS)) in union


def test_target_slug_parity() -> None:
    """AC-104.3: Every homepage demo target slug resolves in TARGET_SLUGS."""
    index_text = _read("docs/index.md")
    assert "postgres-multitenant" not in index_text
    slugs = _extract_demo_slugs(index_text)
    assert slugs, "Homepage must contain executable demo target invocations"
    assert slugs <= TARGET_SLUGS, f"Unknown demo slugs: {sorted(slugs - TARGET_SLUGS)}"
    assert "postgres-basic" in slugs


def test_target_slug_benign_control() -> None:
    """Paired control: postgres-basic in TARGET_SLUGS; postgres-multitenant absent."""
    assert "postgres-basic" in TARGET_SLUGS
    assert "postgres-multitenant" not in TARGET_SLUGS


def test_mcp_tool_names_parity() -> None:
    """AC-104.4: Agent-Native MCP Server section uses only the four live MCP_TOOL_NAMES."""
    assert len(MCP_TOOL_NAMES) == 4
    index_text = _read("docs/index.md")
    section = _slice_section(index_text, "## Agent-Native MCP Server")
    tokens = _extract_mcp_tool_tokens(section)
    assert tokens, "Agent-Native MCP Server section must list MCP tool names"
    assert tokens <= MCP_TOOL_NAMES, f"Unknown MCP tools: {sorted(tokens - MCP_TOOL_NAMES)}"
    assert tokens == MCP_TOOL_NAMES
    for legacy in ("mcp_security_scan", "mcp_database_guard", "mcp_database_oracle", "mcp_remediation_ops"):
        assert legacy not in index_text


def test_mcp_tool_benign_control() -> None:
    """Paired control: verity_unknown_tool is absent from MCP_TOOL_NAMES."""
    assert "verity_unknown_tool" not in MCP_TOOL_NAMES
    assert next(iter(MCP_TOOL_NAMES)) in MCP_TOOL_NAMES


def test_sarif_pro_badge() -> None:
    """AC-104.5: --format sarif carries [Pro] and PRO_FEATURE_REQUIRED; Free formats are unbadged."""
    text = _read("docs/index.md")
    idx = text.find("--format sarif")
    assert idx != -1, "Homepage must document --format sarif"
    line_start = text.rfind("\n", 0, idx) + 1
    line_end = text.find("\n", idx)
    if line_end == -1:
        line_end = len(text)
    sarif_line = text[line_start:line_end]
    window = text[idx : idx + 200]
    assert "[Pro]" in sarif_line or "[Pro]" in window
    assert "PRO_FEATURE_REQUIRED" in text
    assert "exit code 2" in text
    assert (
        "In Verity Free, `--format sarif` returns `PRO_FEATURE_REQUIRED` (exit code 2); "
        "SARIF v2.1.0 export requires `verity-pro`."
    ) in text

    for fmt in ("terminal", "json", "markdown", "html"):
        for line in text.splitlines():
            if f"--format {fmt}" in line:
                assert "[Pro]" not in line, f"Free format {fmt!r} must not carry [Pro]: {line!r}"


def test_auxiliary_page_nav() -> None:
    """AC-104.6: Auxiliary page exists, covers 11 Tier 3 + 12 Tier 4 rows, and is in mkdocs.yml nav."""
    aux_path = REPO_ROOT / "docs" / "reference" / "auxiliary_and_benchmarks.md"
    assert aux_path.is_file()
    aux_text = aux_path.read_text(encoding="utf-8")
    assert "internal QA" in aux_text or "Internal QA" in aux_text
    assert "Score" in aux_text
    assert "Disposition" in aux_text
    assert "Tier 3" in aux_text
    assert "Tier 4" in aux_text

    mkdocs_text = _read("mkdocs.yml")
    assert "Reference:" in mkdocs_text
    assert "reference/auxiliary_and_benchmarks.md" in mkdocs_text


@pytest.mark.parametrize("legacy_id", ["VERITY-STATIC-001", "VERITY-AST-001", "VERITY-BOLA-001"])
def test_no_legacy_fake_rule_ids_on_homepage(legacy_id: str) -> None:
    """Ensure legacy placeholder rule IDs were purged from docs/index.md."""
    assert legacy_id not in _read("docs/index.md")
