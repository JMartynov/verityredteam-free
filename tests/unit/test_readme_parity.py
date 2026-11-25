"""README parity tests enforcing Tier 1/2 focus, Pro showcase, and registry parity."""

from __future__ import annotations

import re
from pathlib import Path

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
_VENDOR_PRO_CLASS_RE = re.compile(
    r"^\s*class\s+(SnowflakeSecurityGuard|FilterSecurityGuard|VolumePolicyGuard)\b",
    re.MULTILINE,
)

_MATRIX_HEADER = (
    "| Capability Domain | Verity RedTeam Free (Apache-2.0) | Verity RedTeam Pro (Commercial) |"
)
_REQUIRED_DOMAINS = (
    "Database AST Guarding",
    "Reporting & CI/CD Formats",
    "Agent-Native MCP Server (verity serve)",
    "Adversarial Verification & Red-Teaming",
)
_PRO_FEATURE_H3S = (
    "SnowflakeSecurityGuard",
    "FilterSecurityGuard",
    "VolumePolicyGuard",
    "OASIS SARIF v2.1.0 & Compliance Bundles",
    "Pro verity_remediation_ops",
    "Multi-Turn Socratic Red-Teaming",
)


def _read_readme(rel_path: str) -> str:
    return (REPO_ROOT / rel_path).read_text(encoding="utf-8")


def _slice_section(text: str, heading: str) -> str:
    pattern = re.compile(rf"^{re.escape(heading)}\s*$", re.MULTILINE)
    match = pattern.search(text)
    if match is None:
        raise AssertionError(f"Missing required heading: {heading!r}")
    level = len(heading) - len(heading.lstrip("#"))
    next_heading = re.compile(rf"^#{{1,{level}}}\s+", re.MULTILINE)
    nxt = next_heading.search(text, match.end())
    end = nxt.start() if nxt is not None else len(text)
    return text[match.start() : end]


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


def _fenced_blocks(text: str) -> list[tuple[str, str]]:
    return [
        ((m.group("lang") or "").lower(), m.group("body"))
        for m in _FENCE_RE.finditer(text)
    ]


def _vendored_pro_class_pattern() -> re.Pattern[str]:
    return _VENDOR_PRO_CLASS_RE


def _pro_before_internal_qa(text: str) -> bool:
    pro_h2 = "## Verity Pro Enterprise Features"
    qa_h2 = "## Internal QA & Regression Benchmark Harness (Tier 3/4 Reference)"
    if pro_h2 not in text or qa_h2 not in text:
        return False
    return text.index(pro_h2) < text.index(qa_h2)


def _count_table_data_rows(section_text: str) -> int:
    rows = [
        line.strip()
        for line in section_text.splitlines()
        if line.strip().startswith("|") and line.strip().endswith("|")
    ]
    data_rows = [r for r in rows if not re.fullmatch(r"\|[\s:\-|]+\|", r)]
    return max(0, len(data_rows) - 1) if data_rows else 0


def test_readme_tier1_tier2_focus() -> None:
    """AC-110.1: Free README has 12 Tier 1 rows, 13 Tier 2 rows, no Tier 3/4, one aux link."""
    text = _read_readme("README.md")
    tier1 = _slice_section(text, "## Tier 1 — Must-Have Product Core")
    tier2 = _slice_section(text, "## Tier 2 — High Customer Need")

    assert _count_table_data_rows(tier1) == 12
    assert _count_table_data_rows(tier2) == 13
    assert re.search(r"^##\s+Tier\s+[34]\b", text, re.MULTILINE) is None

    aux_links = re.findall(
        r"\[[^\]]*\]\(([^)]*docs/reference/auxiliary_and_benchmarks\.md[^)]*)\)",
        text,
    )
    assert len(aux_links) == 1
    assert "[Auxiliary & Benchmark Appendix (Tier 3/4)](docs/reference/auxiliary_and_benchmarks.md)" in text
    assert text.index("## Tier 2 — High Customer Need") < text.index(
        "docs/reference/auxiliary_and_benchmarks.md"
    )


def test_readme_rule_id_parity() -> None:
    """AC-110.2: Every README rule ID resolves in STATIC_RULE_IDS | AST_RULE_IDS."""
    assert len(STATIC_RULE_IDS) == 13
    assert len(AST_RULE_IDS) == 9
    union = STATIC_RULE_IDS | AST_RULE_IDS

    extracted = _extract_rule_ids(_read_readme("README.md"))
    assert extracted, "README must contain live VERITY rule IDs"
    assert extracted <= union, f"Unknown README rule IDs: {sorted(extracted - union)}"


def test_rule_id_resolver_benign_control() -> None:
    """Paired control: synthetic VERITY-STATIC-0000 rejected; real ID resolves."""
    union = STATIC_RULE_IDS | AST_RULE_IDS
    assert "VERITY-STATIC-0000" not in union
    assert next(iter(STATIC_RULE_IDS)) in union


def test_readme_target_slug_parity() -> None:
    """AC-110.3: Every README demo target slug resolves in TARGET_SLUGS."""
    text = _read_readme("README.md")
    assert "postgres-multitenant" not in text
    slugs = _extract_demo_slugs(text)
    assert slugs, "README must include fenced demo target commands"
    assert slugs <= TARGET_SLUGS, f"Unknown README demo slugs: {sorted(slugs - TARGET_SLUGS)}"
    assert "postgres-basic" in slugs


def test_target_slug_benign_control() -> None:
    """Paired control: postgres-basic in TARGET_SLUGS; postgres-multitenant absent."""
    assert "postgres-basic" in TARGET_SLUGS
    assert "postgres-multitenant" not in TARGET_SLUGS


def test_readme_mcp_tool_names_parity() -> None:
    """AC-110.4: Only the four canonical MCP_TOOL_NAMES appear as verity_* tokens in README."""
    tokens = _extract_mcp_tool_tokens(_read_readme("README.md"))
    assert tokens, "README must document MCP tool names"
    assert tokens <= MCP_TOOL_NAMES, f"Unknown verity_* tokens: {sorted(tokens - MCP_TOOL_NAMES)}"
    assert tokens == MCP_TOOL_NAMES


def test_mcp_tool_benign_control() -> None:
    """Paired control: verity_unknown_tool absent from MCP_TOOL_NAMES."""
    assert "verity_unknown_tool" not in MCP_TOOL_NAMES


def test_readme_sarif_pro_badge() -> None:
    """AC-110.5: --format sarif has [Pro] badge and PRO_FEATURE_REQUIRED / exit code 2 note."""
    text = _read_readme("README.md")
    idx = text.find("--format sarif")
    assert idx != -1, "README must document --format sarif"
    line_start = text.rfind("\n", 0, idx) + 1
    line_end = text.find("\n", idx)
    if line_end == -1:
        line_end = len(text)
    sarif_line = text[line_start:line_end]
    window = text[idx : idx + 200]
    assert "[Pro]" in sarif_line or "[Pro]" in window

    # Locate the enclosing section for PRO_FEATURE_REQUIRED and exit code 2
    section_start = text.rfind("\n## ", 0, idx)
    section_end = text.find("\n## ", idx)
    section = text[max(0, section_start) : len(text) if section_end == -1 else section_end]
    assert "PRO_FEATURE_REQUIRED" in section
    assert "exit code 2" in section

    for fmt in ("terminal", "json", "markdown", "html"):
        for line in text.splitlines():
            if f"--format {fmt}" in line:
                assert "[Pro]" not in line, f"Free format {fmt!r} must not carry [Pro]: {line!r}"


def test_readme_pro_section_matrix_and_link() -> None:
    """AC-110.6: README Pro section has 4-domain matrix with [Pro] and docs/pro link."""
    text = _read_readme("README.md")
    section = _slice_section(text, "## Verity Pro Enterprise Features")
    assert _MATRIX_HEADER in section

    for domain in _REQUIRED_DOMAINS:
        rows = [
            line for line in section.splitlines()
            if line.strip().startswith("|") and domain in line
        ]
        assert len(rows) == 1, f"Expected 1 matrix row for {domain!r}"
        cells = [c.strip() for c in rows[0].strip().strip("|").split("|")]
        assert len(cells) == 3
        assert "[Pro]" in cells[2], f"Pro cell missing [Pro] for {domain!r}"

    assert re.search(r"\[[^\]]+\]\([^)]*pro/enterprise_features\.md\)", section) is not None
    assert text.index("## Tier 2 — High Customer Need") < text.index("## Verity Pro Enterprise Features")
    assert text.index("## Verity Pro Enterprise Features") < text.index(
        "docs/reference/auxiliary_and_benchmarks.md"
    )


def test_readme_pro_feature_subsections() -> None:
    """AC-110.7: Each of 6 Pro feature H3s has python, bash/json, mermaid blocks and no class defs."""
    text = _read_readme("README.md")
    for h3 in _PRO_FEATURE_H3S:
        sub = _slice_section(text, f"### {h3}")
        blocks = _fenced_blocks(sub)
        langs = {lang for lang, _ in blocks}
        assert "python" in langs, f"{h3!r} missing python fenced block"
        assert langs & {"bash", "json"}, f"{h3!r} missing bash/json fenced block"
        assert "mermaid" in langs, f"{h3!r} missing mermaid fenced block"
        for lang, body in blocks:
            if lang == "python":
                assert _vendored_pro_class_pattern().search(body) is None


def test_pro_vendor_guard_benign_control() -> None:
    """Paired control: usage accepted; Pro guard class definition rejected."""
    usage = (
        'guard = SnowflakeSecurityGuard(allowed_stages=("@STAGE",))\n'
        "class GuardSnippetBuilder:\n"
        "    pass\n"
    )
    vendored = "class FilterSecurityGuard:\n    pass\n"
    assert _vendored_pro_class_pattern().search(usage) is None
    assert _vendored_pro_class_pattern().search(vendored) is not None
