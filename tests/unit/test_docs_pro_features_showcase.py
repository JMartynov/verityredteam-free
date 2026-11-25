"""Tests for the dedicated Verity Pro Enterprise Features showcase in Free docs."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PRO_DOC_PATH = REPO_ROOT / "docs" / "pro" / "enterprise_features.md"
INDEX_PATH = REPO_ROOT / "docs" / "index.md"
MKDOCS_PATH = REPO_ROOT / "mkdocs.yml"

_REQUIRED_H2 = (
    "Overview",
    "Free vs. Pro Feature Comparison",
    "Database Guards",
    "Compliance & SARIF Reporting",
    "Agent-Native MCP Server Actions",
    "Remediation",
    "Adversarial Verification & Red-Teaming",
    "Graceful Degradation (PRO_FEATURE_REQUIRED)",
)

_REQUIRED_DOMAINS = (
    "Database AST Guarding",
    "Reporting & CI/CD Formats",
    "Agent-Native MCP Server (verity serve)",
    "Adversarial Verification & Red-Teaming",
)

_FEATURE_SUBSECTIONS = (
    "SnowflakeSecurityGuard",
    "FilterSecurityGuard",
    "VolumePolicyGuard",
    "OASIS SARIF v2.1.0 & Compliance Bundles",
    "Pro verity_remediation_ops",
    "Multi-Turn Socratic Red-Teaming",
)

_FENCE_RE = re.compile(
    r"(?P<fence>```|~~~)(?P<lang>[A-Za-z0-9_+-]*)\r?\n(?P<body>.*?)(?P=fence)",
    re.DOTALL,
)
_VENDOR_CLASS_RE = re.compile(
    r"^\s*class\s+(SnowflakeSecurityGuard|FilterSecurityGuard|VolumePolicyGuard)\b",
    re.MULTILINE,
)


def _read_pro_doc() -> str:
    return PRO_DOC_PATH.read_text(encoding="utf-8")


def _fenced_blocks(text: str) -> list[tuple[str, str]]:
    return [
        ((m.group("lang") or "").lower(), m.group("body"))
        for m in _FENCE_RE.finditer(text)
    ]


def _slice_heading(text: str, level_prefix: str, title: str) -> str:
    pattern = re.compile(
        rf"^{re.escape(level_prefix)}\s+{re.escape(title)}\s*$",
        re.MULTILINE,
    )
    match = pattern.search(text)
    if match is None:
        raise AssertionError(f"Missing heading {level_prefix} {title!r}")
    level = len(level_prefix)
    next_heading = re.compile(rf"^#{{1,{level}}}\s+", re.MULTILINE)
    nxt = next_heading.search(text, match.end())
    end = nxt.start() if nxt is not None else len(text)
    return text[match.start() : end]


def test_page_structure_and_nav() -> None:
    """AC-107.1: Pro showcase page has exact H1, ordered H2s, homepage link, and mkdocs nav."""
    assert PRO_DOC_PATH.is_file(), "docs/pro/enterprise_features.md must exist"
    text = _read_pro_doc()
    h1_matches = re.findall(r"^#\s+(.+)$", text, re.MULTILINE)
    assert h1_matches and h1_matches[0].strip() == "Verity Pro Enterprise Features"

    h2_headings = [m.strip() for m in re.findall(r"^##\s+(.+)$", text, re.MULTILINE)]
    positions = []
    for req in _REQUIRED_H2:
        assert req in h2_headings, f"Missing required H2 heading: {req!r}"
        positions.append(h2_headings.index(req))
    assert positions == sorted(positions), f"H2 headings out of order: {h2_headings}"

    index_text = INDEX_PATH.read_text(encoding="utf-8")
    pro_links = re.findall(r"\[[^\]]+\]\(([^)]*pro/enterprise_features\.md[^)]*)\)", index_text)
    assert len(pro_links) == 1
    assert index_text.index("## Tier 2") < index_text.index("pro/enterprise_features.md")

    mkdocs_text = MKDOCS_PATH.read_text(encoding="utf-8")
    assert "Verity Pro:" in mkdocs_text
    assert "pro/enterprise_features.md" in mkdocs_text


def test_free_vs_pro_matrix() -> None:
    """AC-107.2: Free-vs-Pro comparison matrix covers all 4 domains with [Pro] badges."""
    text = _read_pro_doc()
    section = _slice_heading(text, "##", "Free vs. Pro Feature Comparison")
    header = "| Capability Domain | Verity RedTeam Free (Apache-2.0) | Verity RedTeam Pro (Commercial) |"
    assert header in section

    for domain in _REQUIRED_DOMAINS:
        row_matches = [
            line for line in section.splitlines()
            if line.strip().startswith("|") and domain in line
        ]
        assert len(row_matches) == 1, f"Expected 1 matrix row for {domain!r}"
        cells = [c.strip() for c in row_matches[0].strip().strip("|").split("|")]
        assert len(cells) == 3
        assert cells[0].strip("*` ") == domain
        assert cells[1], f"Free cell must be non-empty for {domain!r}"
        assert "[Pro]" in cells[2], f"Pro cell must contain [Pro] for {domain!r}"

    assert "PRO_FEATURE_REQUIRED" in section
    assert "exit code 2" in section


@pytest.mark.parametrize("feature", _FEATURE_SUBSECTIONS)
def test_pro_feature_sections(feature: str) -> None:
    """AC-107.3: Each of the 6 Pro feature subsections has python, bash/json, and mermaid blocks."""
    text = _read_pro_doc()
    sub = _slice_heading(text, "###", feature)
    blocks = _fenced_blocks(sub)
    langs = {lang for lang, _ in blocks}
    assert "python" in langs, f"{feature!r} missing fenced python example"
    assert langs & {"bash", "json"}, f"{feature!r} missing fenced bash or json example"
    assert "mermaid" in langs, f"{feature!r} missing fenced mermaid diagram"

    if feature == "OASIS SARIF v2.1.0 & Compliance Bundles":
        assert "verity scan --path . --format sarif --output verity-results.sarif --fail-on-findings" in sub
        assert "PRO_FEATURE_REQUIRED" in sub
    if feature == "Pro verity_remediation_ops":
        for action in (
            "generate_safe_parameterized_query",
            "generate_guard_patch",
            "generate_wrapper_config",
        ):
            assert action in sub


def test_graceful_degradation_documented() -> None:
    """AC-107.4: Graceful degradation contract, exit code 2, and unlock rule documented."""
    text = _read_pro_doc()
    section = _slice_heading(text, "##", "Graceful Degradation (PRO_FEATURE_REQUIRED)")
    assert "PRO_FEATURE_REQUIRED" in section
    assert "exit code 2" in section
    assert '{"error": "PRO_FEATURE_REQUIRED", "feature": "<feature>", "message": "<message>"}' in section
    assert "partial" in section.lower()
    assert "traceback" in section.lower()
    assert "verity-pro" in section
    assert "| Feature | Free behavior | Pro behavior |" in section


def test_no_vendored_pro_implementations() -> None:
    """AC-107.5: Python examples are valid syntax and never define Pro guard classes."""
    text = _read_pro_doc()
    python_blocks = [body for lang, body in _fenced_blocks(text) if lang == "python"]
    assert python_blocks
    for body in python_blocks:
        ast.parse(body)
        assert _VENDOR_CLASS_RE.search(body) is None


def test_pro_vendor_guard_benign_control() -> None:
    """Paired control: usage snippets accepted; Pro guard class definitions rejected."""
    usage = (
        'guard = SnowflakeSecurityGuard(allowed_stages=("@STAGE",))\n'
        "class GuardSnippetBuilder:\n"
        "    pass\n"
    )
    vendored = "class FilterSecurityGuard:\n    pass\n"
    assert _VENDOR_CLASS_RE.search(usage) is None
    assert _VENDOR_CLASS_RE.search(vendored) is not None
