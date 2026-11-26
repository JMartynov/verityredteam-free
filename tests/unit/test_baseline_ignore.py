"""Locked ATDD tests for M31 / TASK-80 .verityignore, verity.toml, and inline suppressions."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from verity.baseline.ignore import (
    PolicyValidationError,
    apply_policy_suppressions,
    load_ignore_spec,
    load_policy_config,
)
from verity.baseline.inline import apply_inline_suppressions, parse_inline_suppressions


def test_verityignore_include_cycle_and_negation(tmp_path: Path) -> None:
    """AC-31.2 / AC-80.5: :include .gitignore with cycle protection & ! negation last-match-wins."""
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "docs").mkdir()
    (repo / "build_out").mkdir()
    (repo / "src").mkdir()

    # Cycle between .gitignore and .extraignore
    (repo / ".gitignore").write_text(
        "*.log\nbuild_out/\n:include .extraignore\n",
        encoding="utf-8",
    )
    (repo / ".extraignore").write_text(
        ":include .gitignore\ntemp_*.py\n",
        encoding="utf-8",
    )
    (repo / ".verityignore").write_text(
        ":include .gitignore\n"
        "docs/**\n"
        "!docs/keep.py\n",
        encoding="utf-8",
    )

    spec = load_ignore_spec(repo)
    assert spec.is_ignored(repo / "app.log") is True
    assert spec.is_ignored(repo / "build_out" / "server.py") is True
    assert spec.is_ignored(repo / "temp_scratch.py") is True
    assert spec.is_ignored(repo / "docs" / "drop.py") is True
    # Last-match-wins negation re-includes docs/keep.py
    assert spec.is_ignored(repo / "docs" / "keep.py") is False
    # Default ignored directories are excluded unless --no-default-ignores
    assert spec.is_ignored(repo / "node_modules" / "pkg" / "index.py") is True
    assert spec.is_ignored(repo / ".venv" / "lib.py") is True
    assert spec.is_ignored(repo / "src" / "server.py") is False

    # --no-default-ignores disables built-ins and auto-loaded .verityignore
    no_def = load_ignore_spec(repo, use_default_ignores=False)
    assert no_def.is_ignored(repo / "node_modules" / "pkg" / "index.py") is False
    assert no_def.is_ignored(repo / "docs" / "drop.py") is False


def test_verity_toml_ignore_expiry_and_osv_alias(tmp_path: Path) -> None:
    """AC-31.2 / AC-80.6: unexpired [[ignore]] suppresses OSV/CVE alias; expired warns & stays active."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "verity.toml").write_text(
        """
[scan]
fail_on = "HIGH"
fail_on_new = true

[[ignore]]
id = "CVE-2025-6514"
paths = ["configs/**"]
servers = ["remote-mcp"]
reason = "Mitigated by network egress proxy"
expires = "2099-12-31"

[[ignore]]
id = "VERITY-AST-CWE-94-EVAL"
paths = ["legacy/*.py"]
reason = "Temporary migration window"
expires = "2020-01-01"
""",
        encoding="utf-8",
    )

    policy = load_policy_config(repo, today=date(2026, 6, 1))
    assert policy.scan.get("fail_on") == "HIGH"
    assert policy.scan.get("fail_on_new") is True
    assert len(policy.expired_warnings) == 1
    assert "VERITY-AST-CWE-94-EVAL" in policy.expired_warnings[0]

    findings = [
        {
            "rule_id": "VULN-GHSA-1234-5678",
            "cve_id": "CVE-2025-6514",
            "aliases": ["CVE-2025-6514"],
            "file_path": "configs/mcp.json",
            "server_name": "remote-mcp",
            "fingerprint": "verity:v1:aaaaaaaaaaaaaaaa_0",
        },
        {
            # Non-matching path glob should NOT be suppressed (benign control)
            "rule_id": "VULN-GHSA-1234-5678",
            "cve_id": "CVE-2025-6514",
            "aliases": ["CVE-2025-6514"],
            "file_path": "prod/mcp.json",
            "server_name": "remote-mcp",
            "fingerprint": "verity:v1:bbbbbbbbbbbbbbbb_0",
        },
        {
            # Expired rule must NOT suppress
            "rule_id": "VERITY-AST-CWE-94-EVAL",
            "file_path": "legacy/old.py",
            "fingerprint": "verity:v1:cccccccccccccccc_0",
        },
    ]

    apply_policy_suppressions(findings, policy)
    assert findings[0]["suppression"]["source"] == "policy"
    assert findings[0]["suppression"]["kind"] == "external"
    assert "egress proxy" in findings[0]["suppression"]["reason"]
    assert "suppression" not in findings[1]
    assert "suppression" not in findings[2]


def test_verity_toml_allowlists_and_strict_policy(tmp_path: Path) -> None:
    """AC-31.2 / AC-80.7: [[allowlists]] stopwords/regexes & --strict-policy missing reason guard."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "verity.toml").write_text(
        """
[[allowlists]]
description = "Safe arithmetic formula fixtures"
paths = ["src/math_*.py"]
stopwords = ["SUM(column_a)"]
regexes = ['\\*\\s*1\\.15$']
regex_target = "match"
""",
        encoding="utf-8",
    )
    policy = load_policy_config(repo)

    benign_twin = {
        "rule_id": "VERITY-AST-CWE-94-EVAL",
        "file_path": "src/math_calc.py",
        "snippet": 'eval("SUM(column_a) * 1.15")',
        "message": "SUM(column_a) * 1.15",
    }
    malicious_twin = {
        "rule_id": "VERITY-AST-CWE-94-EVAL",
        "file_path": "src/server.py",
        "snippet": 'eval(user_payload)',
        "message": "eval(user_payload)",
    }

    findings = [benign_twin, malicious_twin]
    apply_policy_suppressions(findings, policy)
    assert benign_twin["suppression"]["source"] == "policy"
    assert "suppression" not in malicious_twin

    # --strict-policy rejects empty reason in [[ignore]] or empty description in [[allowlists]]
    bad_toml = tmp_path / "bad_policy.toml"
    bad_toml.write_text(
        """
[[ignore]]
id = "VERITY-AST-CWE-94-EVAL"
reason = "   "
""",
        encoding="utf-8",
    )
    with pytest.raises(PolicyValidationError):
        load_policy_config(repo, config_path=bad_toml, strict_policy=True)


def test_inline_ignore_directives_and_no_inline_ignores() -> None:
    """AC-31.2 / AC-80.8: # verity-ignore / # nosemgrep same/preceding line & --no-inline-ignores."""
    source = "\n".join(
        [
            "import os, subprocess, yaml",
            "# verity-ignore: VERITY-AST-CWE-78-SYSTEM -- validated allowlist binary",
            "os.system('ls')",
            "subprocess.run(cmd, shell=True)  # verity-ignore: CWE-78 -- static internal arg",
            "# nosemgrep: VERITY-AST-CWE-502-YAML",
            "yaml.load(data)",
            "eval(expr)  # verity-ignore",
            "eval(other_expr)  # noqa: E501",
            'read_workspace_file("docs/README.md")',
        ]
    )

    directives = parse_inline_suppressions(source)
    assert 2 in directives
    assert 4 in directives
    assert 5 in directives
    assert 7 in directives
    # Standard linter directives must NOT be parsed as verity-ignore
    assert 8 not in directives

    base_findings = [
        {
            "rule_id": "VERITY-AST-CWE-78-SYSTEM",
            "cwe_id": "CWE-78",
            "file_path": "src/app.py",
            "line_number": 3,
        },
        {
            "rule_id": "VERITY-AST-CWE-78-SHELL",
            "cwe_id": "CWE-78",
            "file_path": "src/app.py",
            "line_number": 4,
        },
        {
            "rule_id": "VERITY-AST-CWE-502-YAML",
            "cwe_id": "CWE-502",
            "file_path": "src/app.py",
            "line_number": 6,
        },
        {
            "rule_id": "VERITY-AST-CWE-94-EVAL",
            "cwe_id": "CWE-94",
            "file_path": "src/app.py",
            "line_number": 7,
        },
        {
            "rule_id": "VERITY-AST-CWE-94-EVAL",
            "cwe_id": "CWE-94",
            "file_path": "src/app.py",
            "line_number": 8,
        },
    ]

    # With inline ignores enabled
    f_enabled = [dict(f) for f in base_findings]
    apply_inline_suppressions(f_enabled, {"src/app.py": source}, respect_inline_ignores=True)
    for idx in range(4):
        assert f_enabled[idx]["suppression"]["kind"] == "inSource"
        assert f_enabled[idx]["suppression"]["source"] == "inline"
    assert "suppression" not in f_enabled[4]  # non-verity comment did not suppress

    # With --no-inline-ignores
    f_disabled = [dict(f) for f in base_findings]
    apply_inline_suppressions(f_disabled, {"src/app.py": source}, respect_inline_ignores=False)
    for item in f_disabled:
        assert "suppression" not in item

    # With --strict-policy, blanket '# verity-ignore' without '-- <reason>' fails
    with pytest.raises(PolicyValidationError):
        apply_inline_suppressions(
            [dict(base_findings[3])],
            {"src/app.py": source},
            respect_inline_ignores=True,
            strict_policy=True,
        )
