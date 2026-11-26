"""Locked ATDD tests for M31 / TASK-80 path canonicalization and finding fingerprinting."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from verity.baseline.fingerprint import assign_fingerprints, compute_finding_fingerprint
from verity.baseline.paths import canonicalize_path, resolve_project_root
from verity.scanner.engine import McpAstScannerEngine


def test_resolve_project_root_precedence(tmp_path: Path) -> None:
    """AC-31.1 / AC-80.1: explicit --root > .git ancestor > target dir/parent > cwd."""
    git_repo = tmp_path / "repo"
    (git_repo / ".git").mkdir(parents=True)
    nested_dir = git_repo / "services" / "mcp"
    nested_dir.mkdir(parents=True)
    nested_file = nested_dir / "server.py"
    nested_file.write_text("x = 1\n", encoding="utf-8")

    explicit = tmp_path / "explicit_root"
    explicit.mkdir()

    # 1. Explicit root wins over .git
    assert (
        resolve_project_root(target_paths=[nested_file], explicit_root=explicit)
        == explicit.resolve()
    )

    # 2. Enclosing .git ancestor wins over target dir/file parent
    assert resolve_project_root(target_paths=[nested_file]) == git_repo.resolve()

    # 3. Target dir / file parent wins when no .git exists
    no_git = tmp_path / "no_git_proj"
    sub = no_git / "pkg"
    sub.mkdir(parents=True)
    f = sub / "app.py"
    f.write_text("x = 1\n", encoding="utf-8")
    assert resolve_project_root(target_paths=[no_git]) == no_git.resolve()
    assert resolve_project_root(target_paths=[f]) == sub.resolve()

    # 4. Fallback to cwd when no targets and no .git
    plain_cwd = tmp_path / "plain_cwd"
    plain_cwd.mkdir()
    assert resolve_project_root(target_paths=None, cwd=plain_cwd) == plain_cwd.resolve()


def test_paths_normalize_srcroot_and_home(tmp_path: Path) -> None:
    """AC-31.1 / AC-80.1: POSIX repo-relative paths and ~ for workstation configs."""
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    fake_home = tmp_path / "home" / "alice"
    fake_home.mkdir(parents=True)

    nested = repo / "src" / "server.py"
    nested.parent.mkdir(parents=True)
    nested.write_text("pass\n", encoding="utf-8")

    cursor_cfg = fake_home / ".cursor" / "mcp.json"
    cursor_cfg.parent.mkdir(parents=True)
    cursor_cfg.write_text("{}", encoding="utf-8")

    # Repo file -> repo-relative POSIX
    assert canonicalize_path(nested, project_root=repo, home_dir=fake_home) == "src/server.py"
    # Relative with Windows backslashes & leading ./
    assert (
        canonicalize_path(r".\docs\README.md", project_root=repo, home_dir=fake_home)
        == "docs/README.md"
    )
    # Out-of-repo home config -> ~ prefix with no raw machine home path
    home_rel = canonicalize_path(cursor_cfg, project_root=repo, home_dir=fake_home)
    assert home_rel == "~/.cursor/mcp.json"
    assert str(fake_home) not in home_rel


def test_fingerprint_survives_line_shift(tmp_path: Path) -> None:
    """AC-31.1 / AC-80.2: inserting 50 lines above an AST finding preserves fingerprint."""
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    src = repo / "src" / "server.py"
    src.parent.mkdir(parents=True)

    vuln_code = (
        "def run_tool(expr: str):\n"
        "    return eval(expr)\n"
    )
    src.write_text(vuln_code, encoding="utf-8")
    r1 = McpAstScannerEngine().scan_path(src)
    f1 = [f.to_dict() for f in r1.findings]
    assert len(f1) == 1
    assign_fingerprints(f1, project_root=repo)
    fp1 = f1[0]["fingerprint"]
    assert re.fullmatch(r"verity:v1:[0-9a-f]{16}_\d+", fp1)
    assert f1[0]["file_path"] == "src/server.py"

    # Shift down by 50 lines
    padding = "\n".join(f"# comment line {i}" for i in range(50)) + "\n"
    src.write_text(padding + vuln_code, encoding="utf-8")
    r2 = McpAstScannerEngine().scan_path(src)
    f2 = [f.to_dict() for f in r2.findings]
    assert len(f2) == 1
    assign_fingerprints(f2, project_root=repo)
    assert f2[0]["line_number"] == f1[0]["line_number"] + 50
    assert f2[0]["fingerprint"] == fp1

    # Paired benign twin: safe SQL query emits zero AST findings
    benign = repo / "src" / "safe.py"
    benign.write_text(
        'def safe_query(cursor, tenant_id: str):\n'
        '    return cursor.execute("SELECT id, name FROM users WHERE tenant_id = %s", (tenant_id,))\n',
        encoding="utf-8",
    )
    r_benign = McpAstScannerEngine().scan_path(benign)
    assert r_benign.findings == []


def test_fingerprint_occurrence_index_disambiguates_duplicates(tmp_path: Path) -> None:
    """AC-31.1 / AC-80.3: identical findings in one file get _0 and _1 occurrence suffixes."""
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)

    findings = [
        {
            "rule_id": "VERITY-AST-CWE-94-EVAL",
            "file_path": str(repo / "src" / "dup.py"),
            "line_number": 20,
            "mcp_tool_context": "tool_a",
            "snippet": "return eval(expr)",
        },
        {
            "rule_id": "VERITY-AST-CWE-94-EVAL",
            "file_path": str(repo / "src" / "dup.py"),
            "line_number": 10,
            "mcp_tool_context": "tool_a",
            "snippet": "return eval(expr)",
        },
    ]
    assign_fingerprints(findings, project_root=repo)
    fps = [f["fingerprint"] for f in findings]
    # Sorted by line_number (line 10 gets _0, line 20 gets _1)
    assert findings[1]["fingerprint"].endswith("_0")
    assert findings[0]["fingerprint"].endswith("_1")
    assert len(set(fps)) == 2
    assert fps[0].rsplit("_", 1)[0] == fps[1].rsplit("_", 1)[0]


def test_fingerprint_invalidates_on_rotated_secret_without_plaintext(tmp_path: Path) -> None:
    """AC-31.1 / AC-80.4: secret rotation changes fingerprint; zero plaintext stored."""
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    cfg = repo / ".cursor" / "mcp.json"

    secret_v1 = "sk-live-secret-token-alpha-1111111111"
    secret_v2 = "sk-live-secret-token-bravo-2222222222"

    f1 = {
        "rule_id": "SEC-STATIC-SECRET-IN-CONFIG",
        "file_path": str(cfg),
        "server_name": "analytics",
        "env_key": "OPENAI_API_KEY",
        "_raw_secret": secret_v1,
        "message": f"Env variable 'OPENAI_API_KEY' contains unredacted credential ({secret_v1}).",
    }
    f2 = {
        "rule_id": "SEC-STATIC-SECRET-IN-CONFIG",
        "file_path": str(cfg),
        "server_name": "analytics",
        "env_key": "OPENAI_API_KEY",
        "_raw_secret": secret_v2,
        "message": f"Env variable 'OPENAI_API_KEY' contains unredacted credential ({secret_v2}).",
    }
    assign_fingerprints([f1], project_root=repo)
    assign_fingerprints([f2], project_root=repo)

    assert f1["fingerprint"] != f2["fingerprint"]
    assert secret_v1 not in f1["fingerprint"]
    assert secret_v2 not in f2["fingerprint"]

    # Determinism check with identical secret
    f1_dup = dict(f1)
    f1_dup.pop("fingerprint", None)
    assign_fingerprints([f1_dup], project_root=repo)
    assert f1_dup["fingerprint"] == f1["fingerprint"]

    # Benign config value hashes deterministically with zero plaintext leak
    benign = {
        "rule_id": "VERITY-CFG-SECRET-001",
        "file_path": str(cfg),
        "server_name": "safe",
        "env_key": "API_BASE_URL",
        "_raw_secret": "https://example.test",
    }
    fp_benign = compute_finding_fingerprint(benign, project_root=repo)
    assert "example.test" not in fp_benign
    assert len(fp_benign) == 16
    assert hashlib.sha256(b"https://example.test").hexdigest() not in json.dumps(benign)


def test_fingerprint_tool_schema_and_posture_findings(tmp_path: Path) -> None:
    """AC-31.1: tool_schema and cfg_posture findings produce distinct domain fingerprints."""
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)

    schema_a = {
        "rule_id": "VERITY-STATIC-INJECTION-OVERRIDE",
        "file_path": str(repo / "tools.json"),
        "tool_name": "fetch_data",
        "field_path": "description",
        "target_type": "tool",
        "matched_snippet": "IGNORE PREVIOUS INSTRUCTIONS",
    }
    schema_b = {
        "rule_id": "VERITY-STATIC-INJECTION-OVERRIDE",
        "file_path": str(repo / "tools.json"),
        "tool_name": "fetch_data",
        "field_path": "inputSchema.properties.q.description",
        "target_type": "tool",
        "matched_snippet": "IGNORE PREVIOUS INSTRUCTIONS",
    }
    posture = {
        "rule_id": "VULN-CVE-2025-6514",
        "file_path": str(repo / "mcp.json"),
        "server_name": "remote",
        "advisory_id": "CVE-2025-6514",
        "title": "Known Vulnerability: mcp-remote RCE",
    }

    assign_fingerprints([schema_a, schema_b, posture], project_root=repo)
    assert schema_a["fingerprint"] != schema_b["fingerprint"]
    assert posture["fingerprint"].startswith("verity:v1:")
