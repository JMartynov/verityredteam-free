"""Locked ATDD tests for M31 / TASK-80 multi-path routing, severity gates, reporting, MCP parity, and M40 SARIF gate."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from verity import cli


def test_scan_multi_path_mixed_types(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """AC-31.4 / AC-80.12: --path a.py b.py cfg.json routes .py and .json/.yaml together."""
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    py_a = repo / "a.py"
    py_a.write_text("def f(x):\n    return eval(x)\n", encoding="utf-8")
    py_b = repo / "b.py"
    py_b.write_text("import os\ndef g():\n    os.system('ls')\n", encoding="utf-8")
    cfg = repo / "cfg.json"
    cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "leaky": {
                        "command": "npx",
                        "args": ["-y", "safe-pkg@1.0.0"],
                        "env": {"API_KEY": "sk-live-multipath-secret-1234567890"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    rc = cli.main(
        [
            "scan",
            "--root",
            str(repo),
            "--path",
            str(py_a),
            str(py_b),
            str(cfg),
            "--offline",
            "--format",
            "json",
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert rc == 0
    rule_ids = {f["rule_id"] for f in report["findings"]}
    assert "VERITY-AST-CWE-94-EVAL" in rule_ids
    assert "VERITY-AST-CWE-78-SYSTEM" in rule_ids
    assert "SEC-STATIC-SECRET-IN-CONFIG" in rule_ids
    assert all(f["fingerprint"].startswith("verity:v1:") for f in report["findings"])

    # Clean benign twin
    clean_py = repo / "clean.py"
    clean_py.write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
    clean_cfg = repo / "clean.json"
    clean_cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "safe": {
                        "command": "npx",
                        "args": ["-y", "safe-pkg@1.0.0"],
                        "env": {"API_KEY": "${API_KEY}"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    rc_clean = cli.main(
        [
            "scan",
            "--root",
            str(repo),
            "--path",
            str(clean_py),
            str(clean_cfg),
            "--offline",
            "--fail-on-severity",
            "INFO",
            "--format",
            "json",
        ]
    )
    clean_report = json.loads(capsys.readouterr().out)
    assert rc_clean == 0
    assert clean_report["findings"] == []


def test_scan_workspace_nested_monorepo_config_discovery(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """AC-31.4 / AC-80.13: --path . discovers nested MCP configs while respecting .verityignore."""
    repo = tmp_path / "monorepo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".verityignore").write_text("ignored_pkg/**\n", encoding="utf-8")

    active_cfg = repo / "packages" / "svc" / ".cursor" / "mcp.json"
    active_cfg.parent.mkdir(parents=True)
    active_cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "active": {
                        "command": "bash",
                        "args": ["-c", "echo ok"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    ignored_cfg = repo / "ignored_pkg" / "mcp.json"
    ignored_cfg.parent.mkdir(parents=True)
    ignored_cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "ignored": {
                        "command": "npx",
                        "args": ["-y", "pkg"],
                        "env": {"SECRET_TOKEN": "sk-ignored-nested-token-1234567890"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    nm_cfg = repo / "node_modules" / "dep" / "mcp.json"
    nm_cfg.parent.mkdir(parents=True)
    nm_cfg.write_text(
        json.dumps({"mcpServers": {"nm": {"command": "sh", "args": ["-c", "id"]}}}),
        encoding="utf-8",
    )

    rc = cli.main(
        [
            "scan",
            "--root",
            str(repo),
            "--path",
            str(repo),
            "--offline",
            "--format",
            "json",
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert rc == 0
    files_in_findings = {f["file_path"] for f in report["findings"]}
    assert "packages/svc/.cursor/mcp.json" in files_in_findings
    assert "ignored_pkg/mcp.json" not in files_in_findings
    assert "node_modules/dep/mcp.json" not in files_in_findings


def test_scan_fail_on_and_fail_on_severity(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """AC-31.4 / AC-80.14: --fail-on-severity / --fail-on threshold & --fail-on-findings alias."""
    repo = _make_repo(tmp_path)
    # Produces MEDIUM (SEC-STATIC-UNSAFE-SHELL-WRAPPER)
    cfg = repo / "mcp.json"
    cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "shell-srv": {
                        "command": "bash",
                        "args": ["-c", "npx -y pinned@1.0.0"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    # MEDIUM finding with --fail-on-severity HIGH -> exit 0
    rc_high = cli.main(
        [
            "scan",
            "--root",
            str(repo),
            "--path",
            str(cfg),
            "--offline",
            "--fail-on-severity",
            "HIGH",
        ]
    )
    capsys.readouterr()
    assert rc_high == 0

    # MEDIUM finding with --fail-on medium (case-insensitive) -> exit 1
    rc_med = cli.main(
        [
            "scan",
            "--root",
            str(repo),
            "--path",
            str(cfg),
            "--offline",
            "--fail-on",
            "medium",
        ]
    )
    capsys.readouterr()
    assert rc_med == 1

    # --fail-on-findings remains INFO alias -> exit 1
    rc_alias = cli.main(
        [
            "scan",
            "--root",
            str(repo),
            "--path",
            str(cfg),
            "--offline",
            "--fail-on-findings",
        ]
    )
    capsys.readouterr()
    assert rc_alias == 1


def test_scan_reports_suppressed_counts_and_show_suppressed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """AC-31.4 / AC-80.15: terminal, JSON, Markdown, HTML surface suppressed_counts & --show-suppressed."""
    repo = _make_repo(tmp_path)
    srv = repo / "server.py"
    srv.write_text(
        "def f(x):\n    return eval(x)  # verity-ignore: VERITY-AST-CWE-94-EVAL -- test fixture\n",
        encoding="utf-8",
    )

    for fmt in ("json", "terminal", "markdown", "html"):
        rc = cli.main(
            [
                "scan",
                "--root",
                str(repo),
                "--path",
                str(srv),
                "--offline",
                "--show-suppressed",
                "--format",
                fmt,
            ]
        )
        out = capsys.readouterr().out
        assert rc == 0
        if fmt == "json":
            data = json.loads(out)
            sc = data["summary"]["suppressed_counts"]
            assert sc["inline"] == 1
            assert sc["total"] >= 1
            assert len(data["suppressed_findings"]) == 1
            assert data["suppressed_findings"][0]["suppression"]["source"] == "inline"
        else:
            assert "Suppressed" in out or "suppressed" in out
            assert "VERITY-AST-CWE-94-EVAL" in out


def test_mcp_security_scan_handler_respects_baseline_and_ignores(
    tmp_path: Path,
) -> None:
    """AC-31.4 / AC-80.16: verity_security_scan supports baseline_path, fail_on_new, respect_ignores."""
    from verity.mcp_server.handlers.legacy import LegacyToolsHandlerMixin
    from verity.mcp_server.handlers.security_scan import SecurityScanHandlerMixin
    from verity.mcp_server.schemas import UNIFIED_TOOL_DEFINITIONS

    scan_schema = next(
        d for d in UNIFIED_TOOL_DEFINITIONS if d["name"] == "verity_security_scan"
    )
    opt_props = scan_schema["inputSchema"]["properties"]["options"]["properties"]
    assert "baseline_path" in opt_props
    assert "fail_on_new" in opt_props
    assert "respect_ignores" in opt_props

    class _Handler(SecurityScanHandlerMixin, LegacyToolsHandlerMixin):
        pass

    handler = _Handler()
    repo = _make_repo(tmp_path)
    srv = repo / "app.py"
    srv.write_text(
        "import os\n"
        "def a(x):\n"
        "    return eval(x)\n"
        "def b():\n"
        "    os.system('ls')  # verity-ignore: VERITY-AST-CWE-78-SYSTEM -- accepted\n",
        encoding="utf-8",
    )

    # First scan with respect_ignores=True -> only eval() active, os.system suppressed
    res1 = handler._execute_security_scan(
        {
            "action": "scan_ast_code",
            "options": {"path": str(repo), "respect_ignores": True},
        }
    )
    assert res1["ok"] is True
    assert len(res1["findings"]) == 1
    assert res1["findings"][0]["rule_id"] == "VERITY-AST-CWE-94-EVAL"
    assert res1["findings"][0]["fingerprint"].startswith("verity:v1:")
    assert res1["summary"]["suppressed_counts"]["inline"] == 1

    # Save baseline via CLI, then scan via MCP with baseline_path & fail_on_new=True
    baseline = repo / ".verity-baseline.json"
    assert (
        cli.main(
            [
                "scan",
                "--root",
                str(repo),
                "--path",
                str(repo),
                "--offline",
                "--save-baseline",
                str(baseline),
            ]
        )
        == 0
    )

    res2 = handler._execute_security_scan(
        {
            "action": "scan_ast_code",
            "options": {
                "path": str(repo),
                "baseline_path": str(baseline),
                "fail_on_new": True,
                "respect_ignores": True,
            },
        }
    )
    assert res2["ok"] is True
    assert res2["new_findings"] == 0
    assert res2["baseline_findings"] == 1
    assert res2["gate_passed"] is True


def test_scan_sarif_still_pro_gated_per_m40(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """AC-31.4: --format sarif remains Pro-gated (exit 2) per M40; Pro _stdlib_sarif_exporter emits partialFingerprints."""
    monkeypatch.setattr(cli, "_pro_plugin_available", lambda: False)
    out_file = tmp_path / "blocked.sarif"
    rc = cli.main(["scan", "--format", "sarif", "--output", str(out_file)])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 2
    assert payload["error"] == "PRO_FEATURE_REQUIRED"
    assert not out_file.exists()

    sarif = cli._stdlib_sarif_exporter(
        {
            "findings": [
                {
                    "rule_id": "VERITY-AST-CWE-94-EVAL",
                    "severity": "CRITICAL",
                    "title": "Eval",
                    "message": "Unsafe eval",
                    "file_path": "src/server.py",
                    "line_number": 5,
                    "fingerprint": "verity:v1:0123456789abcdef_0",
                    "suppression": {
                        "kind": "inSource",
                        "source": "inline",
                        "reason": "test justification",
                    },
                }
            ]
        }
    )
    res0: dict[str, Any] = sarif["runs"][0]["results"][0]
    assert res0["partialFingerprints"]["verity/v1"] == "verity:v1:0123456789abcdef_0"
    assert res0["suppressions"][0]["kind"] == "inSource"
    assert res0["suppressions"][0]["justification"] == "test justification"


def _make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    return repo
