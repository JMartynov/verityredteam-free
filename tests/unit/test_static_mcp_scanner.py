"""Unit test suite for Static MCP Code & AST Vulnerability Scanner (Task 38)."""

from __future__ import annotations

import tempfile
from pathlib import Path

from verity.scanner import (
    McpAstScannerEngine,
    RuleCatalog,
    ScannerSeverity,
    scan_python_file,
)


def test_rule_catalog_integrity() -> None:
    """Validate that the rule catalog defines unique rules with required properties."""
    rules = RuleCatalog.ALL_RULES
    assert len(rules) >= 6
    rule_ids = [r.rule_id for r in rules]
    assert len(rule_ids) == len(set(rule_ids)), "Rule IDs must be unique"
    for r in rules:
        assert r.cwe_id.startswith("CWE-")
        assert r.severity in ScannerSeverity
        assert len(r.title) > 0
        assert len(r.remediation) > 0


def test_scan_code_injection_eval_detection(tmp_path: Path) -> None:
    """Detect dynamic eval() execution in vulnerable MCP fixture."""
    fixture_path = tmp_path / "server.py"
    fixture_path.write_text(
        'def evaluate_formula(expr: str):\n    return eval(expr)\n', encoding="utf-8"
    )
    findings = scan_python_file(str(fixture_path))
    eval_findings = [f for f in findings if f.rule_id == RuleCatalog.RULE_CWE_94_EVAL.rule_id]
    assert len(eval_findings) >= 1
    f = eval_findings[0]
    assert f.severity == ScannerSeverity.CRITICAL
    assert f.cwe_id == "CWE-94"
    assert "eval" in f.snippet
    assert f.mcp_tool_context == "evaluate_formula"


def test_scan_subprocess_shell_injection() -> None:
    """Detect subprocess invocation with shell=True."""
    code = '''
def tool_run_backup(cmd: str):
    import subprocess
    return subprocess.run(cmd, shell=True, capture_output=True)
'''
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tmp:
        tmp.write(code)
        tmp_path = tmp.name

    try:
        findings = scan_python_file(tmp_path)
        rid = RuleCatalog.RULE_CWE_78_SHELL_TRUE.rule_id
        shell_findings = [f for f in findings if f.rule_id == rid]
        assert len(shell_findings) == 1
        assert shell_findings[0].severity == ScannerSeverity.CRITICAL
        assert shell_findings[0].cwe_id == "CWE-78"
        assert shell_findings[0].mcp_tool_context == "tool_run_backup"
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_scan_os_system_command_injection() -> None:
    """Detect direct os.system() and os.popen() calls."""
    code = '''
import os

def handle_clean(target: str):
    os.system(f"rm -rf {target}")
'''
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tmp:
        tmp.write(code)
        tmp_path = tmp.name

    try:
        findings = scan_python_file(tmp_path)
        rid = RuleCatalog.RULE_CWE_78_OS_SYSTEM.rule_id
        sys_findings = [f for f in findings if f.rule_id == rid]
        assert len(sys_findings) == 1
        assert sys_findings[0].severity == ScannerSeverity.CRITICAL
        assert sys_findings[0].cwe_id == "CWE-78"
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_scan_unsafe_deserialization_detection(tmp_path: Path) -> None:
    """Detect unsafe pickle.loads() in deserialization MCP fixture."""
    fixture_path = tmp_path / "server.py"
    fixture_path.write_text(
        'import pickle\ndef tool_deserialize(data):\n    return pickle.loads(data)\n',
        encoding="utf-8",
    )
    findings = scan_python_file(str(fixture_path))
    pickle_findings = [f for f in findings if f.rule_id == RuleCatalog.RULE_CWE_502_PICKLE.rule_id]
    assert len(pickle_findings) >= 1
    f = pickle_findings[0]
    assert f.severity == ScannerSeverity.CRITICAL
    assert f.cwe_id == "CWE-502"
    assert "pickle.loads" in f.snippet


def test_scan_path_traversal_detection(tmp_path: Path) -> None:
    """Detect unvalidated path traversal breakout in path traversal fixture."""
    fixture_path = tmp_path / "server.py"
    fixture_path.write_text(
        'if profile == "vulnerable":\n'
        "    pass\n"
        "def tool_read(path: str):\n"
        "    if is_traversal:\n"
        '        return "external_files path_traversal"\n',
        encoding="utf-8",
    )
    findings = scan_python_file(str(fixture_path))
    rid = RuleCatalog.RULE_CWE_22_UNBOUNDED_READ.rule_id
    traversal_findings = [f for f in findings if f.rule_id == rid]
    assert len(traversal_findings) >= 1
    assert traversal_findings[0].cwe_id == "CWE-22"
    assert traversal_findings[0].severity == ScannerSeverity.HIGH


def test_scan_bola_broken_authorization_detection(tmp_path: Path) -> None:
    """Detect broken object level authorization in confused deputy fixture."""
    fixture_path = tmp_path / "server.py"
    fixture_path.write_text(
        'session_tenant = "t1"\n'
        'target_tenant = "t2"\n'
        "def tool_access():\n"
        "    if is_cross_tenant:\n"
        '        return "bola_violation"\n',
        encoding="utf-8",
    )
    findings = scan_python_file(str(fixture_path))
    bola_findings = [f for f in findings if f.rule_id == RuleCatalog.RULE_CWE_862_BOLA.rule_id]
    assert len(bola_findings) >= 1
    assert bola_findings[0].cwe_id == "CWE-862"
    assert bola_findings[0].severity == ScannerSeverity.HIGH


def test_scanner_engine_directory_and_severity_filter(tmp_path: Path) -> None:
    """Test engine recursive scanning and minimum severity filtering."""
    fixtures_dir = tmp_path / "fixtures"
    fixtures_dir.mkdir()
    for index in range(6):
        (fixtures_dir / f"server_{index}.py").write_text(
            'def tool():\n    return eval("1")\n', encoding="utf-8"
        )
    engine = McpAstScannerEngine(min_severity=ScannerSeverity.CRITICAL)
    report = engine.scan_path(str(fixtures_dir))
    total_files = len(report.scanned_files)
    assert total_files > 5
    # All returned findings must be CRITICAL
    for f in report.findings:
        assert f.severity == ScannerSeverity.CRITICAL


def test_scan_report_sarif_export(tmp_path: Path) -> None:
    """Validate SARIF v2.1.0 schema compliance and fields."""
    fixture_path = tmp_path / "server.py"
    fixture_path.write_text(
        'def evaluate_formula(expr: str):\n    return eval(expr)\n', encoding="utf-8"
    )
    engine = McpAstScannerEngine()
    report = engine.scan_path(str(fixture_path))
    sarif = report.to_sarif()
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "Verity-AST-Scanner"
    results = sarif["runs"][0]["results"]
    assert len(results) >= 1
    assert results[0]["ruleId"] == "VERITY-AST-CWE-94-EVAL"
    assert results[0]["level"] == "error"
    assert "evaluate_formula" in str(report.format_text())


def test_clean_hardened_codebase_zero_false_positives() -> None:
    """Verify that pure mathematical whitelist parser produces zero findings."""
    clean_code = '''
import ast

class SafeEvaluator(ast.NodeVisitor):
    def evaluate(self, node):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.BinOp):
            return 42
        raise ValueError("Safe rejection")
'''
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tmp:
        tmp.write(clean_code)
        tmp_path = tmp.name

    try:
        findings = scan_python_file(tmp_path)
        assert len(findings) == 0, f"Expected 0 findings on safe AST code, got {findings}"
    finally:
        Path(tmp_path).unlink(missing_ok=True)
