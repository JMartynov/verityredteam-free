"""ATDD tests for M40: SARIF line and file path precision."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from verity import cli


def test_sarif_preserves_line(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """AC-40.2: Real source line and file path survive export; missing location falls back to startLine == 1."""
    report = {
        "findings": [
            {
                "rule_id": "VERITY-AST-CMD-INJECTION",
                "severity": "HIGH",
                "title": "Command Injection",
                "message": "Shell execution detected",
                "file_path": "src/server.py",
                "line_number": 42,
                "remediation": "Avoid shell=True.",
            },
            {
                "rule_id": "VERITY-STATIC-ALT-KEYS",
                "severity": "MEDIUM",
                "title": "Alternate Location Keys",
                "message": "Uses uri and line keys",
                "uri": "alt/tool.py",
                "line": 17,
            },
            {
                "rule_id": "VERITY-MISSING-LINE",
                "severity": "LOW",
                "title": "Missing Line",
                "message": "No line provided",
                "location": "configs/mcp.json",
                "line_number": None,
            },
            {
                "rule_id": "VERITY-DASH-LINE",
                "severity": "INFO",
                "title": "Dash And Zero Fallback",
                "message": "Normalized dash line should degrade cleanly",
                "file_path": "",
                "line_number": "-",
            },
            {
                "rule_id": "VERITY-ZERO-LINE",
                "severity": "INFO",
                "title": "Zero Line Fallback",
                "message": "Zero line falls back to 1",
                "line_number": 0,
            },
        ]
    }

    sarif = cli._stdlib_sarif_exporter(report)
    results = sarif["runs"][0]["results"]
    assert len(results) == 5

    loc0 = results[0]["locations"][0]["physicalLocation"]
    assert loc0["artifactLocation"]["uri"] == "src/server.py"
    assert loc0["region"]["startLine"] == 42

    loc1 = results[1]["locations"][0]["physicalLocation"]
    assert loc1["artifactLocation"]["uri"] == "alt/tool.py"
    assert loc1["region"]["startLine"] == 17

    loc2 = results[2]["locations"][0]["physicalLocation"]
    assert loc2["artifactLocation"]["uri"] == "configs/mcp.json"
    assert loc2["region"]["startLine"] == 1

    loc3 = results[3]["locations"][0]["physicalLocation"]
    assert loc3["artifactLocation"]["uri"] == "mcp_config.json"
    assert loc3["region"]["startLine"] == 1

    loc4 = results[4]["locations"][0]["physicalLocation"]
    assert loc4["artifactLocation"]["uri"] == "mcp_config.json"
    assert loc4["region"]["startLine"] == 1

    # End-to-end AST scan through `verity scan --path ... --format sarif`
    py_file = tmp_path / "vuln_mcp.py"
    py_file.write_text(
        "\n".join(
            [
                "import subprocess",
                "",
                "",
                "def helper() -> None:",
                "    pass",
                "",
                "",
                "def run_cmd(user_input: str) -> str:",
                '    """Execute a shell command."""',
                "    return subprocess.check_output(user_input, shell=True, text=True)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    config_file = tmp_path / "empty_mcp.json"
    config_file.write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")
    sarif_out = tmp_path / "scan.sarif"

    monkeypatch.setattr(cli, "_pro_plugin_available", lambda: True)
    monkeypatch.setattr(cli, "_iter_plugin_entry_points", lambda: [])

    rc = cli.main(
        [
            "scan",
            "--config-file",
            str(config_file),
            "--path",
            str(py_file),
            "--format",
            "sarif",
            "--output",
            str(sarif_out),
        ]
    )
    assert rc == 0
    exported = json.loads(sarif_out.read_text(encoding="utf-8"))
    exported_results = exported["runs"][0]["results"]
    assert exported_results, "Expected at least one AST finding in SARIF export"

    matched = [
        res
        for res in exported_results
        if res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == str(py_file)
        and res["locations"][0]["physicalLocation"]["region"]["startLine"] == 10
    ]
    assert matched, f"Expected finding at {py_file}:10, got {exported_results}"
