"""Locked ATDD tests for M46 Phase B: OWASP mapping, CycloneDX 1.6 / SPDX 2.3 SBOM, inventory drift, CLI & MCP parity."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from verity import cli
from verity.discovery.models import ClientType, ServerAuditRecord
from verity.mcp_server.handlers.legacy import LegacyToolsHandlerMixin
from verity.mcp_server.handlers.security_scan import SecurityScanHandlerMixin
from verity.mcp_server.schemas import UNIFIED_TOOL_DEFINITIONS
from verity.reporting.sbom import (
    build_compliance_scorecard,
    build_inventory_snapshot,
    compare_inventory_snapshots,
    enrich_findings_with_owasp,
    render_scan_cyclonedx,
    render_scan_spdx,
)


def _sample_records() -> list[ServerAuditRecord]:
    return [
        ServerAuditRecord(
            server_name="fs-server",
            client_type=ClientType.CLAUDE_DESKTOP,
            config_path="/tmp/claude_desktop_config.json",
            matched_package="@modelcontextprotocol/server-filesystem",
            matched_purl="pkg:npm/%40modelcontextprotocol/server-filesystem",
            matched_version="0.6.2",
            confidence_score=1.0,
            match_layer="LAYER_1_EXACT",
            tools_exposed=("read_file", "list_directory"),
        ),
        ServerAuditRecord(
            server_name="remote-helper",
            client_type=ClientType.CURSOR,
            config_path="/tmp/.cursor/mcp.json",
            matched_package="mcp-remote",
            matched_purl="pkg:npm/mcp-remote",
            matched_version="0.1.15",
            confidence_score=1.0,
            match_layer="LAYER_1_EXACT",
            tools_exposed=("proxy_call",),
        ),
    ]


def test_cyclonedx_16_and_spdx_23_sbom_modes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """AC-46.3 / AC-82.8: CycloneDX 1.6 & SPDX 2.3 emit valid SBOMs in inventory-only and vuln-enriched modes."""
    records = _sample_records()
    findings = [
        {
            "rule_id": "VULN-CVE-2025-6514",
            "advisory_id": "CVE-2025-6514",
            "cve_id": "CVE-2025-6514",
            "cwe_id": "CWE-78",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "title": "mcp-remote command injection",
            "message": "RCE via OAuth callback",
            "file_path": "/tmp/.cursor/mcp.json",
            "line_number": 1,
            "remediation": "Upgrade mcp-remote",
            "package_name": "mcp-remote",
            "server_name": "remote-helper",
            "reachability": "REACHABLE",
            "owasp_mcp_id": "MCP04",
            "owasp_llm_id": "LLM03:2025",
        },
        {
            "rule_id": "VULN-CVE-2099-0002",
            "advisory_id": "CVE-2099-0002",
            "cve_id": "CVE-2099-0002",
            "cwe_id": "CWE-22",
            "severity": "MEDIUM",
            "title": "Unused dependency flaw",
            "message": "Not imported in server tools",
            "file_path": "/tmp/claude_desktop_config.json",
            "line_number": 1,
            "remediation": "Upgrade dependency",
            "package_name": "@modelcontextprotocol/server-filesystem",
            "server_name": "fs-server",
            "reachability": "NOT_IMPORTED",
            "owasp_mcp_id": "MCP04",
            "owasp_llm_id": "LLM03:2025",
        },
    ]

    # Inventory-only CycloneDX 1.6
    inv_bom = render_scan_cyclonedx(records, findings, include_vulns=False)
    assert inv_bom["bomFormat"] == "CycloneDX"
    assert inv_bom["specVersion"] == "1.6"
    assert inv_bom["version"] == 1
    assert "metadata" in inv_bom
    assert len(inv_bom["components"]) == 2
    assert all(c["type"] == "application" and "purl" in c for c in inv_bom["components"])
    assert "vulnerabilities" not in inv_bom

    # Enriched CycloneDX 1.6 with reachability-mapped analysis.state & OWASP properties
    vuln_bom = render_scan_cyclonedx(records, findings, include_vulns=True)
    assert len(vuln_bom["vulnerabilities"]) == 2
    by_id = {v["id"]: v for v in vuln_bom["vulnerabilities"]}
    assert by_id["CVE-2025-6514"]["analysis"]["state"] == "exploitable"
    assert by_id["CVE-2025-6514"]["cwes"] == [78]
    assert by_id["CVE-2099-0002"]["analysis"]["state"] == "not_affected"
    props = {p["name"]: p["value"] for p in by_id["CVE-2025-6514"].get("properties", [])}
    assert props["verity:owasp:mcp"] == "MCP04"
    assert props["verity:owasp:llm"] == "LLM03:2025"

    # SPDX 2.3
    spdx = render_scan_spdx(records)
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert spdx["dataLicense"] == "CC0-1.0"
    assert spdx["SPDXID"] == "SPDXRef-DOCUMENT"
    assert len(spdx["packages"]) == 2
    assert len(spdx["relationships"]) == 2

    # CLI integration: --format cyclonedx (inventory-only) vs --format cyclonedx --scanners vuln vs --format spdx
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "leaky": {
                        "command": "npx",
                        "args": ["-y", "safe-pkg@1.0.0"],
                        "env": {"API_KEY": "sk-live-sbom-secret-1234567890"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    rc_inv = cli.main(["scan", "--config-file", str(cfg), "--offline", "--format", "cyclonedx"])
    bom_cli = json.loads(capsys.readouterr().out)
    assert rc_inv == 0
    assert bom_cli["bomFormat"] == "CycloneDX"
    assert bom_cli["specVersion"] == "1.6"
    assert "vulnerabilities" not in bom_cli

    rc_spdx = cli.main(["scan", "--config-file", str(cfg), "--offline", "--format", "spdx"])
    spdx_cli = json.loads(capsys.readouterr().out)
    assert rc_spdx == 0
    assert spdx_cli["spdxVersion"] == "SPDX-2.3"


def test_owasp_compliance_additive_schema_and_fail_gates(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """AC-46.3 / AC-82.7: OWASP mapping preserves all 8 legacy finding keys and enforces compliance gates."""
    legacy_keys = {
        "rule_id",
        "cwe_id",
        "severity",
        "title",
        "message",
        "file_path",
        "line_number",
        "remediation",
    }
    raw_findings = [
        {
            "rule_id": "SEC-STATIC-SECRET-IN-CONFIG",
            "cwe_id": "CWE-798",
            "severity": "CRITICAL",
            "title": "Plaintext secret",
            "message": "Secret in env",
            "file_path": "mcp.json",
            "line_number": 1,
            "remediation": "Use env vars",
            "scanner": "secret",
        },
        {
            "rule_id": "VERITY-AST-CWE-78-SYSTEM",
            "cwe_id": "CWE-78",
            "severity": "CRITICAL",
            "title": "OS Command Injection",
            "message": "os.system called",
            "file_path": "srv.py",
            "line_number": 5,
            "remediation": "Use subprocess list",
            "scanner": "ast",
        },
    ]
    enriched = enrich_findings_with_owasp(raw_findings)
    for item in enriched:
        assert legacy_keys <= set(item.keys())
        assert item["owasp_mcp_id"].startswith("MCP")
        assert item["owasp_llm_id"].startswith("LLM")
        assert item["owasp_category"]

    scorecard = build_compliance_scorecard(enriched, standard="owasp-mcp-top-10")
    assert scorecard["score"] == 60
    assert scorecard["tier"] == "NON_COMPLIANT"
    assert "MCP01" in scorecard["categories"]
    assert "MCP10" in scorecard["categories"]

    # CLI compliance & fail gates
    bad_py = tmp_path / "bad.py"
    bad_py.write_text("import os\ndef f(x):\n    os.system(x)\n    eval(x)\n", encoding="utf-8")
    # 2 CRITICAL findings -> score 60 -> NON_COMPLIANT -> exit 1 with --fail-on-non-compliant
    rc_fail = cli.main(
        [
            "scan",
            "--path",
            str(bad_py),
            "--offline",
            "--compliance",
            "owasp-mcp-top-10",
            "--fail-on-non-compliant",
            "--format",
            "json",
        ]
    )
    rep_fail = json.loads(capsys.readouterr().out)
    assert rc_fail == 1
    assert rep_fail["compliance"]["tier"] == "NON_COMPLIANT"
    assert legacy_keys <= set(rep_fail["findings"][0].keys())
    assert rep_fail["findings"][0]["owasp_mcp_id"].startswith("MCP")

    # Clean benign control -> COMPLIANT, exit 0
    clean_py = tmp_path / "clean.py"
    clean_py.write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
    rc_ok = cli.main(
        [
            "scan",
            "--path",
            str(clean_py),
            "--offline",
            "--compliance",
            "owasp-mcp-top-10",
            "--fail-on-non-compliant",
            "--format",
            "json",
        ]
    )
    rep_ok = json.loads(capsys.readouterr().out)
    assert rc_ok == 0
    assert rep_ok["compliance"]["tier"] == "COMPLIANT"
    assert rep_ok["compliance"]["score"] == 100


def test_inventory_drift_cli_and_coexistence_with_finding_baselines(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """AC-46.4 / AC-82.9: Inventory drift flags detect drift (exit 2), exit 0 when unchanged, and coexist with M31 baselines."""
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "srv-one": {
                        "command": "npx",
                        "args": ["-y", "safe-pkg@1.0.0"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    inv_baseline = tmp_path / "inventory.baseline.json"
    finding_baseline = tmp_path / ".verity-baseline.json"

    # Save both inventory baseline and finding baseline without collision
    rc_save = cli.main(
        [
            "scan",
            "--config-file",
            str(cfg),
            "--offline",
            "--save-inventory-baseline",
            str(inv_baseline),
            "--save-baseline",
            str(finding_baseline),
            "--format",
            "json",
        ]
    )
    capsys.readouterr()
    assert rc_save == 0
    assert inv_baseline.is_file()
    assert finding_baseline.is_file()

    # Unchanged inventory -> has_drift False, exit 0 even with --fail-on-drift
    rc_clean = cli.main(
        [
            "scan",
            "--config-file",
            str(cfg),
            "--offline",
            "--compare-inventory-baseline",
            str(inv_baseline),
            "--fail-on-drift",
            "--format",
            "json",
        ]
    )
    rep_clean = json.loads(capsys.readouterr().out)
    assert rc_clean == 0
    assert rep_clean["inventory_drift"]["has_drift"] is False

    # Mutate inventory (add second server) -> has_drift True, exit 2 with --fail-on-drift
    cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "srv-one": {
                        "command": "npx",
                        "args": ["-y", "safe-pkg@1.0.0"],
                    },
                    "srv-two": {
                        "command": "uvx",
                        "args": ["mcp-server-fetch==1.2.0"],
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    rc_drift = cli.main(
        [
            "scan",
            "--config-file",
            str(cfg),
            "--offline",
            "--compare-inventory-baseline",
            str(inv_baseline),
            "--fail-on-drift",
            "--format",
            "json",
        ]
    )
    rep_drift = json.loads(capsys.readouterr().out)
    assert rc_drift == 2
    assert rep_drift["inventory_drift"]["has_drift"] is True
    assert len(rep_drift["inventory_drift"]["added_servers"]) == 1

    # Direct unit helper check
    snap_a = build_inventory_snapshot(_sample_records()[:1])
    snap_b = build_inventory_snapshot(_sample_records())
    diff = compare_inventory_snapshots(snap_a, snap_b)
    assert diff["has_drift"] is True
    assert len(diff["added_servers"]) == 1
    assert compare_inventory_snapshots(snap_a, snap_a)["has_drift"] is False


def test_mcp_security_scan_parity_options(tmp_path: Path) -> None:
    """AC-46.4 / AC-82.9: verity_security_scan schema and handler support scanners, include_reachability, format, and inventory drift."""
    scan_schema = next(
        d for d in UNIFIED_TOOL_DEFINITIONS if d["name"] == "verity_security_scan"
    )
    opt_props = scan_schema["inputSchema"]["properties"]["options"]["properties"]
    for key in (
        "scanners",
        "include_reachability",
        "format",
        "save_inventory_baseline",
        "compare_inventory_baseline",
        "fail_on_drift",
    ):
        assert key in opt_props

    class _Handler(SecurityScanHandlerMixin, LegacyToolsHandlerMixin):
        def __init__(self) -> None:
            self.context = SimpleNamespace(
                matcher=SimpleNamespace(match=lambda **_kw: SimpleNamespace(matched=False)),
                vuln_engine=SimpleNamespace(query=lambda *_a, **_kw: SimpleNamespace(vulnerabilities=[])),
            )

    handler = _Handler()
    sandbox = tmp_path / "sb"
    cursor_cfg = sandbox / "home" / ".cursor" / "mcp.json"
    cursor_cfg.parent.mkdir(parents=True)
    cursor_cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "demo-srv": {
                        "command": "npx",
                        "args": ["-y", "safe-pkg@1.0.0"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    inv_path = tmp_path / "mcp_inv.json"
    res1 = handler._execute_security_scan(
        {
            "action": "scan_client_configs",
            "options": {
                "sandbox_root": str(sandbox),
                "format": "cyclonedx",
                "scanners": ["config", "secret"],
                "save_inventory_baseline": str(inv_path),
            },
        }
    )
    assert res1["ok"] is True
    assert res1["sbom"]["bomFormat"] == "CycloneDX"
    assert res1["sbom"]["specVersion"] == "1.6"
    assert inv_path.is_file()

    # Mutate config and verify inventory drift gate_passed=False
    cursor_cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "demo-srv": {"command": "npx", "args": ["-y", "safe-pkg@1.0.0"]},
                    "extra-srv": {"command": "uvx", "args": ["mcp-server-fetch==1.2.0"]},
                }
            }
        ),
        encoding="utf-8",
    )
    res2 = handler._execute_security_scan(
        {
            "action": "scan_client_configs",
            "options": {
                "sandbox_root": str(sandbox),
                "compare_inventory_baseline": str(inv_path),
                "fail_on_drift": True,
            },
        }
    )
    assert res2["inventory_drift"]["has_drift"] is True
    assert res2["gate_passed"] is False
