"""Unit tests for M19 opt-in ``--live-probe`` support in ``verity scan``."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from verity import cli
from verity.discovery import auditor as auditor_module
from verity.discovery.models import (
    FindingSeverity,
    LiveServerCapability,
    SecurityAuditFinding,
    ServerAuditRecord,
)
from verity.discovery.transports import stdio as stdio_module

SECRET = "sk-live-verity-secret-1234567890"


def _write_config(tmp_path: Path, servers: dict) -> Path:
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    return path


def _fake_record(config, findings, live_probe_error=None):
    return ServerAuditRecord(
        server_name=config.server_name,
        client_type=config.client_type,
        config_path=config.config_path,
        findings=tuple(findings),
        highest_severity=(
            findings[0].severity if findings else FindingSeverity.INFO
        ),
        live_probe_error=live_probe_error,
    )


def _finding(
    config,
    rule_id="VERITY-STATIC-INJECTION-OVERRIDE",
    severity=FindingSeverity.CRITICAL,
    evidence="ignore previous instructions",
):
    return SecurityAuditFinding(
        issue_id=rule_id,
        severity=severity,
        title=rule_id,
        description=rule_id,
        server_name=config.server_name,
        client_type=config.client_type,
        config_path=config.config_path,
        remediation="Sanitize.",
        redacted_evidence=evidence,
    )


def _run(capsys, argv):
    rc = cli.main(argv)
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


@pytest.fixture
def fake_auditor(monkeypatch):
    calls: list[tuple[str, bool]] = []

    def fake_init(self, *args, **kwargs):
        pass

    def fake_audit(self, config, live_probe=False):
        calls.append((config.server_name, live_probe))
        if live_probe:
            return _fake_record(config, [_finding(config)])
        return _fake_record(config, [])

    monkeypatch.setattr(
        auditor_module.ConsolidatedSecurityAuditor, "__init__", fake_init
    )
    monkeypatch.setattr(
        auditor_module.ConsolidatedSecurityAuditor, "audit_server", fake_audit
    )
    return SimpleNamespace(calls=calls)


@pytest.fixture
def patch_auditor(monkeypatch):
    def install(audit_impl):
        calls: list[tuple[str, bool]] = []

        def fake_init(self, *args, **kwargs):
            pass

        def wrapper(self, config, live_probe=False):
            calls.append((config.server_name, live_probe))
            return audit_impl(config, live_probe)

        monkeypatch.setattr(
            auditor_module.ConsolidatedSecurityAuditor, "__init__", fake_init
        )
        monkeypatch.setattr(
            auditor_module.ConsolidatedSecurityAuditor, "audit_server", wrapper
        )
        return calls

    return install


@pytest.fixture
def real_auditor_offline(monkeypatch, tmp_path):
    monkeypatch.setenv("VERITY_OFFLINE", "1")
    monkeypatch.setenv("VERITY_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(
        auditor_module.HybridDiscoveryMatcher,
        "__init__",
        lambda self, *args, **kwargs: None,
    )
    monkeypatch.setattr(
        auditor_module.HybridDiscoveryMatcher,
        "match_static_config",
        lambda self, config: SimpleNamespace(
            matched=False,
            package_name=None,
            purl=None,
            matched_version=None,
            confidence_score=0.0,
        ),
    )
    monkeypatch.setattr(
        auditor_module.HybridDiscoveryMatcher,
        "match_live_capability",
        lambda self, cap, config: SimpleNamespace(
            matched=False,
            package_name=None,
            purl=None,
            matched_version=None,
            confidence_score=0.0,
            match_layer="NONE",
        ),
    )
    monkeypatch.setattr(
        auditor_module.VulnerabilityLookupEngine,
        "from_auto",
        classmethod(lambda cls, *args, **kwargs: None),
    )
    return monkeypatch


def test_default_off_never_inspects(tmp_path, capsys, real_auditor_offline):
    inspect_calls: list[str] = []
    real_auditor_offline.setattr(
        stdio_module.StdioDiscoveryTransport,
        "inspect",
        lambda self, config: inspect_calls.append(config.server_name)
        or LiveServerCapability(server_name=config.server_name),
    )
    cfg = _write_config(
        tmp_path, {"srv": {"command": "npx", "args": ["-y", "safe-server"]}}
    )
    rc, _out, _err = _run(
        capsys, ["scan", "--config-file", str(cfg), "--format", "json"]
    )
    assert rc == 0
    assert inspect_calls == []


def test_opt_in_calls_audit_with_live_probe(tmp_path, capsys, fake_auditor):
    cfg = _write_config(
        tmp_path, {"srv": {"command": "npx", "args": ["-y", "safe-server"]}}
    )
    _rc, out, _err = _run(
        capsys,
        [
            "scan",
            "--config-file",
            str(cfg),
            "--live-probe",
            "--format",
            "json",
        ],
    )
    assert any(live is True for _name, live in fake_auditor.calls)
    report = json.loads(out)
    ids = {f["rule_id"] for f in report["findings"]}
    assert "VERITY-STATIC-INJECTION-OVERRIDE" in ids
    finding = next(
        f
        for f in report["findings"]
        if f["rule_id"] == "VERITY-STATIC-INJECTION-OVERRIDE"
    )
    assert finding["severity"] == "CRITICAL"
    assert finding["remediation"]


def test_dead_server_timeout_isolated(tmp_path, capsys, patch_auditor):
    def audit_impl(config, live_probe):
        if config.server_name == "dead" and live_probe:
            raise TimeoutError("boom")
        return _fake_record(config, [_finding(config)] if live_probe else [])

    patch_auditor(audit_impl)
    cfg = _write_config(
        tmp_path,
        {
            "healthy": {"command": "npx", "args": ["-y", "safe-server"]},
            "dead": {"command": "npx", "args": ["-y", "safe-server-2"]},
        },
    )
    rc, out, err = _run(
        capsys,
        [
            "scan",
            "--config-file",
            str(cfg),
            "--live-probe",
            "--format",
            "json",
        ],
    )
    assert rc == 0
    assert "dead" in err
    assert "Live probe failed for dead" in err
    report = json.loads(out)
    assert any(
        f["rule_id"] == "VERITY-STATIC-INJECTION-OVERRIDE"
        for f in report["findings"]
    )


def test_unresponsive_process_warns(tmp_path, capsys, patch_auditor):
    def audit_impl(config, live_probe):
        if not live_probe:
            return _fake_record(config, [])
        if config.server_name == "dead":
            return _fake_record(
                config,
                [],
                live_probe_error="Server process exited with code 1",
            )
        return _fake_record(config, [_finding(config)])

    patch_auditor(audit_impl)
    cfg = _write_config(
        tmp_path,
        {
            "healthy": {"command": "npx", "args": ["-y", "safe-server"]},
            "dead": {"command": "npx", "args": ["-y", "safe-server-2"]},
        },
    )
    rc, _out, err = _run(
        capsys,
        [
            "scan",
            "--config-file",
            str(cfg),
            "--live-probe",
            "--format",
            "json",
        ],
    )
    assert rc == 0
    assert "Live probe failed for dead" in err


@pytest.mark.parametrize("fmt", ["terminal", "json", "markdown", "html"])
def test_formatting_parity_and_secret_scrub(
    tmp_path, capsys, patch_auditor, fmt
):
    def audit_impl(config, live_probe):
        if live_probe:
            return _fake_record(
                config, [_finding(config, evidence=f"leak {SECRET}")]
            )
        return _fake_record(config, [])

    patch_auditor(audit_impl)
    cfg = _write_config(
        tmp_path,
        {
            "leaky": {
                "command": "npx",
                "args": ["-y", "safe-server"],
                "env": {"OPENAI_API_KEY": SECRET},
            }
        },
    )
    _rc, out, _err = _run(
        capsys,
        [
            "scan",
            "--config-file",
            str(cfg),
            "--live-probe",
            "--format",
            fmt,
        ],
    )
    assert SECRET not in out
    assert "VERITY-STATIC-INJECTION-OVERRIDE" in out


def test_fail_on_findings_live_only(tmp_path, capsys, fake_auditor):
    cfg = _write_config(
        tmp_path, {"srv": {"command": "npx", "args": ["-y", "safe-server"]}}
    )
    rc_live, _out_live, _ = _run(
        capsys,
        [
            "scan",
            "--config-file",
            str(cfg),
            "--live-probe",
            "--format",
            "json",
            "--fail-on-findings",
        ],
    )
    rc_static, _out_static, _ = _run(
        capsys,
        [
            "scan",
            "--config-file",
            str(cfg),
            "--format",
            "json",
            "--fail-on-findings",
        ],
    )
    assert rc_live == 1
    assert rc_static == 0


def test_offline_live_probe_env_restored(
    tmp_path, capsys, patch_auditor, monkeypatch
):
    monkeypatch.delenv("VERITY_OFFLINE", raising=False)
    seen: list[str | None] = []

    def audit_impl(config, live_probe):
        seen.append(os.environ.get("VERITY_OFFLINE"))
        return _fake_record(config, [])

    patch_auditor(audit_impl)
    cfg = _write_config(
        tmp_path, {"srv": {"command": "npx", "args": ["-y", "safe-server"]}}
    )
    _rc, _out, _err = _run(
        capsys,
        [
            "scan",
            "--config-file",
            str(cfg),
            "--offline",
            "--live-probe",
            "--format",
            "json",
        ],
    )
    assert seen, "audit_server callback did not run"
    assert all(value == "1" for value in seen), seen
    assert "VERITY_OFFLINE" not in os.environ


def test_offline_live_probe_restores_prior_value(
    tmp_path, capsys, patch_auditor, monkeypatch
):
    monkeypatch.setenv("VERITY_OFFLINE", "0")
    seen: list[str | None] = []

    def audit_impl(config, live_probe):
        seen.append(os.environ.get("VERITY_OFFLINE"))
        return _fake_record(config, [])

    patch_auditor(audit_impl)
    cfg = _write_config(
        tmp_path, {"srv": {"command": "npx", "args": ["-y", "safe-server"]}}
    )
    cli.main(
        [
            "scan",
            "--config-file",
            str(cfg),
            "--offline",
            "--live-probe",
            "--format",
            "json",
        ]
    )
    capsys.readouterr()
    assert seen, "audit_server callback did not run"
    assert all(value == "1" for value in seen), seen
    assert os.environ["VERITY_OFFLINE"] == "0"


def test_live_findings_sorted_by_severity(tmp_path, capsys, patch_auditor):
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    def audit_impl(config, live_probe):
        if not live_probe:
            return _fake_record(config, [])
        return _fake_record(
            config,
            [
                _finding(config, rule_id="R-LOW", severity=FindingSeverity.LOW),
                _finding(
                    config, rule_id="R-CRIT", severity=FindingSeverity.CRITICAL
                ),
                _finding(
                    config, rule_id="R-MED", severity=FindingSeverity.MEDIUM
                ),
                _finding(
                    config, rule_id="R-INFO", severity=FindingSeverity.INFO
                ),
                _finding(
                    config, rule_id="R-HIGH", severity=FindingSeverity.HIGH
                ),
            ],
        )

    patch_auditor(audit_impl)
    cfg = _write_config(
        tmp_path, {"srv": {"command": "npx", "args": ["-y", "safe-server"]}}
    )
    _rc, out, _err = _run(
        capsys,
        [
            "scan",
            "--config-file",
            str(cfg),
            "--live-probe",
            "--format",
            "json",
        ],
    )
    report = json.loads(out)
    sevs = [f["severity"] for f in report["findings"]]
    assert sevs == sorted(sevs, key=lambda s: order[s])
