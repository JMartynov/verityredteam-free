"""Unit and CLI tests for M15 unpinned MCP package detection."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

import pytest

from verity import cli
from verity.discovery import auditor as auditor_module
from verity.discovery.auditor import ConsolidatedSecurityAuditor
from verity.discovery.matcher import HybridDiscoveryMatcher
from verity.discovery.models import (
    ClientType,
    DiscoveredServerConfig,
    FindingSeverity,
    TransportType,
)

UNPINNED_RULE = "SEC-STATIC-UNPINNED-PACKAGE"
PINNED_CONFIDENCE = 0.85
UNPINNED_CONFIDENCE = 0.65


def _spec(
    package_name: str, purl: str, version: str, tool_count: int = 1
) -> SimpleNamespace:
    return SimpleNamespace(
        package_name=package_name,
        purl=purl,
        versions=[SimpleNamespace(version=version, tool_signatures=[{}] * tool_count)],
    )


def _specs() -> dict[str, SimpleNamespace]:
    return {
        "mcp-remote": _spec("mcp-remote", "pkg:npm/mcp-remote", "0.1.15"),
        "mcp-server-fetch": _spec(
            "mcp-server-fetch", "pkg:pypi/mcp-server-fetch", "1.2.0"
        ),
        "@modelcontextprotocol/server-github": _spec(
            "@modelcontextprotocol/server-github",
            "pkg:npm/@modelcontextprotocol/server-github",
            "0.5.0",
        ),
    }


class _FakeFingerprintIndex:
    def __init__(self, specs: dict[str, SimpleNamespace]) -> None:
        self._specs = specs

    def find_package_by_hint_or_alias(self, name: str) -> SimpleNamespace | None:
        return self._specs.get(name)


class _FakeFingerprintMatcher:
    def __init__(self, specs: dict[str, SimpleNamespace]) -> None:
        self.fast_index = _FakeFingerprintIndex(specs)


class _FakeVulnerability:
    def __init__(self, vulnerability_id: str) -> None:
        self.vulnerability_id = vulnerability_id
        self.summary = "mcp-remote remote code execution"
        self.details = "RCE via crafted OAuth callback."
        self.cvss_score = 9.8
        self.cwe_ids = ["CWE-94"]
        self.vulnerable_tools = ["mcp_remote_run"]
        self.aliases: list[str] = []
        self.fixed = None


class _FakeLookupResult:
    def __init__(self, vulnerabilities: list[_FakeVulnerability]) -> None:
        self.vulnerabilities = vulnerabilities


class _FakeVulnerabilityEngine:
    calls: ClassVar[list[tuple[str | None, str | None]]] = []

    @classmethod
    def from_auto(
        cls, *args: object, **kwargs: object
    ) -> _FakeVulnerabilityEngine:
        return cls()

    def query(
        self, identifier: str | None = None, version: str | None = None
    ) -> _FakeLookupResult:
        _FakeVulnerabilityEngine.calls.append((identifier, version))
        if identifier == "mcp-remote" and version == "0.1.15":
            return _FakeLookupResult([_FakeVulnerability("CVE-2025-6514")])
        return _FakeLookupResult([])


def _patch_matcher(
    monkeypatch: pytest.MonkeyPatch, specs: dict[str, SimpleNamespace]
) -> None:
    def fake_init(
        self: HybridDiscoveryMatcher,
        fingerprint_dir: str | Path = "data/fingerprints",
    ) -> None:
        self.fingerprint_dir = Path(fingerprint_dir)
        self.matcher = _FakeFingerprintMatcher(specs)

    monkeypatch.setattr(HybridDiscoveryMatcher, "__init__", fake_init)


@pytest.fixture
def matcher(monkeypatch: pytest.MonkeyPatch) -> HybridDiscoveryMatcher:
    _patch_matcher(monkeypatch, _specs())
    return HybridDiscoveryMatcher()


@pytest.fixture
def auditor(monkeypatch: pytest.MonkeyPatch) -> ConsolidatedSecurityAuditor:
    _patch_matcher(monkeypatch, _specs())
    monkeypatch.setattr(
        auditor_module, "VulnerabilityLookupEngine", _FakeVulnerabilityEngine
    )
    monkeypatch.setenv("VERITY_OFFLINE", "1")
    _FakeVulnerabilityEngine.calls = []
    return ConsolidatedSecurityAuditor()


def _config(
    command: str,
    args: list[str],
    name: str = "test-server",
) -> DiscoveredServerConfig:
    return DiscoveredServerConfig(
        client_type=ClientType.CURSOR,
        server_name=name,
        command=command,
        args=tuple(args),
        transport_type=TransportType.STDIO,
    )


def _unpinned(findings: tuple) -> list:
    return [f for f in findings if f.issue_id == UNPINNED_RULE]


def test_unpinned_npx_matcher_returns_none_version(
    matcher: HybridDiscoveryMatcher,
) -> None:
    config = _config("npx", ["-y", "mcp-remote"], "mcp-remote-unpinned")
    result = matcher.match_static_config(config)

    assert result.matched is True
    assert result.matched_version is None
    assert result.confidence_score == pytest.approx(UNPINNED_CONFIDENCE)
    assert result.match_layer == "STATIC_CONFIG_MATCH"


def test_unpinned_npx_auditor_emits_advisory(
    auditor: ConsolidatedSecurityAuditor,
) -> None:
    config = _config("npx", ["-y", "mcp-remote"], "mcp-remote-unpinned")
    record = auditor.audit_server(config)

    issue_ids = {f.issue_id for f in record.findings}
    assert UNPINNED_RULE in issue_ids
    assert not any(issue_id.startswith("VULN-") for issue_id in issue_ids)
    assert _FakeVulnerabilityEngine.calls == []

    finding = next(f for f in record.findings if f.issue_id == UNPINNED_RULE)
    assert finding.severity == FindingSeverity.MEDIUM
    assert set(finding.cwe_ids) == {"CWE-1104", "CWE-829"}
    assert finding.remediation
    assert "mcp-remote" in finding.redacted_evidence


@pytest.mark.parametrize(
    ("name", "package_token", "expected_package"),
    [
        ("mcp-remote-unpinned", "mcp-remote@latest", "mcp-remote"),
        (
            "gh-unpinned",
            "@modelcontextprotocol/server-github@latest",
            "@modelcontextprotocol/server-github",
        ),
    ],
)
def test_floating_latest_is_unpinned(
    matcher: HybridDiscoveryMatcher,
    auditor: ConsolidatedSecurityAuditor,
    name: str,
    package_token: str,
    expected_package: str,
) -> None:
    config = _config("npx", ["-y", package_token], name)
    result = matcher.match_static_config(config)

    assert result.matched is True
    assert result.package_name == expected_package
    assert result.matched_version is None
    assert result.confidence_score == pytest.approx(UNPINNED_CONFIDENCE)

    findings = _unpinned(auditor.audit_server(config).findings)
    assert findings
    assert findings[0].severity == FindingSeverity.MEDIUM
    assert package_token in findings[0].redacted_evidence


def test_pinned_vulnerable_package(
    matcher: HybridDiscoveryMatcher,
    auditor: ConsolidatedSecurityAuditor,
) -> None:
    config = _config("npx", ["-y", "mcp-remote@0.1.15"], "mcp-remote-pinned")
    result = matcher.match_static_config(config)

    assert result.matched is True
    assert result.matched_version == "0.1.15"
    assert result.confidence_score == pytest.approx(PINNED_CONFIDENCE)

    issue_ids = {f.issue_id for f in auditor.audit_server(config).findings}
    assert UNPINNED_RULE not in issue_ids
    assert "VULN-CVE-2025-6514" in issue_ids
    assert ("mcp-remote", "0.1.15") in _FakeVulnerabilityEngine.calls


def test_pinned_python_package_has_no_unpinned_warning(
    matcher: HybridDiscoveryMatcher,
    auditor: ConsolidatedSecurityAuditor,
) -> None:
    config = _config("uvx", ["mcp-server-fetch==1.2.0"], "fetch-pinned")
    result = matcher.match_static_config(config)

    assert result.matched_version == "1.2.0"
    assert result.confidence_score == pytest.approx(PINNED_CONFIDENCE)
    assert not _unpinned(auditor.audit_server(config).findings)


def test_unpinned_python_package_emits_warning(
    auditor: ConsolidatedSecurityAuditor,
) -> None:
    config = _config("uvx", ["mcp-server-fetch"], "fetch-unpinned")
    assert _unpinned(auditor.audit_server(config).findings)


@pytest.mark.parametrize("runner", ["pipx", "bunx", "npx"])
def test_other_floating_runners(
    auditor: ConsolidatedSecurityAuditor, runner: str
) -> None:
    token = "mcp-remote" if runner == "npx" else "mcp-server-fetch"
    args = ["run", token] if runner == "pipx" else [token]
    config = _config(runner, args, f"{runner}-server")
    assert _unpinned(auditor.audit_server(config).findings)


@pytest.mark.parametrize(
    ("runner", "specifier"),
    [("pipx", "mcp-server-fetch==1.2.0"), ("bunx", "mcp-remote@0.1.15")],
)
def test_pinned_other_runners_have_no_warning(
    auditor: ConsolidatedSecurityAuditor, runner: str, specifier: str
) -> None:
    args = ["run", specifier] if runner == "pipx" else [specifier]
    config = _config(runner, args, f"{runner}-pinned")
    assert not _unpinned(auditor.audit_server(config).findings)


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("python3", ["/opt/mcp/server.py"]),
        ("node", ["/app/index.js"]),
        ("npx", ["-y", "./server.js"]),
        ("npx", ["-y", "../local/server.js"]),
    ],
)
def test_local_binaries_not_flagged(
    auditor: ConsolidatedSecurityAuditor, command: str, args: list[str]
) -> None:
    config = _config(command, args, "local-server")
    assert not _unpinned(auditor.audit_server(config).findings)


def test_shell_wrapper_pinned_vs_unpinned(
    auditor: ConsolidatedSecurityAuditor,
) -> None:
    unpinned = _config("bash", ["-c", "npx -y mcp-remote"], "shell-unpinned")
    assert _unpinned(auditor.audit_server(unpinned).findings)

    pinned = _config(
        "bash", ["-c", "npx -y mcp-remote@0.1.15"], "shell-pinned"
    )
    assert not _unpinned(auditor.audit_server(pinned).findings)


def test_shell_wrapper_scoped_package(
    auditor: ConsolidatedSecurityAuditor,
) -> None:
    unpinned = _config(
        "sh", ["-lc", "npx -y @modelcontextprotocol/server-github"], "scoped-unpinned"
    )
    assert _unpinned(auditor.audit_server(unpinned).findings)

    pinned = _config(
        "sh",
        ["-lc", "npx -y @modelcontextprotocol/server-github@1.0.0"],
        "scoped-pinned",
    )
    assert not _unpinned(auditor.audit_server(pinned).findings)


@pytest.mark.parametrize(
    ("args", "expect_unpinned"),
    [
        (["--from", "mcp-server-fetch==1.2.0", "mcp-server-fetch"], False),
        (["--from", "mcp-server-fetch", "mcp-server-fetch"], True),
        (["mcp-server-fetch[cli]==1.2.0"], False),
        (["mcp-server-fetch[cli]"], True),
        (["--python", "3.11", "mcp-server-fetch==1.2.0"], False),
        (["--python", "3.11", "mcp-server-fetch"], True),
    ],
)
def test_uvx_value_flags_and_extras(
    auditor: ConsolidatedSecurityAuditor, args: list[str], expect_unpinned: bool
) -> None:
    config = _config("uvx", args, "uvx-flag-server")
    has_unpinned = bool(_unpinned(auditor.audit_server(config).findings))
    assert has_unpinned is expect_unpinned


def test_pinned_scoped_package_does_not_emit_unpinned(
    matcher: HybridDiscoveryMatcher,
    auditor: ConsolidatedSecurityAuditor,
) -> None:
    config = _config(
        "npx",
        ["-y", "@modelcontextprotocol/server-github@1.0.0"],
        "gh-pinned",
    )
    result = matcher.match_static_config(config)
    assert result.matched is True
    assert result.package_name == "@modelcontextprotocol/server-github"
    assert result.matched_version == "1.0.0"
    assert result.confidence_score == pytest.approx(PINNED_CONFIDENCE)

    assert not _unpinned(auditor.audit_server(config).findings)
    calls = _FakeVulnerabilityEngine.calls
    assert ("@modelcontextprotocol/server-github", "1.0.0") in calls


def _write_cli_config(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "mcp-remote-pinned": {
                        "command": "npx",
                        "args": [
                            "-y",
                            "mcp-remote@0.1.15",
                            "https://remote.example.com/sse",
                        ],
                    },
                    "mcp-remote-unpinned": {
                        "command": "npx",
                        "args": [
                            "-y",
                            "mcp-remote",
                            "https://remote.example.com/sse",
                        ],
                    },
                }
            }
        ),
        encoding="utf-8",
    )


@pytest.mark.parametrize("fmt", ["terminal", "json", "markdown", "html"])
def test_cli_scan_reports_unpinned_package(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    auditor: ConsolidatedSecurityAuditor,
    fmt: str,
) -> None:
    config_path = tmp_path / "mcp.json"
    _write_cli_config(config_path)

    exit_code = cli.main(["scan", "--config-file", str(config_path), "--format", fmt])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert UNPINNED_RULE in out
    assert "VULN-CVE-2025-6514" in out

    if fmt == "json":
        report = json.loads(out)
        unpinned = [
            f for f in report["findings"] if f["rule_id"] == UNPINNED_RULE
        ]
        assert len(unpinned) == 1
        assert unpinned[0]["severity"] == "MEDIUM"
        assert unpinned[0]["remediation"]
        assert "0.1.15" not in unpinned[0]["message"]


def test_cli_fail_on_findings_for_unpinned_package(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    auditor: ConsolidatedSecurityAuditor,
) -> None:
    config_path = tmp_path / "mcp.json"
    _write_cli_config(config_path)

    exit_code = cli.main(
        [
            "scan",
            "--config-file",
            str(config_path),
            "--format",
            "json",
            "--fail-on-findings",
        ]
    )
    capsys.readouterr()
    assert exit_code == 1
