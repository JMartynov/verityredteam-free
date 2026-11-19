"""Consolidated Security Audit Service generating Markdown, JSON, and SARIF reports."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from verity.discovery.config_scanner import MultiClientConfigScanner
from verity.discovery.matcher import HybridDiscoveryMatcher
from verity.discovery.models import (
    ClientType,
    ConsolidatedAuditReport,
    DiscoveredServerConfig,
    FindingSeverity,
    LiveServerCapability,
    SecurityAuditFinding,
    ServerAuditRecord,
)
from verity.discovery.transports.base import BaseDiscoveryTransport
from verity.discovery.transports.stdio import StdioDiscoveryTransport
from verity.lookup.engine import VulnerabilityLookupEngine

logger = logging.getLogger("verity.discovery.auditor")


class ConsolidatedSecurityAuditor:
    """Orchestrates configuration discovery, live probing, and audit report generation."""

    def __init__(
        self,
        fingerprint_dir: str | Path = "data/fingerprints",
        vuln_dir: str | Path = "data/vulnerabilities",
        transport: BaseDiscoveryTransport | None = None,
    ) -> None:
        self.fingerprint_dir = Path(fingerprint_dir)
        self.vuln_dir = Path(vuln_dir)
        self.matcher = HybridDiscoveryMatcher(self.fingerprint_dir)
        self.vuln_engine = VulnerabilityLookupEngine.from_auto(self.vuln_dir)
        self.transport = transport or StdioDiscoveryTransport(timeout_seconds=5.0)

    def audit_server(
        self,
        config: DiscoveredServerConfig,
        live_probe: bool = False,
    ) -> ServerAuditRecord:
        """Perform complete security assessment of a single discovered MCP server."""
        findings: list[SecurityAuditFinding] = []

        raw_env: dict[str, Any] = {}
        if isinstance(config.raw_config, dict):
            candidate_env = config.raw_config.get("env")
            if isinstance(candidate_env, dict):
                raw_env = candidate_env

        # 1. Static Configuration Findings (Hardcoded Secrets & Unsafe Shells)
        for k, v in config.env.items():
            raw_value = raw_env.get(k, v)
            raw_text = str(raw_value) if raw_value is not None else ""
            is_env_reference = raw_text.startswith("${") or raw_text.startswith("$")
            if (
                not is_env_reference
                and MultiClientConfigScanner.SECRET_KEY_PATTERNS.search(k)
                and v
            ):
                findings.append(
                    SecurityAuditFinding(
                        issue_id="SEC-STATIC-SECRET-IN-CONFIG",
                        severity=FindingSeverity.HIGH,
                        title=f"Plaintext Secret in Configuration: {k}",
                        description=f"Env variable '{k}' contains unredacted credential.",
                        server_name=config.server_name,
                        client_type=config.client_type,
                        config_path=config.config_path,
                        remediation=f"Replace hardcoded value with reference '${{{k}}}'.",
                        redacted_evidence=f"{k}=****",
                    )
                )

        if config.command and config.command.lower() in ("sh", "bash", "zsh", "cmd", "powershell"):
            findings.append(
                SecurityAuditFinding(
                    issue_id="SEC-STATIC-UNSAFE-SHELL-WRAPPER",
                    severity=FindingSeverity.MEDIUM,
                    title="Direct Shell Execution Wrapper",
                    description=(
                        f"Server launched via raw shell interpreter '{config.command}', "
                        "increasing injection risk."
                    ),
                    server_name=config.server_name,
                    client_type=config.client_type,
                    config_path=config.config_path,
                    remediation=("Invoke server binary directly without shell interpreter."),
                    redacted_evidence=f"command: {config.command}",
                )
            )

        # 2. Capability Probing & Fingerprint Matching
        live_cap: LiveServerCapability | None = None
        matched_pkg = None
        matched_purl = None
        matched_ver = None
        confidence = 0.0
        match_layer = "NONE"
        tools_exposed: list[str] = []

        if live_probe and config.command and not config.is_disabled:
            live_cap = self.transport.inspect(config)
            if live_cap.is_responsive and live_cap.tools:
                tools_exposed = [t.get("name", "") for t in live_cap.tools if isinstance(t, dict)]
                match_res = self.matcher.match_live_capability(live_cap, config)
                if match_res.matched:
                    matched_pkg = match_res.package_name
                    matched_purl = match_res.purl
                    matched_ver = match_res.matched_version
                    confidence = match_res.confidence_score
                    match_layer = match_res.match_layer

        static_match = self.matcher.match_static_config(config)
        if not matched_pkg:
            if static_match.matched:
                matched_pkg = static_match.package_name
                matched_purl = static_match.purl
                matched_ver = static_match.matched_version
                confidence = static_match.confidence_score
        elif (
            static_match.matched
            and static_match.matched_version
            and match_layer != "LAYER_1_EXACT"
        ):
            matched_ver = static_match.matched_version


        # 3. Correlate with OSV Vulnerability Database
        if matched_pkg and self.vuln_engine:
            lookup_res = self.vuln_engine.query(identifier=matched_pkg, version=matched_ver)
            if lookup_res.vulnerabilities:
                for v in lookup_res.vulnerabilities:
                    vuln_tools = tuple(v.vulnerable_tools)
                    cwe_tup = tuple(v.cwe_ids)
                    sev = FindingSeverity.HIGH
                    if v.cvss_score:
                        if v.cvss_score >= 9.0:
                            sev = FindingSeverity.CRITICAL
                        elif v.cvss_score >= 7.0:
                            sev = FindingSeverity.HIGH
                        elif v.cvss_score >= 4.0:
                            sev = FindingSeverity.MEDIUM
                        else:
                            sev = FindingSeverity.LOW

                    findings.append(
                        SecurityAuditFinding(
                            issue_id=f"VULN-{v.vulnerability_id}",
                            severity=sev,
                            title=f"Known Vulnerability: {v.summary or v.vulnerability_id}",
                            description=v.details or "",
                            server_name=config.server_name,
                            client_type=config.client_type,
                            config_path=config.config_path,
                            cve_id=v.vulnerability_id
                            if v.vulnerability_id.startswith("CVE-")
                            else None,
                            cwe_ids=cwe_tup,
                            cvss_score=v.cvss_score,
                            vulnerable_tools=vuln_tools,
                            remediation="Upgrade to fixed version or apply sandbox.",
                            redacted_evidence=(
                                f"Matched version {matched_ver} in advisory {v.vulnerability_id}"
                            ),
                        )
                    )

        # Compute highest severity
        highest = FindingSeverity.INFO
        sev_order = [
            FindingSeverity.INFO,
            FindingSeverity.LOW,
            FindingSeverity.MEDIUM,
            FindingSeverity.HIGH,
            FindingSeverity.CRITICAL,
        ]
        for f in findings:
            if sev_order.index(f.severity) > sev_order.index(highest):
                highest = f.severity

        return ServerAuditRecord(
            server_name=config.server_name,
            client_type=config.client_type,
            config_path=config.config_path,
            matched_package=matched_pkg,
            matched_purl=matched_purl,
            matched_version=matched_ver,
            confidence_score=confidence,
            match_layer=match_layer,
            is_live_inspected=bool(live_cap and live_cap.is_responsive),
            tools_exposed=tuple(tools_exposed),
            findings=tuple(findings),
            highest_severity=highest,
        )

    def audit_all(
        self,
        target_clients: list[ClientType] | None = None,
        base_home: str | Path | None = None,
        custom_paths: list[str | Path] | None = None,
        sandbox_root: str | Path | None = None,
        live_probe: bool = False,
    ) -> ConsolidatedAuditReport:
        """Discover and audit all configured MCP servers, isolated to sandbox_root if set."""
        configs, scanned_files = MultiClientConfigScanner.scan_all(
            target_clients=target_clients,
            base_home=base_home,
            custom_paths=custom_paths,
            sandbox_root=sandbox_root,
        )

        records: list[ServerAuditRecord] = []
        crit_c = high_c = med_c = low_c = info_c = 0

        for cfg in configs:
            rec = self.audit_server(cfg, live_probe=live_probe)
            records.append(rec)
            for f in rec.findings:
                if f.severity == FindingSeverity.CRITICAL:
                    crit_c += 1
                elif f.severity == FindingSeverity.HIGH:
                    high_c += 1
                elif f.severity == FindingSeverity.MEDIUM:
                    med_c += 1
                elif f.severity == FindingSeverity.LOW:
                    low_c += 1
                else:
                    info_c += 1

        clients_seen = sorted({c.client_type.value for c in configs})
        return ConsolidatedAuditReport(
            scanned_clients=clients_seen,
            scanned_files=scanned_files,
            servers_discovered=len(configs),
            servers_audited=len(records),
            total_findings=crit_c + high_c + med_c + low_c + info_c,
            critical_count=crit_c,
            high_count=high_c,
            medium_count=med_c,
            low_count=low_c,
            info_count=info_c,
            server_records=records,
        )

    @classmethod
    def render_markdown(cls, report: ConsolidatedAuditReport) -> str:
        """Render consolidated audit report into structured GitHub Flavored Markdown."""
        clients_str = ", ".join(report.scanned_clients) if report.scanned_clients else "None"
        sev_summary = (
            f"🔴 CRIT: {report.critical_count} | "
            f"🟠 HIGH: {report.high_count} | "
            f"🟡 MED: {report.medium_count} | "
            f"🔵 LOW: {report.low_count}"
        )
        lines = [
            "# 🛡️ Universal MCP Client Security Audit Report",
            "",
            "### Executive Summary",
            f"- **Scanned Clients**: {clients_str}",
            f"- **Config Files Analyzed**: {len(report.scanned_files)}",
            f"- **Servers Found**: {report.servers_discovered} (Audited: {report.servers_audited})",
            f"- **Findings**: **{report.total_findings}** ({sev_summary})",
            "",
            "---",
            "",
            "### Discovered MCP Servers & Passports",
            "",
            "| Client | Server Name | Identity | Confidence | Layer | Severity | Findings |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        if not report.server_records:
            lines.append("| - | *No MCP servers discovered* | - | - | - | - | - |")
        else:
            for s in report.server_records:
                ident = (
                    f"`{s.matched_package}@{s.matched_version}`"
                    if s.matched_package
                    else "*Unknown Package*"
                )
                conf_str = f"{int(s.confidence_score * 100)}%" if s.confidence_score else "0%"
                sev_badge = f"**{s.highest_severity.value}**"
                f_count = str(len(s.findings))
                row = (
                    f"| `{s.client_type.value}` | `{s.server_name}` | {ident} | "
                    f"{conf_str} | `{s.match_layer}` | {sev_badge} | {f_count} |"
                )
                lines.append(row)

        if report.total_findings > 0:
            lines.extend(
                [
                    "",
                    "---",
                    "",
                    "### Detailed Security Findings & Remediation Plan",
                    "",
                ]
            )
            for s in report.server_records:
                if not s.findings:
                    continue
                lines.append(f"#### Server: `{s.server_name}` ({s.client_type.value})")
                for f in s.findings:
                    cve_badge = f" (`{f.cve_id}`)" if f.cve_id else ""
                    cvss_badge = f" [CVSS {f.cvss_score}]" if f.cvss_score else ""
                    lines.append(f"- **[{f.severity.value}] {f.title}**{cve_badge}{cvss_badge}")
                    lines.append(f"  - *Description*: {f.description}")
                    if f.remediation:
                        lines.append(f"  - *Remediation*: {f.remediation}")
                    if f.redacted_evidence:
                        lines.append(f"  - *Evidence*: `{f.redacted_evidence}`")
                lines.append("")

        return "\n".join(lines)

    @classmethod
    def render_sarif(cls, report: ConsolidatedAuditReport) -> dict[str, Any]:
        """Convert audit findings into standard SARIF v2.1.0 format."""
        rules: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []
        seen_rules: set[str] = set()

        for s in report.server_records:
            for f in s.findings:
                if f.issue_id not in seen_rules:
                    seen_rules.add(f.issue_id)
                    rules.append(
                        {
                            "id": f.issue_id,
                            "name": f.title,
                            "shortDescription": {"text": f.title},
                            "fullDescription": {"text": f.description},
                            "help": {"text": f.remediation},
                        }
                    )

                sarif_level = (
                    "error"
                    if f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH)
                    else "warning"
                )
                results.append(
                    {
                        "ruleId": f.issue_id,
                        "level": sarif_level,
                        "message": {"text": f"[{s.server_name}] {f.title}: {f.description}"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f.config_path or "mcp_config.json"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                )

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Verity MCP Universal Auditor",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/JMartynov/verityredteam-free",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }
