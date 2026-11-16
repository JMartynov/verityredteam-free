"""Legacy atomic MCP tool handlers."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from verity.discovery.active_bridge import ActiveExploitBridge
from verity.discovery.config_scanner import MultiClientConfigScanner
from verity.discovery.models import (
    ClientType,
    DiscoveredServerConfig,
    FindingSeverity,
    SecurityAuditFinding,
    ServerAuditRecord,
    TransportType,
)
from verity.discovery.transports.sse import HttpSseDiscoveryTransport
from verity.discovery.transports.stdio import StdioDiscoveryTransport

logger = logging.getLogger("verity.mcp_server.tools")


class LegacyToolsHandlerMixin:
    """Handlers for legacy atomic MCP tools."""

    def _discover_mcp_endpoints(self, args: dict[str, Any]) -> dict[str, Any]:
        transport_type_str = args.get("transport", "stdio").lower()
        timeout = float(args.get("timeout_seconds", 5.0))

        if transport_type_str == "stdio":
            cmd = args.get("command")
            if not cmd:
                return {"ok": False, "error": "Missing 'command' parameter for stdio transport"}
            cmd_args = args.get("args") or []
            cfg = DiscoveredServerConfig(
                client_type=ClientType.WORKSPACE,
                server_name="dynamic-probe",
                command=cmd,
                args=cmd_args,
                transport_type=TransportType.STDIO,
            )
            transport = StdioDiscoveryTransport(timeout_seconds=timeout)
            cap = transport.inspect(cfg)
            return {
                "ok": True,
                "is_responsive": cap.is_responsive,
                "transport": "stdio",
                "tools_count": len(cap.tools),
                "tools": list(cap.tools),
                "prompts_count": len(cap.prompts),
                "prompts": list(cap.prompts),
                "resources_count": len(cap.resources),
                "resources": list(cap.resources),
                "error_message": cap.error_message,
            }

        if transport_type_str in ("sse", "http"):
            url = args.get("url")
            if not url:
                return {"ok": False, "error": "Missing 'url' parameter for SSE/HTTP transport"}
            cfg = DiscoveredServerConfig(
                client_type=ClientType.WORKSPACE,
                server_name="dynamic-probe",
                url=url,
                transport_type=TransportType.SSE,
            )
            transport = HttpSseDiscoveryTransport(timeout_seconds=timeout)
            cap = transport.inspect(cfg)
            return {
                "ok": True,
                "is_responsive": cap.is_responsive,
                "transport": "sse",
                "tools_count": len(cap.tools),
                "tools": list(cap.tools),
                "prompts_count": len(cap.prompts),
                "prompts": list(cap.prompts),
                "resources_count": len(cap.resources),
                "resources": list(cap.resources),
                "error_message": cap.error_message,
            }

        return {"ok": False, "error": f"Unsupported transport: {transport_type_str}"}

    def _discover_client_environment(self, args: dict[str, Any]) -> dict[str, Any]:
        sandbox_root = args.get("sandbox_root")
        clients_input = args.get("clients")
        custom_paths = list(args.get("custom_paths") or [])

        # If sandbox_root is provided, also auto-discover top-level and nested configs
        if sandbox_root:
            sb = Path(sandbox_root)
            if sb.is_dir():
                for ext in ("*.json", "*.yaml", "*.yml"):
                    for cp in sb.glob(ext):
                        if cp.is_file() and str(cp.resolve()) not in custom_paths:
                            custom_paths.append(str(cp.resolve()))

        target_clients = None
        if clients_input:
            target_clients = [
                ClientType(c) for c in clients_input if c in ClientType._value2member_map_
            ]

        servers, scanned_files = MultiClientConfigScanner.scan_all(
            target_clients=target_clients,
            sandbox_root=sandbox_root,
            custom_paths=custom_paths or None,
        )

        detected_secrets = []
        for s in servers:
            for k, v in s.env.items():
                if any(sec in k.upper() for sec in ("KEY", "SECRET", "TOKEN", "PASSWORD", "AUTH")) or MultiClientConfigScanner.SECRET_VALUE_PATTERNS.search(str(v)):
                    detected_secrets.append(
                        {
                            "server_name": s.server_name,
                            "client_type": s.client_type.value,
                            "env_key": k,
                            "detected_token": str(v),
                            "finding": "Plaintext secret detected in client configuration",
                        }
                    )

        return {
            "ok": True,
            "scanned_files": scanned_files,
            "servers_discovered_count": len(servers),
            "servers": [s.to_dict() for s in servers],
            "detected_secrets": detected_secrets,
        }

    def _fingerprint_mcp_server(self, args: dict[str, Any]) -> dict[str, Any]:
        tools = args.get("tools") or []
        prompts = args.get("prompts")
        resources = args.get("resources")
        name_hint = args.get("name_hint")

        result = self.context.matcher.match(
            tools=tools,
            prompts=prompts,
            resources=resources,
            server_name_hint=name_hint,
        )
        fp_dict = {
            "ok": True,
            "matched": result.matched,
            "package_name": result.package_name,
            "matched_version": result.matched_version,
            "purl": result.purl,
            "confidence_score": result.confidence_score,
            "match_layer": result.match_layer,
            "layer1_exact_match": result.layer1_exact_match,
            "matched_tool_count": result.matched_tool_count,
            "total_observed_tools": result.total_observed_tools,
        }
        if not result.matched and tools:
            try:
                from verity.ucp.engine import UnknownCapabilityProfiler

                audit_plan = UnknownCapabilityProfiler.build_unknown_audit_plan(
                    server_id=name_hint or "custom-mcp-target",
                    tools=tools,
                )
                fp_dict["unknown_capability_profile"] = {
                    "audit_plan_id": audit_plan.server_id,
                    "hypotheses_count": len(audit_plan.hypotheses),
                    "hypotheses": [
                        {
                            "cwe_id": h.cwe_id,
                            "name": h.name,
                            "severity": h.severity,
                            "confidence": h.confidence,
                            "affected_tool": h.affected_tool,
                            "suggested_check": h.suggested_check_file,
                            "rationale": h.rationale,
                        }
                        for h in audit_plan.hypotheses
                    ],
                    "recommended_checks": list(audit_plan.recommended_checks),
                }
            except Exception:
                pass
        return fp_dict

    def _lookup_mcp_vulnerabilities(self, args: dict[str, Any]) -> dict[str, Any]:
        target = args.get("purl") or args.get("package_name") or ""
        version = args.get("version")

        if not target:
            return {"ok": False, "error": "Must provide 'package_name' or 'purl'"}

        res = self.context.vuln_engine.query(target, version=version)
        findings = []
        for m in res.vulnerabilities:
            findings.append(
                {
                    "advisory_id": m.vulnerability_id,
                    "aliases": list(m.aliases),
                    "summary": m.summary,
                    "severity": m.severity,
                    "cvss_score": m.cvss_score,
                    "cwes": list(m.cwe_ids),
                    "vulnerable_tools": list(m.vulnerable_tools),
                    "fixed_version": m.fixed,
                }
            )

        action_summary = res.upgrade_advice.action_summary if res.upgrade_advice else None

        return {
            "ok": True,
            "is_vulnerable": res.is_vulnerable,
            "package_name": res.package_name,
            "evaluated_version": res.queried_version,
            "matches_count": len(findings),
            "findings": findings,
            "max_cvss_score": res.max_cvss_score,
            "max_severity": res.max_severity,
            "remediation_guidance": action_summary,
        }

    def _audit_and_generate_exploit_plan(self, args: dict[str, Any]) -> dict[str, Any]:
        pkg = args.get("package_name", "")
        ver = args.get("version", "")
        cve_id = args.get("cve_id")

        vuln_res = self.context.vuln_engine.query(pkg, version=ver)
        if not vuln_res.is_vulnerable:
            return {
                "ok": True,
                "has_exploit_plan": False,
                "message": f"No active vulnerabilities on {pkg}@{ver}. Target is clean.",
                "plans": [],
            }

        findings_list = []
        for m in vuln_res.vulnerabilities:
            if cve_id and cve_id not in m.vulnerability_id and cve_id not in m.aliases:
                continue
            findings_list.append(
                SecurityAuditFinding(
                    issue_id=m.vulnerability_id,
                    title=m.summary,
                    description=m.details or m.summary,
                    server_name=pkg,
                    client_type=ClientType.WORKSPACE,
                    severity=FindingSeverity(
                        m.severity.upper()
                        if m.severity.upper() in FindingSeverity._value2member_map_
                        else "HIGH"
                    ),
                    cve_id=m.aliases[0] if m.aliases else m.vulnerability_id,
                    cvss_score=m.cvss_score,
                    remediation=m.fixed or "Upgrade package",
                    cwe_ids=m.cwe_ids,
                    vulnerable_tools=m.vulnerable_tools,
                )
            )

        record = ServerAuditRecord(
            server_name=pkg,
            client_type=ClientType.WORKSPACE,
            config_path="",
            matched_package=pkg,
            matched_version=ver,
            matched_purl=f"pkg:npm/{pkg}@{ver}",
            findings=tuple(findings_list),
        )

        plans = ActiveExploitBridge.generate_plans_for_record(record)
        return {
            "ok": True,
            "has_exploit_plan": len(plans) > 0,
            "plans_count": len(plans),
            "plans": [p.to_dict() for p in plans],
        }
