"""Security scan MCP tool handlers."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("verity.mcp_server.tools")


class SecurityScanHandlerMixin:
    """Handlers for verity_security_scan."""

    def _execute_security_scan(self, args: dict[str, Any]) -> dict[str, Any]:
        action = args.get("action", "")
        options = args.get("options") or {}

        if action == "discover_endpoints":
            res = self._discover_mcp_endpoints(options)
            res["action"] = action
            return res

        if action == "scan_client_configs":
            res = self._discover_client_environment(options)
            res["action"] = action
            return res

        if action == "fingerprint_server":
            res = self._fingerprint_mcp_server(options)
            res["action"] = action
            return res

        if action == "lookup_vulnerabilities":
            res = self._lookup_mcp_vulnerabilities(options)
            res["action"] = action
            return res

        if action == "full_audit":
            return self._full_audit_pipeline(options)

        if action == "scan_ast_code":
            from verity.scanner import McpAstScannerEngine, ScannerSeverity

            target_path = options.get("path") or "."
            min_sev_str = options.get("min_severity", "INFO")
            min_sev = ScannerSeverity(min_sev_str)
            scanner = McpAstScannerEngine(min_severity=min_sev)
            report = scanner.scan_path(target_path)
            res = report.to_dict()
            res["ok"] = True
            res["action"] = action
            return res

        if action == "call_target_tool":
            res = self._call_target_tool(options)
            res["action"] = action
            return res

        return {
            "ok": False,
            "error": f"Unsupported action '{action}' for verity_security_scan",
        }

    def _full_audit_pipeline(self, options: dict[str, Any]) -> dict[str, Any]:
        """Execute full discovery -> fingerprinting -> vulnerability lookup in 1 turn."""
        discovery_res = self._discover_mcp_endpoints(options)
        if not discovery_res.get("ok"):
            return {
                "ok": False,
                "action": "full_audit",
                "error": f"Discovery failed: {discovery_res.get('error')}",
            }

        tools = discovery_res.get("tools", [])
        prompts = discovery_res.get("prompts", [])
        resources = discovery_res.get("resources", [])
        name_hint = options.get("name_hint") or options.get("command")

        fp_res = self._fingerprint_mcp_server(
            {"tools": tools, "prompts": prompts, "resources": resources, "name_hint": name_hint}
        )
        pkg_name = fp_res.get("package_name")
        version = fp_res.get("matched_version")

        vuln_res = (
            self._lookup_mcp_vulnerabilities({"package_name": pkg_name, "version": version})
            if pkg_name
            else {"is_vulnerable": False, "findings": []}
        )

        findings = list(vuln_res.get("findings", []))
        audit_mode = "KNOWN_PASSPORT" if (pkg_name and findings) else "UNKNOWN_CAPABILITY_PROFILING"
        recommended_checks = []

        if not findings and tools:
            try:
                from verity.ucp.engine import UnknownCapabilityProfiler

                server_id = name_hint or options.get("url") or "custom-mcp-target"
                audit_plan = UnknownCapabilityProfiler.build_unknown_audit_plan(
                    server_id=server_id,
                    tools=tools,
                )
                for h in audit_plan.hypotheses:
                    cvss = 9.0 if h.severity == "CRITICAL" else (7.5 if h.severity == "HIGH" else 5.0)
                    findings.append(
                        {
                            "advisory_id": h.cwe_id,
                            "aliases": [h.name],
                            "summary": f"{h.name} on tool '{h.affected_tool}': {h.rationale}",
                            "severity": h.severity,
                            "cvss_score": cvss,
                            "cwes": [h.cwe_id],
                            "vulnerable_tools": [h.affected_tool],
                            "affected_parameters": list(h.affected_parameters),
                            "confidence": h.confidence,
                            "suggested_check": h.suggested_check_file,
                            "type": "CAPABILITY_RISK_HYPOTHESIS",
                        }
                    )
                recommended_checks = list(audit_plan.recommended_checks)
            except Exception:
                pass

        target_str = (
            f"{pkg_name}@{version}"
            if (pkg_name and version)
            else (name_hint or options.get("url") or "unknown-custom-target")
        )
        remediation = vuln_res.get("remediation_guidance")
        if not remediation and audit_mode == "UNKNOWN_CAPABILITY_PROFILING" and findings:
            remediation = (
                "Empirical validation recommended: probe hypothesized CWEs using "
                "verity_security_scan(call_target_tool) and corroborate canary evidence "
                "with verity_database_oracle(check_canary_proof)."
            )

        return {
            "ok": True,
            "action": "full_audit",
            "target": target_str,
            "audit_mode": audit_mode,
            "fingerprint": fp_res,
            "is_vulnerable": len(findings) > 0,
            "findings_count": len(findings),
            "findings": findings,
            "recommended_checks": recommended_checks,
            "remediation_guidance": remediation,
        }

    def _call_target_tool(self, options: dict[str, Any]) -> dict[str, Any]:
        """Invoke a tool on a remote target MCP server via HTTP/SSE, capturing telemetry."""
        import json
        import ssl
        import urllib.error
        import urllib.request

        url = options.get("url")
        tool_name = options.get("tool") or options.get("tool_name")
        arguments = options.get("arguments") or options.get("params") or {}
        timeout = float(options.get("timeout_seconds", 10.0))

        if not url:
            return {
                "ok": False,
                "error": "Missing required 'url' parameter for call_target_tool",
            }
        if not tool_name:
            return {
                "ok": False,
                "error": "Missing required 'tool' parameter for call_target_tool",
            }

        candidate_urls = [url]
        if url.endswith("/sse"):
            candidate_urls.append(url[:-4])
        elif url.endswith("/sse/"):
            candidate_urls.append(url[:-5])

        expanded_candidates = []
        for u in candidate_urls:
            expanded_candidates.append(u)
            if "localhost" in u or "127.0.0.1" in u:
                c_mock = u.replace("localhost", "mock-mcp-targets").replace(
                    "127.0.0.1", "mock-mcp-targets"
                )
                if c_mock not in expanded_candidates:
                    expanded_candidates.append(c_mock)
                c_host = u.replace("localhost", "host.docker.internal").replace(
                    "127.0.0.1", "host.docker.internal"
                )
                if c_host not in expanded_candidates:
                    expanded_candidates.append(c_host)

        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
        }
        post_data = json.dumps(payload).encode("utf-8")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        last_error = None
        for candidate in expanded_candidates:
            req = urllib.request.Request(
                candidate,
                data=post_data,
                headers={
                    "User-Agent": "VerityAuditorProxy/1.0",
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                },
            )
            try:
                with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
                    body = resp.read().decode("utf-8", errors="replace")
                    try:
                        resp_json = json.loads(body)
                    except Exception:
                        resp_json = {"raw_text": body}

                    result_obj = resp_json.get("result", resp_json)
                    is_error = False
                    parsed_output = None

                    if isinstance(result_obj, dict):
                        is_error = bool(result_obj.get("isError", False) or "error" in resp_json)
                        content_list = result_obj.get("content", [])
                        if isinstance(content_list, list) and content_list:
                            first_item = content_list[0]
                            if isinstance(first_item, dict) and "text" in first_item:
                                text_val = first_item["text"]
                                try:
                                    parsed_output = json.loads(text_val)
                                except Exception:
                                    parsed_output = text_val
                    elif "error" in resp_json:
                        is_error = True

                    return {
                        "ok": not is_error,
                        "tool": tool_name,
                        "url": candidate,
                        "result": parsed_output if parsed_output is not None else result_obj,
                        "is_error": is_error,
                        "raw_response": resp_json,
                    }
            except Exception as exc:
                last_error = str(exc)
                continue

        return {
            "ok": False,
            "tool": tool_name,
            "url": url,
            "error": f"Failed to invoke tool '{tool_name}' on {url}: {last_error}",
        }

    # =========================================================================
    # Unified Tool 2: verity_database_guard
    # =========================================================================
