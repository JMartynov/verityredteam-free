"""Security scan MCP tool handlers."""

from __future__ import annotations

import contextlib
import json
import logging
from pathlib import Path
from typing import Any

from verity.baseline import (
    BaselineSchemaError,
    PolicyValidationError,
    apply_inline_suppressions,
    apply_policy_suppressions,
    assign_fingerprints,
    diff_baseline,
    load_baseline,
    load_policy_config,
    resolve_project_root,
)

logger = logging.getLogger("verity.mcp_server.tools")

_SECRET_RULE_ID = "SEC-STATIC-SECRET-IN-CONFIG"


def _suppressed_counts(suppressed: list[dict[str, Any]]) -> dict[str, int]:
    """Bucket suppressed findings by their ``suppression.source``."""
    counts: dict[str, int] = {
        "total": len(suppressed),
        "baseline": 0,
        "ignore_file": 0,
        "policy": 0,
        "inline": 0,
        "other": 0,
    }
    for finding in suppressed:
        suppression = finding.get("suppression")
        source = str((suppression or {}).get("source") or "")
        if source in counts and source != "total":
            counts[source] += 1
        else:
            counts["other"] += 1
    return counts


def _load_sources(
    findings: list[dict[str, Any]], project_root: Path | None
) -> tuple[dict[str, str], dict[str, list[str]]]:
    sources: dict[str, str] = {}
    lines_cache: dict[str, list[str]] = {}
    for finding in findings:
        file_path = finding.get("file_path")
        if not file_path:
            continue
        candidates = [Path(str(file_path))]
        if project_root is not None:
            candidates.append(Path(project_root) / str(file_path))
        for candidate in candidates:
            try:
                if not candidate.is_file():
                    continue
                text = candidate.read_text(encoding="utf-8")
            except OSError:
                continue
            sources[str(file_path)] = text
            sources[str(candidate)] = text
            lines_cache[str(file_path)] = text.splitlines()
            lines_cache[str(candidate)] = text.splitlines()
            break
    return sources, lines_cache


class SecurityScanHandlerMixin:
    """Handlers for verity_security_scan."""

    def _augment_findings(
        self,
        findings: list[dict[str, Any]],
        options: dict[str, Any],
        project_root: Path | None,
    ) -> tuple[
        list[dict[str, Any]],
        list[dict[str, Any]],
        dict[str, int],
        int | None,
        int | None,
        int,
        bool,
    ]:
        """Fingerprint findings, apply suppressions, diff against baseline, and scrub private keys."""
        assign_fingerprints(
            findings, project_root=project_root, home_dir=Path.home()
        )

        respect = bool(options.get("respect_ignores", True))
        if respect:
            sources, lines_cache = _load_sources(findings, project_root)
            try:
                policy = load_policy_config(project_root or Path.cwd())
            except (PolicyValidationError, FileNotFoundError):
                policy = None
            if policy is not None and (policy.ignores or policy.allowlists):
                apply_policy_suppressions(
                    findings, policy, source_lines_cache=lines_cache
                )
            if sources:
                with contextlib.suppress(PolicyValidationError):
                    apply_inline_suppressions(
                        findings, sources, respect_inline_ignores=True
                    )

        suppressed = [f for f in findings if "suppression" in f]
        active = [f for f in findings if "suppression" not in f]
        counts = _suppressed_counts(suppressed)

        new_count: int | None = None
        baseline_count: int | None = None
        resolved = 0
        baseline_path = options.get("baseline_path")
        if baseline_path:
            baseline_data = None
            try:
                baseline_data = load_baseline(baseline_path)
            except (FileNotFoundError, BaselineSchemaError):
                baseline_data = None
            if baseline_data is not None:
                diff = diff_baseline(list(active), baseline_data)
                active = diff.new_findings
                suppressed.extend(diff.baseline_findings)
                counts = _suppressed_counts(suppressed)
                new_count = len(diff.new_findings)
                baseline_count = len(diff.baseline_findings)
                resolved = diff.resolved_since_baseline

        gate_passed = True
        if bool(options.get("fail_on_new")) and (new_count or 0) > 0:
            gate_passed = False

        # Never leak private bookkeeping (e.g. ``_raw_secret``) to callers.
        for finding in [*active, *suppressed]:
            for key in [k for k in finding if k.startswith("_")]:
                del finding[key]

        return active, suppressed, counts, new_count, baseline_count, resolved, gate_passed

    def _execute_security_scan(self, args: dict[str, Any]) -> dict[str, Any]:
        action = args.get("action", "")
        options = args.get("options") or {}

        if action == "discover_endpoints":
            res = self._discover_mcp_endpoints(options)
            res["action"] = action
            return res

        if action == "scan_client_configs":
            res = self._discover_client_environment(options)
            project_root: Path | None = None
            sandbox_root = options.get("sandbox_root")
            if sandbox_root:
                try:
                    project_root = resolve_project_root([sandbox_root])
                except Exception:
                    project_root = Path(sandbox_root)
            findings: list[dict[str, Any]] = []
            for item in res.get("detected_secrets", []) or []:
                if not isinstance(item, dict):
                    continue
                findings.append(
                    {
                        "rule_id": _SECRET_RULE_ID,
                        "severity": "HIGH",
                        "message": str(
                            item.get("finding") or "Plaintext secret detected"
                        ),
                        "file_path": str(item.get("client_type") or ""),
                        "server_name": str(item.get("server_name") or ""),
                        "env_key": str(item.get("env_key") or ""),
                        "_raw_secret": str(item.get("detected_token") or ""),
                        "category": "SECRET",
                    }
                )
            (
                active,
                suppressed,
                counts,
                new_count,
                baseline_count,
                resolved,
                gate_passed,
            ) = self._augment_findings(findings, options, project_root)
            res["findings"] = active
            if suppressed:
                res["suppressed_findings"] = suppressed
            summary = res.setdefault("summary", {})
            summary["suppressed_counts"] = counts
            res["gate_passed"] = gate_passed
            if new_count is not None:
                res["new_findings"] = new_count
                res["baseline_findings"] = baseline_count or 0
                res["resolved_since_baseline"] = resolved
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
            from verity.baseline import load_ignore_spec
            from verity.scanner import McpAstScannerEngine, ScannerSeverity

            target_path = options.get("path") or "."
            min_sev_str = options.get("min_severity", "INFO")
            min_sev = ScannerSeverity(min_sev_str)
            project_root = resolve_project_root([target_path])
            respect = bool(options.get("respect_ignores", True))
            ignore_matcher = (
                load_ignore_spec(project_root) if respect else None
            )
            scanner = McpAstScannerEngine(min_severity=min_sev)
            report = scanner.scan_path(
                target_path, project_root=project_root, ignore_matcher=ignore_matcher
            )
            res = report.to_dict()
            findings = [dict(item) for item in res.get("findings", []) or []]
            (
                active,
                suppressed,
                counts,
                new_count,
                baseline_count,
                resolved,
                gate_passed,
            ) = self._augment_findings(findings, options, project_root)
            res["findings"] = active
            if suppressed:
                res["suppressed_findings"] = suppressed
            summary = res.setdefault("summary", {})
            summary["total_findings"] = len(active)
            summary["suppressed_counts"] = counts
            res["suppressed_counts"] = counts
            if new_count is not None:
                res["new_findings"] = new_count
                res["baseline_findings"] = baseline_count or 0
                res["resolved_since_baseline"] = resolved
                summary["new_findings"] = new_count
                summary["baseline_findings"] = baseline_count or 0
                summary["resolved_since_baseline"] = resolved
            res["gate_passed"] = gate_passed
            res["ok"] = True
            res["action"] = action
            return res

        if action == "call_target_tool":
            res = self._call_target_tool(options)
            res["action"] = action
            return res

        if action in ("detect_rug_pull", "snapshot_baseline"):
            return self._execute_rug_pull_action(action, options)

        return {
            "ok": False,
            "error": f"Unsupported action '{action}' for verity_security_scan",
        }

    def _resolve_scan_tools(
        self, options: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
        if "tools" in options and options["tools"] is not None:
            tools = options["tools"]
            if not isinstance(tools, list):
                return [], {
                    "ok": False,
                    "error": "options['tools'] must be a list of tool definitions.",
                }
            return [t for t in tools if isinstance(t, dict)], None

        if options.get("command") or options.get("url"):
            discovery = self._discover_mcp_endpoints(options)
            if not discovery.get("ok") or not discovery.get("is_responsive", True):
                return [], {
                    "ok": False,
                    "error": (
                        discovery.get("error")
                        or discovery.get("error_message")
                        or "Target MCP server is not responsive"
                    ),
                }
            return [t for t in discovery.get("tools", []) if isinstance(t, dict)], None

        return [], None

    def _execute_rug_pull_action(
        self, action: str, options: dict[str, Any]
    ) -> dict[str, Any]:
        from verity.ucp.engine import UnknownCapabilityProfiler

        tools, discovery_error = self._resolve_scan_tools(options)
        if discovery_error is not None:
            discovery_error["action"] = action
            return discovery_error

        profiles = UnknownCapabilityProfiler.profile_toolset(tools)
        current_hashes = {name: p.canonical_hash for name, p in profiles.items()}

        baseline_path = options.get("baseline_path")
        save_baseline = bool(options.get("save_baseline")) or action == "snapshot_baseline"

        if save_baseline:
            saved_path = baseline_path
            if baseline_path:
                path = Path(baseline_path)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    json.dumps(current_hashes, indent=2, sort_keys=True),
                    encoding="utf-8",
                )
                saved_path = str(path)
            return {
                "ok": True,
                "action": action,
                "baseline_saved": True,
                "baseline_path": saved_path,
                "rug_pull_detected": False,
                "authorized_hashes": current_hashes,
                "current_hashes": current_hashes,
                "drift_findings": [],
            }

        authorized_hashes = options.get("authorized_hashes")
        if authorized_hashes is not None:
            if not isinstance(authorized_hashes, dict):
                return {
                    "ok": False,
                    "action": action,
                    "error": (
                        "options['authorized_hashes'] must be a dictionary "
                        "mapping tool names to SHA-256 hashes."
                    ),
                }
            for key, value in authorized_hashes.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    return {
                        "ok": False,
                        "action": action,
                        "error": (
                            "options['authorized_hashes'] must map string "
                            "tool names to string SHA-256 hashes."
                        ),
                    }

        if authorized_hashes is None:
            if not baseline_path:
                return {
                    "ok": False,
                    "action": action,
                    "error": (
                        "Either 'authorized_hashes' or 'baseline_path' must be "
                        "provided for rug-pull detection."
                    ),
                }
            try:
                raw = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
            except Exception as exc:
                return {
                    "ok": False,
                    "action": action,
                    "error": f"Failed to load baseline file '{baseline_path}': {exc}",
                }
            if not isinstance(raw, dict):
                return {
                    "ok": False,
                    "action": action,
                    "error": (
                        f"Baseline file '{baseline_path}' must contain a JSON "
                        "object mapping tool names to hashes."
                    ),
                }
            for key, value in raw.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    return {
                        "ok": False,
                        "action": action,
                        "error": (
                            f"Baseline file '{baseline_path}' must map string "
                            "tool names to string SHA-256 hashes."
                        ),
                    }
            authorized_hashes = raw

        results = UnknownCapabilityProfiler.detect_rug_pull(
            authorized_hashes=authorized_hashes,
            current_tools=tools,
        )

        drift_findings: list[dict[str, Any]] = []
        for r in results:
            if not r.is_rug_pull:
                continue
            if "unauthorized_tool_injected" in r.changed_fields:
                change_type = "ADDED"
            elif "tool_removed" in r.changed_fields:
                change_type = "REMOVED"
            else:
                change_type = "MUTATED"
            drift_findings.append(
                {
                    "tool_name": r.tool_name,
                    "change_type": change_type,
                    "authorized_hash": r.authorized_hash,
                    "current_hash": r.current_hash,
                    "changed_fields": list(r.changed_fields),
                    "details": r.details,
                    "is_rug_pull": True,
                }
            )

        return {
            "ok": True,
            "action": action,
            "rug_pull_detected": len(drift_findings) > 0,
            "authorized_hashes": authorized_hashes,
            "current_hashes": current_hashes,
            "drift_findings": drift_findings,
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

        result: dict[str, Any] = {
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

        project_root: Path | None = None
        try:
            project_root = resolve_project_root([options.get("path") or ".", "."])
        except Exception:
            project_root = Path.cwd()
        audit_findings = list(result.get("findings", []) or [])
        (
            active,
            suppressed,
            counts,
            new_count,
            baseline_count,
            resolved,
            gate_passed,
        ) = self._augment_findings(audit_findings, options, project_root)
        result["findings"] = active
        result["findings_count"] = len(active)
        result["is_vulnerable"] = len(active) > 0
        if suppressed:
            result["suppressed_findings"] = suppressed
        summary = result.setdefault("summary", {})
        summary["suppressed_counts"] = counts
        result["gate_passed"] = gate_passed
        if new_count is not None:
            result["new_findings"] = new_count
            result["baseline_findings"] = baseline_count or 0
            result["resolved_since_baseline"] = resolved
        return result

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
