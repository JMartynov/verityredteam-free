"""Developer-first command line interface for Verity."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import shlex
import sys
from pathlib import Path
from typing import Any

from verity.reporting import (
    render_scan_html,
    render_scan_markdown,
    render_scan_terminal,
    render_test_html,
    render_test_markdown,
    render_test_terminal,
)

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_SEVERITY_RANK = {sev: idx for idx, sev in enumerate(_SEVERITY_ORDER)}

SARIF_MISSING_MESSAGE = (
    "SARIF v2.1.0 compliance export requires the verity-pro plugin."
)


def _iter_plugin_entry_points() -> list[Any]:
    try:
        try:
            eps = importlib.metadata.entry_points(group="verity.plugins")
        except TypeError:  # pragma: no cover - legacy importlib.metadata API
            eps = importlib.metadata.entry_points().get("verity.plugins", [])
        return list(eps or [])
    except Exception:  # pragma: no cover - defensive
        return []


def _pro_plugin_available() -> bool:
    """Return True when the ``verity-pro`` plugin is registered."""
    return bool(_iter_plugin_entry_points())


def _stdlib_sarif_exporter(report: dict[str, Any]) -> dict[str, Any]:
    """Serialize a normalized scan report into SARIF v2.1.0."""
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    seen_rules: set[str] = set()

    for finding in report.get("findings", []) or []:
        rule_id = str(finding.get("rule_id") or "UNKNOWN")
        title = str(finding.get("title") or rule_id)
        message = str(finding.get("message") or "")
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append(
                {
                    "id": rule_id,
                    "name": title,
                    "shortDescription": {"text": title},
                    "fullDescription": {"text": message},
                    "help": {"text": str(finding.get("remediation") or "")},
                }
            )

        severity = str(finding.get("severity") or "INFO").upper()
        if severity in ("CRITICAL", "HIGH"):
            level = "error"
        elif severity in ("LOW", "INFO"):
            level = "note"
        else:
            level = "warning"

        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": f"{title}: {message}".strip()},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": str(finding.get("file_path") or "mcp_config.json")
                            },
                            "region": {"startLine": 1},
                        }
                    }
                ],
            }
        )

    return {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
            "Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Verity MCP Security Scanner",
                        "version": "0.1.0",
                        "informationUri": (
                            "https://github.com/JMartynov/verityredteam-free"
                        ),
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def _load_sarif_exporter() -> Any:
    """Return a SARIF exporter callable from a ``verity.plugins`` entry point."""
    entry_points = _iter_plugin_entry_points()
    for ep in entry_points:
        if getattr(ep, "name", "") in ("sarif", "sarif_export"):
            try:
                return ep.load()
            except Exception:  # pragma: no cover - defensive
                return None

    for ep in entry_points:
        try:
            loaded = ep.load()
        except Exception:
            continue
        for attr in ("export_sarif", "sarif_exporter"):
            candidate = getattr(loaded, attr, None)
            if callable(candidate):
                return candidate

    if _pro_plugin_available():
        return _stdlib_sarif_exporter
    return None


def _print_pro_message(feature: str, message: str) -> None:
    from verity.mcp_server.protocols import pro_feature_required_response

    payload = pro_feature_required_response(feature, message)
    print(payload["message"])


def _field(record: dict[str, Any], *keys: str, default: Any = "") -> Any:
    for key in keys:
        value = record.get(key)
        if value not in (None, ""):
            return value
    return default


def _as_severity(raw: Any) -> str:
    if hasattr(raw, "value"):
        raw = raw.value
    text = str(raw or "INFO").upper()
    return text if text in _SEVERITY_RANK else "INFO"


def _normalize_finding(record: Any) -> dict[str, Any]:
    """Normalize a static/AST finding into the canonical report finding schema."""
    if hasattr(record, "to_dict"):
        data: dict[str, Any] = dict(record.to_dict())
    elif isinstance(record, dict):
        data = dict(record)
    else:  # pragma: no cover - defensive
        data = dict(getattr(record, "__dict__", {}))

    cwe_ids = data.get("cwe_ids")
    if isinstance(cwe_ids, (list, tuple)) and cwe_ids:
        cwe_id = ", ".join(str(c) for c in cwe_ids if c)
    else:
        cwe_id = str(_field(data, "cwe_id", "cve_id"))

    base_message = str(_field(data, "message", "description"))
    evidence = str(_field(data, "redacted_evidence", "evidence"))
    if evidence:
        if not base_message:
            message = evidence
        elif evidence not in base_message:
            message = f"{base_message} ({evidence})"
        else:
            message = base_message
    else:
        message = base_message

    return {
        "rule_id": str(_field(data, "rule_id", "issue_id")),
        "cwe_id": cwe_id,
        "severity": _as_severity(_field(data, "severity")),
        "title": str(_field(data, "title")),
        "message": message,
        "file_path": str(
            _field(data, "file_path", "config_path", "target_name", "server_name")
        ),
        "line_number": _field(data, "line_number", default="-") or "-",
        "remediation": str(_field(data, "remediation")),
    }


def _build_report(
    findings: list[dict[str, Any]],
    scanned_files: list[str] | set[str],
    duration_ms: float = 0.0,
    target_path: str | None = None,
) -> dict[str, Any]:
    severity_counts = {sev: 0 for sev in _SEVERITY_ORDER}
    for finding in findings:
        sev = _as_severity(finding.get("severity"))
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    summary: dict[str, Any] = {
        "scanned_files_count": len(scanned_files),
        "total_findings": len(findings),
        "scan_duration_ms": round(float(duration_ms), 2),
        "error_count": 0,
        "severity_counts": severity_counts,
    }
    if target_path:
        summary["target_path"] = target_path

    return {
        "summary": summary,
        "findings": findings,
        "scanned_files": sorted({str(p) for p in scanned_files}),
    }


def _emit(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")


def _render_scan(report: dict[str, Any], fmt: str) -> str:
    if fmt == "json":
        return json.dumps(report, indent=2)
    if fmt == "markdown":
        return render_scan_markdown(report)
    if fmt == "html":
        return render_scan_html(report)
    return render_scan_terminal(report)


def _render_test(results: list[dict[str, Any]], fmt: str) -> str:
    if fmt == "json":
        return json.dumps(results, indent=2)
    if fmt == "markdown":
        return render_test_markdown(results)
    if fmt == "html":
        return render_test_html(results)
    return render_test_terminal(results)


def _scrub_secrets(finding: dict[str, Any], secrets: list[str]) -> dict[str, Any]:
    """Replace any known plaintext secret values with ``****`` in string fields."""
    if not secrets:
        return finding
    scrubbed: dict[str, Any] = {}
    for key, value in finding.items():
        if isinstance(value, str):
            for secret in secrets:
                if secret and secret in value:
                    value = value.replace(secret, "****")
        scrubbed[key] = value
    return scrubbed


def _collect_config_findings(
    config_file: str | None,
    offline: bool = False,
) -> tuple[list[dict[str, Any]], set[str]]:
    from verity.discovery.auditor import ConsolidatedSecurityAuditor
    from verity.discovery.config_scanner import MultiClientConfigScanner
    from verity.scanner.static_rules import StaticRuleEvaluator

    scanner = MultiClientConfigScanner()
    evaluator = StaticRuleEvaluator()
    scanned_files: set[str] = set()

    if config_file:
        path = Path(config_file)
        if not path.is_file():
            raise FileNotFoundError(f"Config file not found: {config_file}")
        content = path.read_text(encoding="utf-8")
        try:
            if path.suffix.lower() in (".yaml", ".yml"):
                import yaml

                raw = yaml.safe_load(content)
            else:
                raw = json.loads(content)
        except Exception as exc:
            raise ValueError(f"Invalid config file {config_file}: {exc}") from exc
        if not isinstance(raw, (dict, list)):
            raise ValueError(
                f"Config file must contain a JSON/YAML object or list: {config_file}"
            )
        configs = scanner.parse_config_file(config_file)
        scanned_files.add(str(config_file))
    else:
        configs, files = scanner.scan_all()
        scanned_files.update(files)

    previous_offline = os.environ.get("VERITY_OFFLINE")
    if offline:
        os.environ["VERITY_OFFLINE"] = "1"

    try:
        findings: list[dict[str, Any]] = []
        auditor = None
        if configs:
            try:
                auditor = ConsolidatedSecurityAuditor()
            except Exception:
                auditor = None

        for config in configs:
            raw_config = getattr(config, "raw_config", None)
            if not isinstance(raw_config, dict):
                raw_config = {}

            candidate_env: dict[str, Any] = {}
            raw_env = raw_config.get("env")
            if isinstance(raw_env, dict):
                candidate_env.update(raw_env)
            candidate_env.update(getattr(config, "env", {}) or {})

            secrets: list[str] = []
            for key, value in candidate_env.items():
                text = str(value) if value is not None else ""
                if (
                    text
                    and len(text) >= 4
                    and not text.startswith("${")
                    and not text.startswith("$")
                    and (
                        MultiClientConfigScanner.SECRET_KEY_PATTERNS.search(str(key))
                        or MultiClientConfigScanner.SECRET_VALUE_PATTERNS.search(text)
                    )
                ):
                    secrets.append(text)

            if auditor is not None:
                try:
                    record = auditor.audit_server(config, live_probe=False)
                    for audit_finding in record.findings:
                        finding = _normalize_finding(audit_finding)
                        findings.append(_scrub_secrets(finding, secrets))
                except Exception:
                    pass

            tool_dict = {"name": config.server_name, **raw_config}
            for match in evaluator.scan_tool(tool_dict):
                finding = _normalize_finding(match)
                findings.append(_scrub_secrets(finding, secrets))
    finally:
        if offline:
            if previous_offline is None:
                os.environ.pop("VERITY_OFFLINE", None)
            else:
                os.environ["VERITY_OFFLINE"] = previous_offline

    deduped: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for finding in findings:
        key = (
            finding.get("rule_id"),
            finding.get("file_path"),
            finding.get("title"),
            finding.get("message"),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)

    return deduped, scanned_files


def _collect_schema_findings(
    schema_file: str,
) -> tuple[list[dict[str, Any]], set[str]]:
    from verity.scanner.static_rules import StaticRuleEvaluator

    data = json.loads(Path(schema_file).read_text(encoding="utf-8"))
    tools: Any = data.get("tools", []) if isinstance(data, dict) else data
    if not isinstance(tools, list):
        tools = []

    evaluator = StaticRuleEvaluator()
    findings: list[dict[str, Any]] = []
    for tool in tools:
        if isinstance(tool, dict):
            for match in evaluator.scan_tool(tool):
                findings.append(_normalize_finding(match))
    return findings, {str(schema_file)}


def _collect_ast_findings(
    target_path: str,
) -> tuple[list[dict[str, Any]], set[str], float]:
    from verity.scanner.engine import McpAstScannerEngine

    report = McpAstScannerEngine().scan_path(target_path)
    data = report.to_dict() if hasattr(report, "to_dict") else dict(report)

    findings = [_normalize_finding(item) for item in data.get("findings", []) or []]
    scanned = {str(p) for p in data.get("scanned_files", []) or []}

    duration = 0.0
    summary = data.get("summary") if isinstance(data, dict) else None
    if isinstance(summary, dict) and summary.get("scan_duration_ms") is not None:
        duration = float(summary["scan_duration_ms"])
    elif isinstance(data, dict) and data.get("scan_duration_ms") is not None:
        duration = float(data["scan_duration_ms"])
    return findings, scanned, duration


def _collect_scan_data(
    args: argparse.Namespace,
) -> tuple[list[dict[str, Any]], set[str], float]:
    findings: list[dict[str, Any]] = []
    scanned_files: set[str] = set()
    duration_ms = 0.0

    try:
        config_findings, config_files = _collect_config_findings(
            args.config_file, offline=getattr(args, "offline", False)
        )
        findings.extend(config_findings)
        scanned_files.update(config_files)
    except Exception as exc:  # pragma: no cover - defensive
        print(f"Configuration scan failed: {exc}", file=sys.stderr)

    if args.schema_file:
        try:
            schema_findings, schema_files = _collect_schema_findings(args.schema_file)
            findings.extend(schema_findings)
            scanned_files.update(schema_files)
        except Exception as exc:
            print(f"Schema screen failed: {exc}", file=sys.stderr)

    if args.path:
        try:
            ast_findings, ast_files, ast_duration = _collect_ast_findings(args.path)
            findings.extend(ast_findings)
            scanned_files.update(ast_files)
            duration_ms += ast_duration
        except Exception as exc:
            print(f"AST scan failed: {exc}", file=sys.stderr)

    return findings, scanned_files, duration_ms


def _export_sarif(report: dict[str, Any], output: str | None) -> int:
    exporter = _load_sarif_exporter()
    if exporter is None:
        _print_pro_message(
            "export_sarif",
            "verity-pro is installed but no SARIF exporter entry point is registered.",
        )
        return 2
    payload = exporter(report) if callable(exporter) else report
    text = payload if isinstance(payload, str) else json.dumps(payload, indent=2)
    _emit(text, output)
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    if args.format == "sarif" and not _pro_plugin_available():
        _print_pro_message("export_sarif", SARIF_MISSING_MESSAGE)
        return 2

    findings, scanned_files, duration_ms = _collect_scan_data(args)
    report = _build_report(findings, scanned_files, duration_ms, target_path=args.path)

    if args.format == "sarif":
        rc = _export_sarif(report, args.output)
        if rc != 0:
            return rc
    else:
        _emit(_render_scan(report, args.format), args.output)

    if args.fail_on_findings and findings:
        return 1
    return 0


def _probe_config(config: Any, transport: Any, name: str) -> dict[str, Any]:
    from verity.scanner.static_rules import StaticRuleEvaluator

    evaluator = StaticRuleEvaluator()
    try:
        capability = transport.inspect(config)
    except Exception as exc:
        return {
            "name": name,
            "status": "FAIL",
            "message": f"Probe failed: {exc}",
            "details": None,
            "severity": None,
        }

    findings: list[dict[str, Any]] = []
    for tool in getattr(capability, "tools", []) or []:
        findings.extend(_normalize_finding(m) for m in evaluator.scan_tool(tool))

    if not getattr(capability, "is_responsive", True) and not findings:
        return {
            "name": name,
            "status": "FAIL",
            "message": f"Target unreachable: {getattr(capability, 'error_message', '') or 'unknown'}",
            "details": None,
            "severity": None,
        }

    if findings:
        worst = min(
            (f["severity"] for f in findings),
            key=lambda sev: _SEVERITY_RANK.get(sev, len(_SEVERITY_ORDER)),
        )
        return {
            "name": name,
            "status": "FAIL",
            "message": f"{len(findings)} static finding(s) on exposed capabilities.",
            "details": "; ".join(sorted({f["rule_id"] for f in findings if f["rule_id"]})),
            "severity": worst,
        }

    return {
        "name": name,
        "status": "PASS",
        "message": "No static findings on exposed capabilities.",
        "details": None,
        "severity": None,
    }


def _cmd_test(args: argparse.Namespace) -> int:
    results: list[dict[str, Any]] = []

    if args.demo:
        try:
            from verity.targets import run_all_demo_probes

            demo_results = run_all_demo_probes(target_id=args.target)
            if isinstance(demo_results, list):
                for item in demo_results:
                    if not isinstance(item, dict):
                        continue
                    if "status" in item:
                        results.append(item)
                        continue
                    normalized = dict(item)
                    normalized["name"] = item.get("name") or item.get("target_id", "demo")
                    normalized["status"] = (
                        "PASS"
                        if (item.get("vulnerable_breached") and item.get("secure_defended"))
                        else "FAIL"
                    )
                    normalized["severity"] = (
                        item.get("severity") or item.get("cwe_id") or "INFO"
                    )
                    normalized["message"] = item.get("message") or (
                        f"Vulnerable breached={item.get('vulnerable_breached')}, "
                        f"Secure defended={item.get('secure_defended')} — "
                        f"{item.get('evidence', '')}"
                    )
                    normalized["details"] = item.get("details") or str(
                        item.get("evidence") or ""
                    )
                    results.append(normalized)
        except KeyError as exc:
            reason = exc.args[0] if exc.args else f"Unknown demo target: {args.target}"
            results.append(
                {
                    "name": args.target or "demo_probes",
                    "status": "FAIL",
                    "message": str(reason),
                    "details": None,
                    "severity": None,
                }
            )
        except (ImportError, AttributeError):
            results.append(
                {
                    "name": "demo_probes",
                    "status": "FAIL",
                    "message": "verity.targets module not available",
                    "details": None,
                    "severity": None,
                }
            )

    if args.sql:
        from verity.mcp_library.sql_guard import SqlSecurityError, SqlSecurityGuard

        try:
            SqlSecurityGuard.validate_single_select_statement(args.sql)
            SqlSecurityGuard.validate_parameterized_query(args.sql)
            results.append(
                {
                    "name": "sql_security_guard",
                    "status": "PASS",
                    "message": "Query passed read-only and parameterization validation.",
                    "details": args.sql,
                    "severity": None,
                }
            )
        except SqlSecurityError as exc:
            results.append(
                {
                    "name": "sql_security_guard",
                    "status": "FAIL",
                    "message": str(exc),
                    "details": args.sql,
                    "severity": "HIGH",
                }
            )
        except Exception as exc:
            results.append(
                {
                    "name": "sql_security_guard",
                    "status": "FAIL",
                    "message": f"SQL validation error: {exc}",
                    "details": args.sql,
                    "severity": "HIGH",
                }
            )

    if args.url:
        from verity.discovery.models import ClientType, DiscoveredServerConfig, TransportType
        from verity.discovery.transports.sse import HttpSseDiscoveryTransport

        config = DiscoveredServerConfig(
            client_type=ClientType.CUSTOM,
            server_name="remote_sse",
            transport_type=TransportType.SSE,
            url=args.url,
        )
        results.append(_probe_config(config, HttpSseDiscoveryTransport(), "sse_transport_probe"))

    if args.command:
        from verity.discovery.models import ClientType, DiscoveredServerConfig, TransportType
        from verity.discovery.transports.stdio import StdioDiscoveryTransport

        parts = shlex.split(args.command)
        config = DiscoveredServerConfig(
            client_type=ClientType.CUSTOM,
            server_name="stdio_cmd",
            transport_type=TransportType.STDIO,
            command=parts[0] if parts else "",
            args=tuple(parts[1:]) if len(parts) > 1 else (),
        )
        results.append(_probe_config(config, StdioDiscoveryTransport(), "stdio_transport_probe"))

    _emit(_render_test(results, args.format), args.output)

    if any(str(r.get("status", "")).upper() == "FAIL" for r in results):
        return 1
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    from verity.mcp_server.server import run_server

    run_server(host=args.host, port=args.port, transport=args.transport)
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the Verity argument parser."""
    parser = argparse.ArgumentParser(prog="verity", description="Verity MCP security toolkit.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan MCP configurations, schemas, and source.")
    scan.add_argument("--config-file", default=None, help="Single MCP config JSON file to scan.")
    scan.add_argument("--schema-file", default=None, help="JSON file with MCP tool definitions.")
    scan.add_argument("--path", default=None, help="Python source file or directory to scan.")
    scan.add_argument(
        "--format",
        choices=("terminal", "json", "markdown", "html", "sarif"),
        default="terminal",
        help="Output format.",
    )
    scan.add_argument("--output", default=None, help="Write output to this path.")
    scan.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Return exit code 1 when findings are detected.",
    )
    scan.add_argument(
        "--offline",
        action="store_true",
        help="Disable remote snapshot fetching and use local caches only.",
    )
    scan.set_defaults(func=_cmd_scan)

    test = subparsers.add_parser("test", help="Run defensive probes and checks.")
    test.add_argument("--demo", action="store_true", help="Run all demo probes.")
    test.add_argument("--target", default=None, help="Specific demo target identifier.")
    test.add_argument("--sql", default=None, help="SQL query to validate.")
    test.add_argument("--url", default=None, help="SSE endpoint to probe.")
    test.add_argument("--command", default=None, help="Stdio MCP command to probe.")
    test.add_argument(
        "--format",
        choices=("terminal", "json", "markdown", "html"),
        default="terminal",
        help="Output format.",
    )
    test.add_argument("--output", default=None, help="Write output to this path.")
    test.set_defaults(func=_cmd_test)

    serve = subparsers.add_parser("serve", help="Serve the Verity MCP server.")
    serve.add_argument(
        "--transport",
        choices=("stdio", "sse", "http"),
        default="stdio",
        help="Transport to use.",
    )
    serve.add_argument("--host", default="127.0.0.1", help="Bind host for network transports.")
    serve.add_argument("--port", type=int, default=8765, help="Bind port for network transports.")
    serve.set_defaults(func=_cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``verity`` CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
