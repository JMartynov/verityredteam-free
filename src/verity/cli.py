"""Developer-first command line interface for Verity."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import re
import shlex
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import verity
from verity.baseline import (
    BaselineSchemaError,
    PolicyValidationError,
    apply_inline_suppressions,
    apply_policy_suppressions,
    assign_fingerprints,
    diff_baseline,
    load_baseline,
    load_ignore_spec,
    load_policy_config,
    resolve_project_root,
    save_baseline,
    validate_rug_pull_baseline_dict,
)
from verity.reporting import (
    render_scan_html,
    render_scan_markdown,
    render_scan_terminal,
    render_test_html,
    render_test_markdown,
    render_test_terminal,
)
from verity.scanner.credential_patterns import (
    CREDENTIAL_VALUE_PATTERNS,
    PEM_PRIVATE_KEY_BLOCK_PATTERN,
    is_placeholder_value,
)

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_SEVERITY_RANK = {sev: idx for idx, sev in enumerate(_SEVERITY_ORDER)}
_SECRET_RULE_IDS = frozenset({"VERITY-CFG-SECRET-001", "SEC-STATIC-SECRET-IN-CONFIG"})

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


def _parse_start_line(finding: dict[str, Any]) -> int:
    """Return a safe SARIF ``startLine`` from a finding's line metadata."""
    for key in ("line_number", "line"):
        value = finding.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, str):
            text = value.strip()
            if text in ("", "-"):
                continue
            try:
                value = int(text)
            except ValueError:
                continue
        if not isinstance(value, int):
            continue
        if value <= 0:
            continue
        return value
    return 1


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

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f"{title}: {message}".strip()},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": str(
                                finding.get("file_path")
                                or finding.get("uri")
                                or finding.get("location")
                                or "mcp_config.json"
                            )
                        },
                        "region": {"startLine": _parse_start_line(finding)},
                    }
                }
            ],
        }
        fingerprint = finding.get("fingerprint")
        if fingerprint:
            result["partialFingerprints"] = {"verity/v1": str(fingerprint)}
        suppression = finding.get("suppression")
        if isinstance(suppression, dict):
            kind = str(suppression.get("kind") or "external")
            if kind not in ("inSource", "external"):
                kind = "external"
            entry: dict[str, Any] = {"kind": kind}
            reason = suppression.get("reason")
            if reason:
                entry["justification"] = str(reason)
            result["suppressions"] = [entry]
        results.append(result)

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
                        "version": verity.__version__,
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
    print(json.dumps(payload, indent=2))


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


def _as_str_list(val: Any) -> list[str]:
    """Normalize a ``str``/``Path``/sequence/``None`` value into a list of strings."""
    if val is None:
        return []
    if isinstance(val, (str, Path)):
        return [str(val)]
    if isinstance(val, Sequence):
        return [str(item) for item in val if item is not None and str(item)]
    return [str(val)]


def _should_canonicalize(
    project_root: Path,
    target_paths: list[str],
    args: argparse.Namespace,
) -> bool:
    """Decide whether findings' ``file_path`` values should be canonicalized.

    Canonicalization is required whenever results will be persisted
    (``--save-baseline`` / ``--baseline``) or compared across machines
    (``--root``). Directory scans canonicalize for consistency. A single
    file that is not part of a git project keeps its literal path so
    callers (e.g. SARIF exporters) see exactly the path they passed.
    """
    if getattr(args, "root", None) or getattr(args, "save_baseline", None) or getattr(
        args, "baseline", None
    ):
        return True
    for target in target_paths:
        if Path(target).is_dir():
            return True
    try:
        if (Path(project_root) / ".git").exists():
            return True
    except OSError:
        pass
    return False


def _config_source_path(config: Any) -> str:
    for attr in ("config_path", "source_path", "config_file", "path", "source"):
        value = getattr(config, attr, None)
        if value:
            return str(value)
    raw_config = getattr(config, "raw_config", None)
    if isinstance(raw_config, dict):
        for key in ("__config_path__", "_config_path", "config_path", "path"):
            if raw_config.get(key):
                return str(raw_config[key])
    return ""


def _extract_env_var_name(finding: dict[str, Any]) -> str:
    for key in ("env_key", "message", "title"):
        value = finding.get(key)
        if not value:
            continue
        match = re.search(r"['\"]([A-Za-z0-9_]+)['\"]", str(value))
        if match:
            return match.group(1)
    return ""


def _annotate_secret_finding(
    finding: dict[str, Any], env_secrets: dict[str, str]
) -> None:
    """Attach ``env_key`` and the raw secret value to config secret findings."""
    if str(finding.get("rule_id") or "") not in _SECRET_RULE_IDS:
        return
    env_key = str(finding.get("env_key") or _extract_env_var_name(finding))
    if env_key and env_key in env_secrets:
        finding.setdefault("env_key", env_key)
        finding.setdefault("_raw_secret", env_secrets[env_key])


def _load_sources(
    findings: list[dict[str, Any]], project_root: Path | None
) -> tuple[dict[str, str], dict[str, list[str]]]:
    """Read on-disk source for findings, keyed by both stored and resolved paths."""
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


def _resolve_fail_threshold(args: argparse.Namespace, policy: Any) -> str | None:
    """Return the minimum severity that should trigger a non-zero exit code."""
    if getattr(args, "fail_on_findings", False):
        return "INFO"
    raw = getattr(args, "fail_on_severity", None) or getattr(args, "fail_on", None)
    if raw:
        return _as_severity(raw)
    scan_cfg = getattr(policy, "scan", {}) or {}
    if isinstance(scan_cfg, dict):
        configured = scan_cfg.get("fail_on_severity") or scan_cfg.get("fail_on")
        if configured:
            return _as_severity(configured)
    return None


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

    finding: dict[str, Any] = {
        "rule_id": str(_field(data, "rule_id", "issue_id")),
        "cwe_id": cwe_id,
        "severity": _as_severity(_field(data, "severity")),
        "title": str(_field(data, "title")),
        "message": message,
        "file_path": str(
            _field(
                data,
                "file_path",
                "config_path",
                "uri",
                "location",
                "target_name",
                "server_name",
            )
        ),
        "line_number": _field(data, "line_number", "line", default="-") or "-",
        "remediation": str(_field(data, "remediation")),
    }
    for key in (
        "mcp_tool_context",
        "func_name",
        "snippet",
        "matched_snippet",
        "field_path",
        "target_type",
        "tool_name",
        "server_name",
        "advisory_id",
        "cve_id",
        "aliases",
        "package_name",
        "category",
        "env_key",
        "_raw_secret",
        "source",
        "kind",
    ):
        value = data.get(key)
        if value not in (None, ""):
            finding[key] = value
    return finding


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


def _collect_redaction_targets(text: str, secrets: list[str]) -> list[str]:
    """Return every explicit secret and credential-pattern match in ``text``."""
    from verity.discovery.config_scanner import MultiClientConfigScanner

    targets = {secret for secret in secrets if secret and secret in text}
    for match in PEM_PRIVATE_KEY_BLOCK_PATTERN.finditer(text):
        targets.add(match.group(0))
    for pattern in CREDENTIAL_VALUE_PATTERNS:
        for match in pattern.finditer(text):
            targets.add(match.group(0))
    for dsn_match in MultiClientConfigScanner.DSN_CREDENTIAL_PATTERN.finditer(text):
        pwd = dsn_match.group(1)
        if pwd and not pwd.startswith("$") and not is_placeholder_value(pwd):
            targets.add(dsn_match.group(0))
    return sorted(targets, key=len, reverse=True)


def _scrub_secrets(
    finding: dict[str, Any], secrets: list[str] | None = None
) -> dict[str, Any]:
    """Redact plaintext secrets and drop private (underscore-prefixed) keys."""
    targets: list[str] = [str(item) for item in (secrets or []) if item]
    embedded = finding.get("_redaction_secrets")
    if isinstance(embedded, (list, tuple, set)):
        targets.extend(str(item) for item in embedded if item)
    for key in ("_raw_secret", "raw_secret_value"):
        value = finding.get(key)
        if value:
            targets.append(str(value))

    scrubbed: dict[str, Any] = {}
    for key, value in finding.items():
        if key.startswith("_"):
            continue
        if isinstance(value, str):
            for secret in _collect_redaction_targets(value, targets):
                value = value.replace(secret, "****")
        scrubbed[key] = value
    return scrubbed


def _collect_config_findings(
    config_file: str | Sequence[str] | None,
    offline: bool = False,
    live_probe: bool = False,
    *,
    scrub: bool = True,
    scan_workstation: bool = True,
    ignore_matcher: Any | None = None,
) -> tuple[list[dict[str, Any]], set[str]]:
    from verity.discovery.auditor import ConsolidatedSecurityAuditor
    from verity.discovery.config_scanner import MultiClientConfigScanner
    from verity.scanner.static_rules import StaticRuleEvaluator

    scanner = MultiClientConfigScanner()
    evaluator = StaticRuleEvaluator()
    scanned_files: set[str] = set()
    config_paths = _as_str_list(config_file)

    configs: list[Any] = []
    config_sources: dict[int, str] = {}

    if config_paths:
        for raw_path in config_paths:
            path = Path(raw_path)
            if not path.is_file():
                raise FileNotFoundError(f"Config file not found: {raw_path}")
            content = path.read_text(encoding="utf-8")
            try:
                if path.suffix.lower() in (".yaml", ".yml"):
                    import yaml

                    raw = yaml.safe_load(content)
                else:
                    raw = json.loads(content)
            except Exception as exc:
                raise ValueError(f"Invalid config file {raw_path}: {exc}") from exc
            if not isinstance(raw, (dict, list)):
                raise ValueError(
                    f"Config file must contain a JSON/YAML object or list: {raw_path}"
                )
            parsed = scanner.parse_config_file(raw_path)
            for cfg in parsed:
                config_sources[id(cfg)] = str(raw_path)
            configs.extend(parsed)
            scanned_files.add(str(raw_path))
    elif scan_workstation:
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

        if auditor is not None:
            from verity.data_fetcher import _is_offline

            if _is_offline():
                vuln_engine = getattr(auditor, "vuln_engine", None)
                vuln_index = getattr(vuln_engine, "index", None)
                vuln_total = getattr(vuln_index, "total_vulnerabilities", None)

                matcher = getattr(auditor, "matcher", None)
                inner_matcher = getattr(matcher, "matcher", None)
                fast_index = getattr(inner_matcher, "fast_index", None)
                passport_total = getattr(fast_index, "packages", None)
                passport_count = (
                    len(passport_total) if passport_total is not None else None
                )

                if vuln_total == 0 or passport_count == 0:
                    print(
                        "Warning: offline mode has no cached or packaged "
                        "baseline data; vulnerability/fingerprint lookups will "
                        "return 0 matches.",
                        file=sys.stderr,
                    )

        for config in configs:
            raw_config = getattr(config, "raw_config", None)
            if not isinstance(raw_config, dict):
                raw_config = {}

            config_path = config_sources.get(id(config)) or _config_source_path(config)
            server_name = str(getattr(config, "server_name", "") or "")

            candidate_env: dict[str, Any] = {}
            raw_env = raw_config.get("env")
            if isinstance(raw_env, dict):
                candidate_env.update(raw_env)
            candidate_env.update(getattr(config, "env", {}) or {})

            env_secrets: dict[str, str] = {}
            secrets: list[str] = []
            for key, value in candidate_env.items():
                raw_val = raw_env.get(key, value)
                if not MultiClientConfigScanner.is_secret_env_entry(str(key), raw_val):
                    continue
                text = str(value) if value is not None else ""
                raw_text = str(raw_val) if raw_val is not None else ""
                if text and not is_placeholder_value(text):
                    env_secrets[str(key)] = text
                if raw_text and raw_text != text and not is_placeholder_value(raw_text):
                    env_secrets.setdefault(str(key), raw_text)
                if len(text) >= 4:
                    secrets.append(text)
                if raw_text and raw_text != text and len(raw_text) >= 4:
                    secrets.append(raw_text)
                for candidate_text in (raw_text, text):
                    dsn_match = MultiClientConfigScanner.DSN_CREDENTIAL_PATTERN.search(
                        candidate_text
                    )
                    if dsn_match:
                        pwd = dsn_match.group(1)
                        if len(pwd) >= 6 and pwd not in secrets:
                            secrets.append(pwd)
                    for pem_match in PEM_PRIVATE_KEY_BLOCK_PATTERN.finditer(
                        candidate_text
                    ):
                        pem_value = pem_match.group(0)
                        if pem_value and pem_value not in secrets:
                            secrets.append(pem_value)

            if auditor is not None:
                record = None
                try:
                    record = auditor.audit_server(config, live_probe=live_probe)
                except Exception as exc:
                    if live_probe:
                        print(
                            f"Live probe failed for {server_name}: {exc}",
                            file=sys.stderr,
                        )
                if record is not None:
                    if live_probe:
                        probe_error = getattr(record, "live_probe_error", None)
                        if probe_error:
                            print(
                                f"Live probe failed for {server_name}: {probe_error}",
                                file=sys.stderr,
                            )
                    for audit_finding in record.findings:
                        finding = _normalize_finding(audit_finding)
                        if config_path:
                            finding["file_path"] = config_path
                        if not finding.get("server_name"):
                            finding["server_name"] = server_name
                        _annotate_secret_finding(finding, env_secrets)
                        if scrub:
                            finding = _scrub_secrets(finding, secrets)
                        else:
                            finding["_redaction_secrets"] = list(secrets)
                        findings.append(finding)

            for env_key, raw_value in env_secrets.items():
                findings.append(
                    {
                        "rule_id": "SEC-STATIC-SECRET-IN-CONFIG",
                        "cwe_id": "CWE-798",
                        "severity": "HIGH",
                        "title": "Plaintext secret in MCP configuration",
                        "message": (
                            f"Environment variable '{env_key}' contains a "
                            "plaintext secret"
                        ),
                        "file_path": config_path or server_name,
                        "line_number": 1,
                        "remediation": (
                            "Use environment variable references or a secret manager."
                        ),
                        "server_name": server_name,
                        "env_key": env_key,
                        "_raw_secret": raw_value,
                        "category": "SECRET",
                        "_redaction_secrets": list(secrets),
                    }
                )

            tool_dict = {"name": server_name, **raw_config}
            for match in evaluator.scan_tool(tool_dict):
                finding = _normalize_finding(match)
                if config_path:
                    finding["file_path"] = config_path
                if not finding.get("server_name"):
                    finding["server_name"] = server_name
                if scrub:
                    finding = _scrub_secrets(finding, secrets)
                else:
                    finding["_redaction_secrets"] = list(secrets)
                findings.append(finding)
    finally:
        if offline:
            if previous_offline is None:
                os.environ.pop("VERITY_OFFLINE", None)
            else:
                os.environ["VERITY_OFFLINE"] = previous_offline

    if live_probe:
        findings.sort(
            key=lambda f: _SEVERITY_RANK.get(
                _as_severity(f.get("severity")), len(_SEVERITY_ORDER)
            )
        )

    return findings, scanned_files


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
    *,
    project_root: Path | None = None,
    ignore_matcher: Any | None = None,
) -> tuple[list[dict[str, Any]], set[str], float]:
    from verity.scanner.engine import McpAstScannerEngine

    report = McpAstScannerEngine().scan_path(
        target_path, project_root=project_root, ignore_matcher=ignore_matcher
    )
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
    *,
    project_root: Path | None = None,
    ignore_matcher: Any | None = None,
) -> tuple[list[dict[str, Any]], set[str], float]:
    findings: list[dict[str, Any]] = []
    scanned_files: set[str] = set()
    duration_ms = 0.0

    config_files = _as_str_list(getattr(args, "config_file", None))
    raw_targets = _as_str_list(getattr(args, "path", None))
    schema_file = getattr(args, "schema_file", None)

    config_targets: list[str] = []
    ast_targets: list[str] = []
    for target in raw_targets:
        path = Path(target)
        if path.suffix.lower() in (".json", ".yaml", ".yml"):
            config_targets.append(target)
        elif path.is_dir():
            ast_targets.append(target)
            try:
                from verity.discovery.config_scanner import (
                    MultiClientConfigScanner,
                )

                config_targets.extend(
                    str(p)
                    for p in MultiClientConfigScanner.discover_workspace_configs(
                        target, ignore_matcher=ignore_matcher
                    )
                )
            except Exception as exc:
                print(f"Workspace discovery failed: {exc}", file=sys.stderr)
        else:
            ast_targets.append(target)

    all_config_paths = list(dict.fromkeys([*config_files, *config_targets]))
    scan_workstation = not (config_files or raw_targets or schema_file)

    if all_config_paths or scan_workstation:
        try:
            config_findings, config_scanned = _collect_config_findings(
                all_config_paths or None,
                offline=getattr(args, "offline", False),
                live_probe=getattr(args, "live_probe", False),
                scrub=False,
                scan_workstation=scan_workstation,
                ignore_matcher=ignore_matcher,
            )
            findings.extend(config_findings)
            scanned_files.update(config_scanned)
        except Exception as exc:  # pragma: no cover - defensive
            print(f"Configuration scan failed: {exc}", file=sys.stderr)

    if schema_file:
        try:
            schema_findings, schema_files = _collect_schema_findings(schema_file)
            findings.extend(schema_findings)
            scanned_files.update(schema_files)
        except Exception as exc:
            print(f"Schema screen failed: {exc}", file=sys.stderr)

    for target in ast_targets:
        try:
            ast_findings, ast_files, ast_duration = _collect_ast_findings(
                target, project_root=project_root, ignore_matcher=ignore_matcher
            )
            findings.extend(ast_findings)
            scanned_files.update(ast_files)
            duration_ms += ast_duration
        except Exception as exc:
            print(f"AST scan failed: {exc}", file=sys.stderr)

    return findings, scanned_files, duration_ms


def _export_sarif(report: dict[str, Any], output: str | None) -> int:
    exporter = _load_sarif_exporter()
    if exporter is None:
        _print_pro_message("export_sarif", SARIF_MISSING_MESSAGE)
        return 2
    payload = exporter(report) if callable(exporter) else report
    text = payload if isinstance(payload, str) else json.dumps(payload, indent=2)
    _emit(text, output)
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    if args.format == "sarif" and not _pro_plugin_available():
        _print_pro_message("export_sarif", SARIF_MISSING_MESSAGE)
        return 2

    if getattr(args, "save_baseline", None) and getattr(args, "baseline", None):
        print(
            "--save-baseline and --baseline are mutually exclusive.",
            file=sys.stderr,
        )
        return 2

    if not getattr(args, "fail_on_findings", False):
        raw_fail = getattr(args, "fail_on_severity", None) or getattr(
            args, "fail_on", None
        )
        if raw_fail and str(raw_fail).upper() not in _SEVERITY_RANK:
            print(
                f"Invalid severity for --fail-on-severity/--fail-on: {raw_fail}",
                file=sys.stderr,
            )
            return 2

    config_files = _as_str_list(getattr(args, "config_file", None))
    for config_file in config_files:
        if not Path(config_file).is_file():
            print(f"Config file not found: {config_file}", file=sys.stderr)
            return 2
    if getattr(args, "config", None) and not Path(args.config).is_file():
        print(f"Policy config not found: {args.config}", file=sys.stderr)
        return 2
    if getattr(args, "ignore_file", None) and not Path(args.ignore_file).is_file():
        print(f"Ignore file not found: {args.ignore_file}", file=sys.stderr)
        return 2

    target_paths = _as_str_list(getattr(args, "path", None))
    project_root = resolve_project_root(
        target_paths=[*target_paths, *config_files] or None,
        explicit_root=getattr(args, "root", None),
    )
    canonical_root = (
        project_root if _should_canonicalize(project_root, target_paths, args) else None
    )

    try:
        ignore_matcher = load_ignore_spec(
            project_root,
            getattr(args, "ignore_file", None),
            use_default_ignores=not getattr(args, "no_default_ignores", False),
        )
    except Exception:  # pragma: no cover - defensive
        ignore_matcher = None

    try:
        policy = load_policy_config(
            project_root,
            getattr(args, "config", None),
            strict_policy=getattr(args, "strict_policy", False),
        )
    except (PolicyValidationError, FileNotFoundError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    findings, scanned_files, duration_ms = _collect_scan_data(
        args, project_root=canonical_root, ignore_matcher=ignore_matcher
    )

    assign_fingerprints(
        findings,
        project_root=canonical_root,
        home_dir=Path.home(),
        update_file_path=canonical_root is not None,
    )

    source_by_file, source_lines_cache = _load_sources(findings, canonical_root)
    apply_policy_suppressions(
        findings, policy, source_lines_cache=source_lines_cache
    )
    try:
        apply_inline_suppressions(
            findings,
            source_by_file,
            respect_inline_ignores=not getattr(args, "no_inline_ignores", False),
            strict_policy=getattr(args, "strict_policy", False),
        )
    except PolicyValidationError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    findings = [_scrub_secrets(finding) for finding in findings]

    suppressed = [f for f in findings if "suppression" in f]
    active = [f for f in findings if "suppression" not in f]

    new_findings_count: int | None = None
    baseline_findings_count: int | None = None
    resolved_since_baseline = 0

    if getattr(args, "baseline", None):
        try:
            baseline_data = load_baseline(args.baseline)
        except (FileNotFoundError, BaselineSchemaError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
        diff = diff_baseline(list(active), baseline_data)
        active = diff.new_findings
        suppressed.extend(diff.baseline_findings)
        new_findings_count = len(diff.new_findings)
        baseline_findings_count = len(diff.baseline_findings)
        resolved_since_baseline = diff.resolved_since_baseline

    if getattr(args, "save_baseline", None):
        try:
            save_baseline(
                args.save_baseline,
                list(active),
                project_root=project_root,
                home_dir=Path.home(),
            )
        except Exception as exc:  # pragma: no cover - defensive
            print(str(exc), file=sys.stderr)
            return 2

    target_label = " ".join(target_paths) or None
    report = _build_report(active, scanned_files, duration_ms, target_path=target_label)
    summary = report["summary"]
    summary["suppressed_counts"] = _suppressed_counts(suppressed)
    if new_findings_count is not None:
        summary["new_findings"] = new_findings_count
        summary["baseline_findings"] = baseline_findings_count or 0
        summary["resolved_since_baseline"] = resolved_since_baseline
    if policy.expired_warnings:
        summary["expired_ignore_warnings"] = list(policy.expired_warnings)
    if getattr(args, "show_suppressed", False):
        report["suppressed_findings"] = suppressed

    if args.format == "sarif":
        rc = _export_sarif(report, args.output)
        if rc != 0:
            return rc
    else:
        _emit(_render_scan(report, args.format), args.output)

    if (
        new_findings_count is not None
        and getattr(args, "fail_on_new", False)
        and new_findings_count > 0
    ):
        return 1

    threshold = _resolve_fail_threshold(args, policy)
    if threshold:
        limit = _SEVERITY_RANK.get(threshold, len(_SEVERITY_ORDER))
        for finding in active:
            rank = _SEVERITY_RANK.get(
                _as_severity(finding.get("severity")), len(_SEVERITY_ORDER)
            )
            if rank <= limit:
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
        details = "; ".join(sorted({f["rule_id"] for f in findings if f["rule_id"]}))
        message = (
            f"{len(findings)} static finding(s) on exposed capabilities: {details}"
            if details
            else f"{len(findings)} static finding(s) on exposed capabilities."
        )
        return {
            "name": name,
            "status": "FAIL",
            "message": message,
            "details": details,
            "severity": worst,
        }

    return {
        "name": name,
        "status": "PASS",
        "message": "No static findings on exposed capabilities.",
        "details": None,
        "severity": None,
    }


def _run_rug_pull_cli(
    config: Any,
    transport: Any,
    results: list[dict[str, Any]],
    save_baseline: str | None,
    baseline: str | None,
) -> int | None:
    """Handle --save-baseline / --baseline for a probed MCP endpoint."""
    if not save_baseline and not baseline:
        return None

    from verity.ucp.engine import UnknownCapabilityProfiler

    result_name = "rug_pull_baseline_save" if save_baseline else "rug_pull_baseline"

    authorized: dict[str, str] | None = None
    if baseline:
        try:
            authorized_raw = json.loads(Path(baseline).read_text(encoding="utf-8"))
            if not isinstance(authorized_raw, dict):
                raise ValueError("baseline must be a JSON object")
        except Exception as exc:
            results.append(
                {
                    "name": "rug_pull_baseline",
                    "status": "FAIL",
                    "message": f"Failed to load baseline file '{baseline}': {exc}",
                    "details": None,
                    "severity": "CRITICAL",
                }
            )
            return None
        try:
            authorized = validate_rug_pull_baseline_dict(authorized_raw)
        except BaselineSchemaError as exc:
            is_scan_baseline = "verity scan" in str(exc).lower()
            results.append(
                {
                    "name": "rug_pull_baseline",
                    "status": "FAIL",
                    "message": str(exc),
                    "details": "SCHEMA_MISMATCH" if is_scan_baseline else None,
                    "severity": "CRITICAL",
                }
            )
            return 2 if is_scan_baseline else None

    try:
        capability = transport.inspect(config)
    except Exception as exc:
        results.append(
            {
                "name": result_name,
                "status": "FAIL",
                "message": f"Rug-pull probe failed: {exc}",
                "details": None,
                "severity": "CRITICAL" if baseline else None,
            }
        )
        return None

    if not getattr(capability, "is_responsive", True):
        results.append(
            {
                "name": result_name,
                "status": "FAIL",
                "message": (
                    "Target unreachable: "
                    f"{getattr(capability, 'error_message', '') or 'unknown'}"
                ),
                "details": None,
                "severity": "CRITICAL" if baseline else None,
            }
        )
        return None

    tools = [t for t in getattr(capability, "tools", []) or [] if isinstance(t, dict)]

    if save_baseline:
        profiles = UnknownCapabilityProfiler.profile_toolset(tools)
        hashes = {name: p.canonical_hash for name, p in profiles.items()}
        try:
            path = Path(save_baseline)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(hashes, indent=2, sort_keys=True), encoding="utf-8"
            )
            results.append(
                {
                    "name": "rug_pull_baseline_save",
                    "status": "PASS",
                    "message": (
                        f"Saved trusted baseline for {len(hashes)} tool(s) "
                        f"to {save_baseline}."
                    ),
                    "details": str(path),
                    "severity": None,
                }
            )
        except Exception as exc:
            results.append(
                {
                    "name": "rug_pull_baseline_save",
                    "status": "FAIL",
                    "message": f"Failed to write baseline file '{save_baseline}': {exc}",
                    "details": None,
                    "severity": None,
                }
            )

    if baseline and authorized is not None:
        drift = [
            r
            for r in UnknownCapabilityProfiler.detect_rug_pull(
                authorized_hashes=authorized, current_tools=tools
            )
            if r.is_rug_pull
        ]
        if drift:
            affected = ", ".join(sorted({r.tool_name for r in drift}))
            results.append(
                {
                    "name": "rug_pull_baseline",
                    "status": "FAIL",
                    "message": f"RUG_PULL_DETECTED: tool definition drift for: {affected}",
                    "details": "RUG_PULL_DETECTED",
                    "severity": "CRITICAL",
                }
            )
        else:
            results.append(
                {
                    "name": "rug_pull_baseline",
                    "status": "PASS",
                    "message": "No tool definition drift detected against baseline.",
                    "details": None,
                    "severity": None,
                }
            )

    return None


def _cmd_test(args: argparse.Namespace) -> int:
    results: list[dict[str, Any]] = []
    rc_override = 0

    baseline_flags = bool(args.save_baseline or args.baseline)
    baseline_endpoint_missing = baseline_flags and not (args.url or args.command)
    baseline_both = bool(args.save_baseline and args.baseline)

    if baseline_endpoint_missing:
        results.append(
            {
                "name": "rug_pull_baseline",
                "status": "FAIL",
                "message": (
                    "--save-baseline/--baseline require --command or --url."
                ),
                "details": None,
                "severity": None,
            }
        )

    if baseline_both:
        results.append(
            {
                "name": "rug_pull_baseline",
                "status": "FAIL",
                "message": (
                    "--save-baseline and --baseline are mutually exclusive."
                ),
                "details": None,
                "severity": None,
            }
        )

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

        dialect = getattr(args, "dialect", "postgres") or "postgres"
        details = f"{args.sql} #dialect={dialect}"
        try:
            SqlSecurityGuard.validate_single_select_statement(
                args.sql, dialect=dialect
            )
            SqlSecurityGuard.validate_parameterized_query(args.sql)
            results.append(
                {
                    "name": "sql_security_guard",
                    "status": "PASS",
                    "message": "Query passed read-only and parameterization validation.",
                    "details": details,
                    "severity": None,
                }
            )
        except SqlSecurityError as exc:
            results.append(
                {
                    "name": "sql_security_guard",
                    "status": "FAIL",
                    "message": str(exc),
                    "details": details,
                    "severity": "HIGH",
                }
            )
        except Exception as exc:
            results.append(
                {
                    "name": "sql_security_guard",
                    "status": "FAIL",
                    "message": f"SQL validation error: {exc}",
                    "details": details,
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
        sse_transport = HttpSseDiscoveryTransport()
        results.append(_probe_config(config, sse_transport, "sse_transport_probe"))
        if not baseline_both:
            rc = _run_rug_pull_cli(
                config, sse_transport, results, args.save_baseline, args.baseline
            )
            if rc:
                rc_override = rc

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
        stdio_transport = StdioDiscoveryTransport()
        results.append(_probe_config(config, stdio_transport, "stdio_transport_probe"))
        if not baseline_both:
            rc = _run_rug_pull_cli(
                config, stdio_transport, results, args.save_baseline, args.baseline
            )
            if rc:
                rc_override = rc

    _emit(_render_test(results, args.format), args.output)

    if rc_override:
        return rc_override
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
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {verity.__version__}",
        help="Show the Verity version and exit.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan MCP configurations, schemas, and source.")
    scan.add_argument(
        "--config-file",
        nargs="+",
        default=None,
        help="One or more MCP config JSON/YAML files to scan.",
    )
    scan.add_argument("--schema-file", default=None, help="JSON file with MCP tool definitions.")
    scan.add_argument(
        "--path",
        nargs="+",
        default=None,
        help="Source files, directories, or config files to scan.",
    )
    scan.add_argument("--root", default=None, help="Explicit project root for path canonicalization.")
    scan.add_argument("--config", default=None, help="Path to a verity.toml policy config.")
    scan.add_argument("--ignore-file", default=None, help="Path to a .verityignore file.")
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
        "--fail-on-severity",
        default=None,
        help="Return exit code 1 when a finding meets or exceeds this severity.",
    )
    scan.add_argument(
        "--fail-on",
        default=None,
        help="Alias for --fail-on-severity (case-insensitive).",
    )
    scan.add_argument(
        "--fail-on-new",
        action="store_true",
        help="Return exit code 1 when new findings appear versus --baseline.",
    )
    scan.add_argument("--save-baseline", default=None, help="Write a baseline document to this path.")
    scan.add_argument("--baseline", default=None, help="Diff findings against this baseline document.")
    scan.add_argument(
        "--show-suppressed",
        action="store_true",
        help="Include suppressed findings in the report output.",
    )
    scan.add_argument(
        "--strict-policy",
        action="store_true",
        help="Require reasons on ignore rules and inline suppressions.",
    )
    scan.add_argument(
        "--no-inline-ignores",
        action="store_true",
        help="Disable in-source # verity-ignore / # nosemgrep directives.",
    )
    scan.add_argument(
        "--no-default-ignores",
        action="store_true",
        help="Disable built-in default ignore directories.",
    )
    scan.add_argument(
        "--offline",
        action="store_true",
        help="Disable remote snapshot fetching and use local caches only.",
    )
    scan.add_argument(
        "--live-probe",
        action="store_true",
        help=(
            "Actively probe configured MCP servers to fingerprint live "
            "capabilities (opt-in, slower)."
        ),
    )
    scan.set_defaults(func=_cmd_scan)

    test = subparsers.add_parser("test", help="Run defensive probes and checks.")
    test.add_argument("--demo", action="store_true", help="Run all demo probes.")
    test.add_argument("--target", default=None, help="Specific demo target identifier.")
    test.add_argument("--sql", default=None, help="SQL query to validate.")
    test.add_argument(
        "--dialect",
        choices=(
            "postgres",
            "mysql",
            "sqlite",
            "duckdb",
            "tsql",
            "bigquery",
            "snowflake",
        ),
        default="postgres",
        help="SQL dialect for --sql validation (default: postgres).",
    )
    test.add_argument("--url", default=None, help="SSE endpoint to probe.")
    test.add_argument("--command", default=None, help="Stdio MCP command to probe.")
    test.add_argument(
        "--format",
        choices=("terminal", "json", "markdown", "html"),
        default="terminal",
        help="Output format.",
    )
    test.add_argument("--output", default=None, help="Write output to this path.")
    test.add_argument(
        "--save-baseline",
        default=None,
        help="Probe the MCP target and save its canonical tool hashes to this JSON path.",
    )
    test.add_argument(
        "--baseline",
        default=None,
        help="Compare the MCP target's canonical tool hashes against this JSON baseline.",
    )
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
