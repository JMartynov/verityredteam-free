"""Stable finding fingerprinting for Verity baseline/diff workflows."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from verity.baseline.paths import canonicalize_path

_ENV_VAR_RE = re.compile(r"Env(?:ironment)?\s+variable\s+['\"]([^'\"]+)['\"]", re.IGNORECASE)
_SECRET_RULE_IDS = frozenset({"VERITY-CFG-SECRET-001", "SEC-STATIC-SECRET-IN-CONFIG"})


def collapse_whitespace(text: Any) -> str:
    """Collapse all runs of whitespace into single spaces."""
    if text is None:
        return ""
    return " ".join(str(text).split())


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _digest(payload: list[Any]) -> str:
    serialized = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    )
    return _sha256_hex(serialized)[:16]


def _extract_env_key(finding: dict[str, Any]) -> str:
    for key in ("env_key", "message", "title"):
        value = finding.get(key)
        if not value:
            continue
        if key == "env_key":
            return str(value)
        match = _ENV_VAR_RE.search(str(value))
        if match:
            return match.group(1)
    return ""


def compute_finding_fingerprint(
    finding: dict[str, Any],
    project_root: Path | None = None,
    *,
    home_dir: Path | None = None,
) -> str:
    """Compute a 16-char stable hex fingerprint for a single finding dict."""
    data = finding or {}
    rule_id = str(data.get("rule_id") or "")
    file_path = data.get("file_path")
    canonical = (
        canonicalize_path(file_path, project_root=project_root, home_dir=home_dir)
        if file_path
        else ""
    )

    source = str(data.get("source") or "")
    is_ast = (
        data.get("kind") == "ast"
        or rule_id.startswith("VERITY-AST-")
        or source == "ast_scanner"
        or "mcp_tool_context" in data
        or "snippet" in data
    )
    if is_ast:
        context = data.get("mcp_tool_context") or data.get("func_name") or ""
        payload = [
            "ast",
            rule_id,
            canonical,
            str(context),
            collapse_whitespace(data.get("snippet")),
        ]
        return _digest(payload)

    is_secret = (
        rule_id in _SECRET_RULE_IDS
        or "_raw_secret" in data
        or "raw_secret_value" in data
        or "env_key" in data
    )
    if is_secret:
        raw_secret = data.get("_raw_secret")
        if raw_secret is None:
            raw_secret = data.get("raw_secret_value")
        raw_secret_str = "" if raw_secret is None else str(raw_secret)
        env_key = data.get("env_key") or _extract_env_key(data)
        payload = [
            "cfg_secret",
            rule_id,
            canonical,
            str(data.get("server_name") or ""),
            str(env_key or ""),
            _sha256_hex(raw_secret_str),
        ]
        return _digest(payload)

    is_tool_schema = (
        rule_id.startswith("VERITY-STATIC-")
        or "field_path" in data
        or "target_type" in data
    )
    if is_tool_schema:
        tool_name = data.get("tool_name") or data.get("target_name") or ""
        matched = (
            data.get("matched_snippet")
            or data.get("snippet")
            or data.get("message")
            or ""
        )
        payload = [
            "tool_schema",
            rule_id,
            canonical,
            str(tool_name),
            str(data.get("field_path") or ""),
            str(data.get("target_type") or ""),
            collapse_whitespace(matched),
        ]
        return _digest(payload)

    package = (
        data.get("package")
        or data.get("package_name")
        or data.get("advisory_id")
        or data.get("cve_id")
        or data.get("title")
        or data.get("message")
        or ""
    )
    payload = [
        "cfg_posture",
        rule_id,
        canonical,
        str(data.get("server_name") or ""),
        str(package),
    ]
    return _digest(payload)


def assign_fingerprints(
    findings: list[dict[str, Any]],
    project_root: Path | None = None,
    *,
    home_dir: Path | None = None,
    update_file_path: bool = True,
) -> list[dict[str, Any]]:
    """Assign occurrence-stable ``verity:v1:<hash>_<n>`` fingerprints in place."""
    grouped: dict[tuple[str, str], list[tuple[int, int, dict[str, Any]]]] = {}

    for index, finding in enumerate(findings):
        base_hash = compute_finding_fingerprint(
            finding, project_root=project_root, home_dir=home_dir
        )
        file_path = finding.get("file_path")
        canonical = (
            canonicalize_path(file_path, project_root=project_root, home_dir=home_dir)
            if file_path
            else ""
        )
        if update_file_path:
            finding["file_path"] = canonical
        line_number = finding.get("line_number")
        line_int = (
            line_number
            if isinstance(line_number, int) and not isinstance(line_number, bool)
            else 0
        )
        grouped.setdefault((canonical, base_hash), []).append((line_int, index, finding))

    for (_canonical, base_hash), items in grouped.items():
        items.sort(key=lambda item: (item[0], item[1]))
        for occurrence, (_line, _index, finding) in enumerate(items):
            finding["fingerprint"] = f"verity:v1:{base_hash}_{occurrence}"

    return findings
