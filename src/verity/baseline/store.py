"""Baseline persistence, schema validation, and diffing for Verity."""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import verity
from verity.baseline.paths import canonicalize_path

BASELINE_SCHEMA_VERSION = "1.0"


class BaselineSchemaError(ValueError):
    """Raised when a baseline document fails schema validation."""


@dataclass
class BaselineDiffResult:
    """Result of diffing active findings against a stored baseline."""

    new_findings: list[dict[str, Any]] = field(default_factory=list)
    baseline_findings: list[dict[str, Any]] = field(default_factory=list)
    resolved_since_baseline: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize the diff result to a dictionary."""
        return {
            "new_findings": self.new_findings,
            "baseline_findings": self.baseline_findings,
            "resolved_since_baseline": self.resolved_since_baseline,
        }


def _serialize_entry(
    finding: dict[str, Any],
    project_root: Path | None,
    home_dir: Path | None,
) -> dict[str, Any]:
    file_path = finding.get("file_path")
    canonical = (
        canonicalize_path(file_path, project_root=project_root, home_dir=home_dir)
        if file_path
        else ""
    )
    return {
        "category": str(finding.get("category") or finding.get("cwe_id") or ""),
        "file_path": canonical,
        "fingerprint": finding.get("fingerprint"),
        "line_number": finding.get("line_number"),
        "rule_id": finding.get("rule_id"),
        "server_name": str(finding.get("server_name") or ""),
        "severity": finding.get("severity"),
        "tool_name": str(
            finding.get("tool_name")
            or finding.get("mcp_tool_context")
            or finding.get("target_name")
            or ""
        ),
    }


def save_baseline(
    path: str | Path,
    findings: list[dict[str, Any]],
    *,
    project_root: Path | None = None,
    home_dir: Path | None = None,
) -> Path:
    """Atomically persist a baseline document with no secrets or machine-specific paths."""
    entries = [_serialize_entry(finding, project_root, home_dir) for finding in findings]
    entries.sort(
        key=lambda entry: (
            str(entry.get("file_path") or ""),
            str(entry.get("rule_id") or ""),
            str(entry.get("fingerprint") or ""),
        )
    )

    version = getattr(verity, "__version__", "0.0.0")
    payload = {
        "entries": entries,
        "generated_by": f"verity-redteam-core/{version}",
        "schema_version": BASELINE_SCHEMA_VERSION,
    }
    serialized = json.dumps(payload, sort_keys=True, indent=2) + "\n"

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=str(target.parent),
        prefix=".verity-baseline-",
        suffix=".tmp",
        delete=False,
    ) as handle:
        handle.write(serialized)
        handle.flush()
        os.fsync(handle.fileno())
        temp_name = handle.name
    try:
        os.replace(temp_name, target)
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(temp_name)
        raise
    return target


def load_baseline(path: str | Path) -> dict[str, Any]:
    """Load and validate a baseline document."""
    target = Path(path)
    if not target.is_file():
        raise FileNotFoundError(f"Baseline file not found: {path}")
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineSchemaError(f"Unable to read baseline: {exc}") from exc

    if not isinstance(data, dict):
        raise BaselineSchemaError("Baseline root must be an object")
    if "schema_version" not in data or "entries" not in data:
        if all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in data.items()
        ):
            raise BaselineSchemaError(
                "Schema mismatch: baseline file appears to be a 'verity test' rug-pull "
                "tool-hash map, not a 'verity scan' baseline (verity-baseline.v1.json)."
            )
        raise BaselineSchemaError(
            "Invalid baseline schema: missing 'schema_version' or 'entries'"
        )
    if data.get("schema_version") != BASELINE_SCHEMA_VERSION:
        raise BaselineSchemaError(
            f"Unsupported baseline schema_version: {data.get('schema_version')!r}"
        )
    if not isinstance(data.get("entries"), list):
        raise BaselineSchemaError("Baseline 'entries' must be a list")
    return data


def validate_rug_pull_baseline_dict(payload: Any) -> dict[str, str]:
    """Validate a ``verity test`` rug-pull hash dict, rejecting ``verity scan`` baselines."""
    if not isinstance(payload, dict):
        raise BaselineSchemaError("Rug-pull baseline must be a JSON object")
    if "schema_version" in payload or "entries" in payload:
        raise BaselineSchemaError(
            "Schema mismatch: baseline file is a 'verity scan' baseline "
            "(verity-baseline.v1.json), not a 'verity test' rug-pull tool-hash map."
        )
    for key, value in payload.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise BaselineSchemaError(
                "Rug-pull baseline must map string tool names to string SHA-256 hashes"
            )
    return payload


def diff_baseline(
    findings: list[dict[str, Any]],
    baseline_data: dict[str, Any],
) -> BaselineDiffResult:
    """Diff active findings against a loaded baseline by fingerprint."""
    entries = baseline_data.get("entries", []) if isinstance(baseline_data, dict) else []
    known: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if isinstance(entry, dict) and entry.get("fingerprint"):
            known[str(entry["fingerprint"])] = entry

    matched: set[str] = set()
    new_findings: list[dict[str, Any]] = []
    baseline_findings: list[dict[str, Any]] = []

    for finding in findings:
        if "suppression" in finding:
            continue
        fingerprint = finding.get("fingerprint")
        if fingerprint and fingerprint in known:
            matched.add(str(fingerprint))
            finding["suppression"] = {
                "kind": "external",
                "source": "baseline",
                "reason": "present in baseline",
            }
            baseline_findings.append(finding)
        else:
            new_findings.append(finding)

    resolved_count = sum(1 for fp in known if fp not in matched)

    return BaselineDiffResult(
        new_findings=new_findings,
        baseline_findings=baseline_findings,
        resolved_since_baseline=resolved_count,
    )
