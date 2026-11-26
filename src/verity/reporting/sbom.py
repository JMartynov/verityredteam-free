"""OWASP mapping, CycloneDX/SPDX SBOM, compliance scorecards, and inventory drift."""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

INVENTORY_SCHEMA_VERSION = 1

OWASP_MCP_CATEGORIES: dict[str, str] = {
    "MCP01": "Insecure Credential Management",
    "MCP02": "Excessive Agency",
    "MCP03": "Overly Broad Permissions",
    "MCP04": "Supply Chain Compromise",
    "MCP05": "Command Injection",
    "MCP06": "Insecure Deserialization",
    "MCP07": "Authentication Bypass",
    "MCP08": "Insufficient Sandboxing",
    "MCP09": "Tool Poisoning",
    "MCP10": "Insufficient Logging & Monitoring",
}

_SEVERITY_DEDUCTIONS: dict[str, int] = {
    "CRITICAL": 20,
    "HIGH": 15,
    "MEDIUM": 5,
    "LOW": 1,
    "INFO": 0,
}

_REACHABILITY_STATE: dict[str, str] = {
    "REACHABLE": "exploitable",
    "NOT_IMPORTED": "not_affected",
    "UNREACHABLE": "not_affected",
    "UNREACHABLE_IMPORT": "not_affected",
    "UNKNOWN": "unknown",
}


def _rule_to_owasp(rule_id: str, cwe_id: str = "") -> tuple[str, str, str]:
    """Map a rule_id/cwe_id pair to an (MCP id, LLM id, category) triple."""
    rule = (rule_id or "").upper()
    cwe = (cwe_id or "").upper()

    if "TYPOSQUAT" in rule:
        return "MCP04", "LLM03:2025", OWASP_MCP_CATEGORIES["MCP04"]
    if "CONFLICT" in rule:
        return "MCP03", "LLM00", OWASP_MCP_CATEGORIES["MCP03"]
    if "TOOL-POISONING" in rule or "TOOL_POISONING" in rule:
        return "MCP03", "LLM00", OWASP_MCP_CATEGORIES["MCP03"]
    if "BOLA" in rule or "CWE-862" in cwe:
        return "MCP02", "LLM06:2025", OWASP_MCP_CATEGORIES["MCP02"]
    if "TRAVERSAL" in rule or "CWE-22" in cwe:
        return "MCP02", "LLM06:2025", OWASP_MCP_CATEGORIES["MCP02"]
    if "SSRF" in rule or "CWE-918" in cwe:
        return "MCP01", "LLM02:2025", OWASP_MCP_CATEGORIES["MCP01"]
    if "EXFIL" in rule:
        return "MCP01", "LLM02:2025", OWASP_MCP_CATEGORIES["MCP01"]
    if "SECRET" in rule or "CWE-798" in cwe or "CREDENTIAL" in rule:
        return "MCP01", "LLM06:2025", OWASP_MCP_CATEGORIES["MCP01"]
    if "CWE-78" in cwe or "COMMAND" in rule or "SYSTEM" in rule:
        return "MCP05", "LLM05:2025", OWASP_MCP_CATEGORIES["MCP05"]
    if "CWE-94" in cwe or "CWE-95" in cwe or "EVAL" in rule or "CODE" in rule:
        return "MCP05", "LLM05:2025", OWASP_MCP_CATEGORIES["MCP05"]
    if "CWE-89" in cwe or "SQL" in rule:
        return "MCP05", "LLM05:2025", OWASP_MCP_CATEGORIES["MCP05"]
    if "INJECT" in rule or "PROMPT" in rule or "CWE-74" in cwe:
        return "MCP09", "LLM01:2025", OWASP_MCP_CATEGORIES["MCP09"]
    if "UNPINNED" in rule or "CWE-1104" in cwe or "CWE-829" in cwe:
        return "MCP04", "LLM03:2025", OWASP_MCP_CATEGORIES["MCP04"]
    return "MCP04", "LLM03:2025", OWASP_MCP_CATEGORIES["MCP04"]


def enrich_findings_with_owasp(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return copies of ``findings`` annotated with OWASP MCP/LLM identifiers."""
    enriched: list[dict[str, Any]] = []
    for finding in findings or []:
        new_finding: dict[str, Any] = dict(finding)
        mcp_id, llm_id, category = _rule_to_owasp(
            str(finding.get("rule_id") or finding.get("issue_id") or ""),
            str(finding.get("cwe_id") or finding.get("cwe_ids") or ""),
        )
        new_finding.setdefault("owasp_mcp_id", mcp_id)
        new_finding.setdefault("owasp_llm_id", llm_id)
        new_finding.setdefault("owasp_category", category)
        if not new_finding.get("owasp_mcp_id"):
            new_finding["owasp_mcp_id"] = mcp_id
        if not new_finding.get("owasp_llm_id"):
            new_finding["owasp_llm_id"] = llm_id
        if not new_finding.get("owasp_category"):
            new_finding["owasp_category"] = category
        enriched.append(new_finding)
    return enriched


def build_compliance_scorecard(
    findings: list[dict[str, Any]],
    standard: str = "owasp-mcp-top-10",
) -> dict[str, Any]:
    """Compute a per-category OWASP compliance scorecard from enriched findings."""
    findings = list(findings or [])
    categories: dict[str, dict[str, Any]] = {}
    for cat in OWASP_MCP_CATEGORIES:
        categories[cat] = {
            "name": OWASP_MCP_CATEGORIES[cat],
            "count": 0,
            "severity_counts": {sev: 0 for sev in _SEVERITY_DEDUCTIONS},
        }

    deduction = 0
    for finding in findings:
        mcp_id = str(finding.get("owasp_mcp_id") or "")
        if mcp_id not in categories:
            mcp_id = _rule_to_owasp(
                str(finding.get("rule_id") or ""),
                str(finding.get("cwe_id") or ""),
            )[0]
        if mcp_id not in categories:
            mcp_id = "MCP04"
        severity = str(finding.get("severity") or "INFO").upper()
        if severity not in _SEVERITY_DEDUCTIONS:
            severity = "INFO"
        categories[mcp_id]["count"] += 1
        categories[mcp_id]["severity_counts"][severity] += 1
        deduction += _SEVERITY_DEDUCTIONS[severity]

    score = max(0, 100 - deduction)
    if score >= 90:
        tier = "COMPLIANT"
    elif score >= 70:
        tier = "PARTIAL"
    else:
        tier = "NON_COMPLIANT"

    return {
        "standard": standard,
        "score": score,
        "tier": tier,
        "findings_count": len(findings),
        "categories": categories,
    }


def _parse_cwe_ids(cwe_id: Any) -> list[int]:
    if cwe_id is None:
        return []
    parts = cwe_id if isinstance(cwe_id, (list, tuple)) else [cwe_id]
    text = " ".join(str(c) for c in parts)
    return [int(m) for m in re.findall(r"CWE-(\d+)", text, flags=re.IGNORECASE)]


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", text).strip("-") or "package"


def _component_name(record: Any) -> str:
    if isinstance(record, dict):
        return str(
            record.get("matched_package")
            or record.get("server_name")
            or "unknown"
        )
    return str(
        getattr(record, "matched_package", None)
        or getattr(record, "server_name", "unknown")
    )


def _component_version(record: Any) -> str:
    if isinstance(record, dict):
        return str(record.get("matched_version") or "0.0.0")
    return str(getattr(record, "matched_version", None) or "0.0.0")


def _component_purl(record: Any) -> str:
    purl = (
        record.get("matched_purl")
        if isinstance(record, dict)
        else getattr(record, "matched_purl", None)
    )
    if purl:
        return str(purl)
    return (
        f"pkg:mcp/{_slug(_component_name(record))}"
        f"@{_component_version(record)}"
    )


def _cyclonedx_components(records: list[Any]) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    for record in records or []:
        purl = _component_purl(record)
        components.append(
            {
                "type": "application",
                "bom-ref": purl,
                "name": _component_name(record),
                "version": _component_version(record),
                "purl": purl,
            }
        )
    return components


def _cyclonedx_vulns(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    vulns: list[dict[str, Any]] = []
    for finding in findings:
        vuln_id = str(
            finding.get("cve_id")
            or finding.get("advisory_id")
            or finding.get("rule_id")
            or "UNKNOWN"
        )
        reach = str(finding.get("reachability") or "UNKNOWN").upper()
        state = _REACHABILITY_STATE.get(reach, "unknown")
        entry: dict[str, Any] = {
            "id": vuln_id,
            "analysis": {"state": state},
        }
        cwes = _parse_cwe_ids(finding.get("cwe_id"))
        if cwes:
            entry["cwes"] = cwes
        title = finding.get("title")
        if title:
            entry["description"] = str(title)
        message = finding.get("message")
        if message:
            entry["detail"] = str(message)
        props: list[dict[str, str]] = []
        if finding.get("owasp_mcp_id"):
            props.append(
                {"name": "verity:owasp:mcp", "value": str(finding["owasp_mcp_id"])}
            )
        if finding.get("owasp_llm_id"):
            props.append(
                {"name": "verity:owasp:llm", "value": str(finding["owasp_llm_id"])}
            )
        if props:
            entry["properties"] = props
        vulns.append(entry)
    return vulns


def render_scan_cyclonedx(
    records: list[Any],
    findings: list[dict[str, Any]] | None = None,
    include_vulns: bool = False,
    configs: list[Any] | None = None,
) -> dict[str, Any]:
    """Render scan inventory/records as a CycloneDX 1.6 JSON document."""
    enriched = enrich_findings_with_owasp(list(findings or []))
    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC)
            .isoformat()
            .replace("+00:00", "Z"),
            "tools": [
                {
                    "vendor": "Verity",
                    "name": "Verity MCP Security Scanner",
                    "version": "0.2.1",
                }
            ],
        },
        "components": _cyclonedx_components(list(records or [])),
    }
    if include_vulns:
        bom["vulnerabilities"] = _cyclonedx_vulns(enriched)
    return bom


def render_scan_spdx(
    records: list[Any],
    configs: list[Any] | None = None,
) -> dict[str, Any]:
    """Render scan inventory/records as an SPDX 2.3 JSON document."""
    packages: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []

    for index, record in enumerate(records or [], start=1):
        name = _component_name(record)
        version = _component_version(record)
        spdx_id = f"SPDXRef-Package-{index}-{_slug(name)}"
        package: dict[str, Any] = {
            "SPDXID": spdx_id,
            "name": name,
            "versionInfo": version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
        purl = _component_purl(record)
        if purl:
            package["externalRefs"] = [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": purl,
                }
            ]
        packages.append(package)
        relationships.append(
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": spdx_id,
            }
        )

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Verity-MCP-SBOM",
        "documentNamespace": f"https://verity.dev/spdx/{uuid.uuid4()}",
        "creationInfo": {
            "created": datetime.now(UTC)
            .isoformat()
            .replace("+00:00", "Z"),
            "creators": ["Tool: Verity-0.2.1"],
        },
        "packages": packages,
        "relationships": relationships,
    }


def _server_identity(record: Any) -> str:
    name = _component_name(record)
    if isinstance(record, dict):
        config_path = str(record.get("config_path") or "")
        client_type = str(record.get("client_type") or "")
    else:
        config_path = str(getattr(record, "config_path", "") or "")
        ct = getattr(record, "client_type", "")
        client_type = str(getattr(ct, "value", ct) or "")
    return f"{client_type}::{name}::{config_path}"


def build_inventory_snapshot(
    records: list[Any],
    configs: list[Any] | None = None,
) -> dict[str, Any]:
    """Build a serializable MCP inventory snapshot from audit records."""
    servers: dict[str, dict[str, Any]] = {}
    for record in records or []:
        key = _server_identity(record)
        if isinstance(record, dict):
            entry = {
                "server_name": str(record.get("server_name") or ""),
                "client_type": str(record.get("client_type") or ""),
                "config_path": str(record.get("config_path") or ""),
                "matched_package": record.get("matched_package"),
                "matched_version": record.get("matched_version"),
                "matched_purl": record.get("matched_purl"),
                "tools_exposed": list(record.get("tools_exposed") or []),
            }
        else:
            ct = getattr(record, "client_type", "")
            entry = {
                "server_name": str(getattr(record, "server_name", "")),
                "client_type": str(getattr(ct, "value", ct) or ""),
                "config_path": str(getattr(record, "config_path", "") or ""),
                "matched_package": getattr(record, "matched_package", None),
                "matched_version": getattr(record, "matched_version", None),
                "matched_purl": getattr(record, "matched_purl", None),
                "tools_exposed": list(
                    getattr(record, "tools_exposed", ()) or ()
                ),
            }
        servers[key] = entry
    return {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "generated_at": datetime.now(UTC)
        .isoformat()
        .replace("+00:00", "Z"),
        "servers": servers,
    }


def compare_inventory_snapshots(
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
) -> dict[str, Any]:
    """Compare two inventory snapshots and report additions/removals/changes."""
    before_servers: dict[str, Any] = (before or {}).get("servers") or {}
    after_servers: dict[str, Any] = (after or {}).get("servers") or {}

    before_keys = set(before_servers)
    after_keys = set(after_servers)

    added_keys = sorted(after_keys - before_keys)
    removed_keys = sorted(before_keys - after_keys)
    changed_keys = sorted(
        key
        for key in before_keys & after_keys
        if before_servers.get(key) != after_servers.get(key)
    )

    has_drift = bool(added_keys or removed_keys or changed_keys)

    return {
        "has_drift": has_drift,
        "added_servers": [after_servers[k] for k in added_keys],
        "removed_servers": [before_servers[k] for k in removed_keys],
        "changed_servers": [after_servers[k] for k in changed_keys],
        "added_count": len(added_keys),
        "removed_count": len(removed_keys),
        "changed_count": len(changed_keys),
    }


def save_inventory_baseline(path: str | Path, snapshot: dict[str, Any]) -> None:
    """Persist an inventory snapshot to ``path`` as JSON."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(snapshot, indent=2, sort_keys=True), encoding="utf-8"
    )


def load_inventory_baseline(path: str | Path) -> dict[str, Any]:
    """Load an inventory snapshot from ``path``."""
    target = Path(path)
    if not target.is_file():
        raise FileNotFoundError(f"Inventory baseline not found: {path}")
    return json.loads(target.read_text(encoding="utf-8"))


def build_audit_records(configs: list[Any] | None) -> list[Any]:
    """Convert ``DiscoveredServerConfig``/dict entries into ``ServerAuditRecord``."""
    try:
        from verity.discovery.models import ClientType, ServerAuditRecord
    except Exception:  # pragma: no cover - defensive
        return []

    records: list[Any] = []
    for cfg in configs or []:
        if isinstance(cfg, ServerAuditRecord):
            records.append(cfg)
            continue

        if isinstance(cfg, dict):
            server_name = str(cfg.get("server_name") or "")
            client_type_raw = cfg.get("client_type") or "custom"
            config_path = str(cfg.get("config_path") or "")
            matched_package = cfg.get("matched_package")
            matched_version = cfg.get("matched_version")
            matched_purl = cfg.get("matched_purl")
            tools_exposed = tuple(cfg.get("tools_exposed") or ())
        else:
            server_name = str(getattr(cfg, "server_name", "") or "")
            client_type_raw = getattr(cfg, "client_type", "custom")
            config_path = str(getattr(cfg, "config_path", "") or "")
            matched_package = getattr(cfg, "matched_package", None)
            matched_version = getattr(cfg, "matched_version", None)
            matched_purl = getattr(cfg, "matched_purl", None)
            tools_exposed = tuple(getattr(cfg, "tools_exposed", ()) or ())

        client_type_value = getattr(client_type_raw, "value", None)
        if client_type_value is None:
            client_type_value = str(client_type_raw)
        try:
            client_type = ClientType(str(client_type_value))
        except (ValueError, TypeError):
            client_type = ClientType.CUSTOM

        records.append(
            ServerAuditRecord(
                server_name=server_name,
                client_type=client_type,
                config_path=config_path,
                matched_package=matched_package,
                matched_version=matched_version,
                matched_purl=matched_purl,
                tools_exposed=tools_exposed,
            )
        )
    return records
