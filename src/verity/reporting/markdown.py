"""GitHub-Flavored Markdown report renderers."""

from __future__ import annotations

from typing import Any

PRO_UPGRADE_FOOTER = (
    "Upgrade to Verity Pro for Snowflake RBAC guards, live DB canary oracles, "
    "and SARIF CI/CD exports."
)


def _cell(value: Any) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\r", " ").replace("\n", " ")
    text = text.replace("|", "\\|")
    return text.strip() or "-"


def _field(record: dict[str, Any], *keys: str, default: str = "-") -> str:
    for key in keys:
        value = record.get(key)
        if value not in (None, ""):
            return str(value)
    return default


def render_scan_markdown(report_data: dict[str, Any]) -> str:
    """Render a scan report as GitHub-Flavored Markdown."""
    summary = report_data.get("summary") or {}
    findings = report_data.get("findings") or []
    severity_counts = summary.get("severity_counts") or {}

    lines: list[str] = ["# Verity Scan Report", "", "## Summary", ""]
    lines.append("| Metric | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Scanned files | {_cell(summary.get('scanned_files_count', 0))} |")
    lines.append(
        f"| Total findings | {_cell(summary.get('total_findings', len(findings)))} |"
    )
    duration = round(float(summary.get("scan_duration_ms") or 0.0), 2)
    lines.append(f"| Duration (ms) | {_cell(duration)} |")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        lines.append(f"| {sev} | {_cell(severity_counts.get(sev, 0))} |")

    lines.extend(["", "## Findings", ""])
    if findings:
        lines.append("| Severity | Rule | CWE | Title | Location | Remediation |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for finding in findings:
            path = _field(finding, "file_path", "target_name")
            line = _field(finding, "line_number")
            lines.append(
                "| {sev} | {rule} | {cwe} | {title} | {loc} | {rem} |".format(
                    sev=_cell(finding.get("severity", "INFO")),
                    rule=_cell(_field(finding, "rule_id")),
                    cwe=_cell(_field(finding, "cwe_id")),
                    title=_cell(_field(finding, "title", "message", "description")),
                    loc=_cell(f"{path}:{line}"),
                    rem=_cell(_field(finding, "remediation")),
                )
            )
    else:
        lines.append("_No findings detected._")

    suppressed_counts = summary.get("suppressed_counts") or {}
    suppressed_findings = report_data.get("suppressed_findings") or []
    if suppressed_counts or suppressed_findings:
        lines.extend(["", "## Suppressed Findings", ""])
        lines.append("| Source | Count |")
        lines.append("| --- | --- |")
        for source in ("baseline", "ignore_file", "policy", "inline", "other"):
            lines.append(f"| {source} | {_cell(suppressed_counts.get(source, 0))} |")
        lines.append(
            f"| total | {_cell(suppressed_counts.get('total', len(suppressed_findings)))} |"
        )
        if suppressed_findings:
            lines.extend(
                [
                    "",
                    "| Severity | Rule | Location | Reason |",
                    "| --- | --- | --- | --- |",
                ]
            )
            for finding in suppressed_findings:
                suppression = finding.get("suppression") or {}
                path = _field(finding, "file_path", "target_name")
                line = _field(finding, "line_number")
                lines.append(
                    "| {sev} | {rule} | {loc} | {reason} |".format(
                        sev=_cell(finding.get("severity", "INFO")),
                        rule=_cell(_field(finding, "rule_id")),
                        loc=_cell(f"{path}:{line}"),
                        reason=_cell(
                            suppression.get("reason") or suppression.get("source")
                        ),
                    )
                )

    resolved = summary.get("resolved_since_baseline")
    if resolved is not None:
        lines.extend(["", f"**Resolved since baseline:** {_cell(resolved)}"])
    for warning in summary.get("expired_ignore_warnings") or []:
        lines.append(f"- :warning: {_cell(warning)}")

    lines.extend(["", "---", "", f"_{PRO_UPGRADE_FOOTER}_", ""])
    return "\n".join(lines)


def render_test_markdown(results: list[dict[str, Any]]) -> str:
    """Render probe/test results as GitHub-Flavored Markdown."""
    lines: list[str] = ["# Verity Test Results", ""]
    if results:
        lines.append("| Status | Check | Severity | Message |")
        lines.append("| --- | --- | --- | --- |")
        for result in results:
            lines.append(
                "| {status} | {name} | {sev} | {msg} |".format(
                    status=_cell(str(result.get("status", "FAIL")).upper()),
                    name=_cell(_field(result, "name")),
                    sev=_cell(_field(result, "severity")),
                    msg=_cell(_field(result, "message", "details")),
                )
            )
    else:
        lines.append("_No checks executed._")

    passed = sum(1 for r in results if str(r.get("status", "")).upper() == "PASS")
    failed = len(results) - passed
    lines.extend(["", f"**Passed:** {passed} &nbsp;&nbsp; **Failed:** {failed}", ""])
    lines.extend(["---", "", f"_{PRO_UPGRADE_FOOTER}_", ""])
    return "\n".join(lines)
