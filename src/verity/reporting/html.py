"""Standalone HTML5 report renderers."""

from __future__ import annotations

import html
from typing import Any

PRO_UPGRADE_FOOTER = (
    "Upgrade to Verity Pro for Snowflake RBAC guards, live DB canary oracles, "
    "and SARIF CI/CD exports."
)

_STYLE = """
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
       margin: 2rem; color: #1f2328; }
h1 { font-size: 1.6rem; }
table { border-collapse: collapse; width: 100%; margin-bottom: 1.5rem; }
th, td { border: 1px solid #d0d7de; padding: 0.4rem 0.6rem; text-align: left; vertical-align: top; }
th { background: #f6f8fa; }
.badge { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 0.4rem;
         font-size: 0.8rem; font-weight: 600; color: #fff; }
.sev-CRITICAL { background: #a40e26; }
.sev-HIGH { background: #cf222e; }
.sev-MEDIUM { background: #bf8700; }
.sev-LOW { background: #1a7f37; }
.sev-INFO { background: #0969da; }
.status-PASS { background: #1a7f37; }
.status-FAIL { background: #cf222e; }
.footer { margin-top: 2rem; font-style: italic; color: #57606a; }
"""


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _field(record: dict[str, Any], *keys: str, default: str = "-") -> str:
    for key in keys:
        value = record.get(key)
        if value not in (None, ""):
            return str(value)
    return default


def _severity_badge(severity: Any) -> str:
    sev = str(severity or "INFO").upper()
    return f'<span class="badge sev-{_e(sev)}">{_e(sev)}</span>'


def _status_badge(status: Any) -> str:
    st = str(status or "FAIL").upper()
    return f'<span class="badge status-{_e(st)}">{_e(st)}</span>'


def _document(title: str, body: str) -> str:
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{_e(title)}</title>\n"
        f"<style>{_STYLE}</style>\n"
        "</head>\n"
        "<body>\n"
        f"{body}\n"
        f'<p class="footer">{_e(PRO_UPGRADE_FOOTER)}</p>\n'
        "</body>\n"
        "</html>\n"
    )


def render_scan_html(report_data: dict[str, Any]) -> str:
    """Render a scan report as a standalone HTML5 document."""
    summary = report_data.get("summary") or {}
    findings = report_data.get("findings") or []
    severity_counts = summary.get("severity_counts") or {}

    rows: list[str] = [
        "<h1>Verity Scan Report</h1>",
        "<h2>Summary</h2>",
        "<table>",
        "<thead><tr><th>Metric</th><th>Value</th></tr></thead>",
        "<tbody>",
        f"<tr><td>Scanned files</td><td>{_e(summary.get('scanned_files_count', 0))}</td></tr>",
        f"<tr><td>Total findings</td><td>{_e(summary.get('total_findings', len(findings)))}</td></tr>",
        f"<tr><td>Duration (ms)</td><td>{_e(round(float(summary.get('scan_duration_ms') or 0.0), 2))}</td></tr>",
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        rows.append(f"<tr><td>{sev}</td><td>{_e(severity_counts.get(sev, 0))}</td></tr>")
    rows.extend(["</tbody>", "</table>", "<h2>Findings</h2>"])

    if findings:
        rows.extend(
            [
                "<table>",
                "<thead><tr><th>Severity</th><th>Rule</th><th>CWE</th><th>Title</th>"
                "<th>Location</th><th>Remediation</th></tr></thead>",
                "<tbody>",
            ]
        )
        for finding in findings:
            path = _field(finding, "file_path", "target_name")
            line = _field(finding, "line_number")
            rows.append(
                "<tr>"
                f"<td>{_severity_badge(finding.get('severity'))}</td>"
                f"<td>{_e(_field(finding, 'rule_id'))}</td>"
                f"<td>{_e(_field(finding, 'cwe_id'))}</td>"
                f"<td>{_e(_field(finding, 'title', 'message', 'description'))}</td>"
                f"<td>{_e(f'{path}:{line}')}</td>"
                f"<td>{_e(_field(finding, 'remediation'))}</td>"
                "</tr>"
            )
        rows.extend(["</tbody>", "</table>"])
    else:
        rows.append("<p>No findings detected.</p>")

    return _document("Verity Scan Report", "\n".join(rows))


def render_test_html(results: list[dict[str, Any]]) -> str:
    """Render probe/test results as a standalone HTML5 document."""
    rows: list[str] = ["<h1>Verity Test Results</h1>"]
    if results:
        rows.extend(
            [
                "<table>",
                "<thead><tr><th>Status</th><th>Check</th><th>Severity</th>"
                "<th>Message</th></tr></thead>",
                "<tbody>",
            ]
        )
        for result in results:
            rows.append(
                "<tr>"
                f"<td>{_status_badge(result.get('status'))}</td>"
                f"<td>{_e(_field(result, 'name'))}</td>"
                f"<td>{_e(_field(result, 'severity'))}</td>"
                f"<td>{_e(_field(result, 'message', 'details'))}</td>"
                "</tr>"
            )
        rows.extend(["</tbody>", "</table>"])
    else:
        rows.append("<p>No checks executed.</p>")

    passed = sum(1 for r in results if str(r.get("status", "")).upper() == "PASS")
    failed = len(results) - passed
    rows.append(
        f"<p><strong>Passed:</strong> {_e(passed)} &nbsp; "
        f"<strong>Failed:</strong> {_e(failed)}</p>"
    )

    return _document("Verity Test Results", "\n".join(rows))
