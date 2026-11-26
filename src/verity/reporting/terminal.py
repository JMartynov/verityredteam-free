"""Terminal report renderers built on :mod:`rich`."""

from __future__ import annotations

import io
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.table import Table

PRO_UPGRADE_FOOTER = (
    "Upgrade to Verity Pro for Snowflake RBAC guards, live DB canary oracles, "
    "and SARIF CI/CD exports."
)

_SEVERITY_STYLES: dict[str, str] = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "bold cyan",
    "INFO": "bold blue",
}

_STATUS_STYLES: dict[str, str] = {
    "PASS": "bold green",
    "FAIL": "bold red",
}


def _severity_badge(severity: str | None) -> str:
    sev = str(severity or "INFO").upper()
    style = _SEVERITY_STYLES.get(sev, "bold")
    return f"[{style}] {sev} [/]"


def _status_badge(status: str | None) -> str:
    st = str(status or "FAIL").upper()
    style = _STATUS_STYLES.get(st, "bold")
    return f"[{style}] {st} [/]"


def _field(record: dict[str, Any], *keys: str, default: str = "-") -> str:
    for key in keys:
        value = record.get(key)
        if value not in (None, ""):
            return str(value)
    return default


def _new_console() -> Console:
    return Console(record=True, width=100, file=io.StringIO())


def render_scan_terminal(report_data: dict[str, Any]) -> str:
    """Render a scan report to plain terminal text."""
    console = _new_console()

    summary = report_data.get("summary") or {}
    findings = report_data.get("findings") or []
    severity_counts = summary.get("severity_counts") or {}

    console.print("[bold]Verity Scan Report[/bold]")

    overview = Table(title="Summary", show_header=True, header_style="bold")
    overview.add_column("Metric")
    overview.add_column("Value", justify="right")
    overview.add_row("Scanned files", str(summary.get("scanned_files_count", 0)))
    overview.add_row("Total findings", str(summary.get("total_findings", len(findings))))
    overview.add_row(
        "Duration (ms)", str(round(float(summary.get("scan_duration_ms") or 0.0), 2))
    )
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        overview.add_row(sev, str(severity_counts.get(sev, 0)))
    console.print(overview)

    table = Table(title="Findings", show_header=True, header_style="bold")
    table.add_column("Severity")
    table.add_column("Rule", no_wrap=True)
    table.add_column("Title")
    table.add_column("Location")

    if findings:
        for finding in findings:
            severity = _severity_badge(str(finding.get("severity", "INFO")))
            rule_id = escape(_field(finding, "rule_id"))
            title = escape(_field(finding, "title", "message", "description"))
            path = escape(_field(finding, "file_path", "target_name"))
            line = escape(_field(finding, "line_number"))
            table.add_row(severity, rule_id, title, f"{path}:{line}")
    else:
        table.add_row("-", "-", "No findings detected.", "-")

    console.print(table)

    suppressed_counts = summary.get("suppressed_counts") or {}
    suppressed_findings = report_data.get("suppressed_findings") or []
    if suppressed_counts or suppressed_findings:
        counts_table = Table(
            title="Suppressed Findings", show_header=True, header_style="bold"
        )
        counts_table.add_column("Source")
        counts_table.add_column("Count", justify="right")
        for source in ("baseline", "ignore_file", "policy", "inline", "other"):
            counts_table.add_row(source, str(int(suppressed_counts.get(source, 0) or 0)))
        counts_table.add_row(
            "total",
            str(int(suppressed_counts.get("total", len(suppressed_findings)) or 0)),
        )
        console.print(counts_table)

        if suppressed_findings:
            detail = Table(
                title="Suppressed Findings Detail",
                show_header=True,
                header_style="bold",
            )
            detail.add_column("Severity")
            detail.add_column("Rule", no_wrap=True)
            detail.add_column("Location")
            detail.add_column("Reason")
            for finding in suppressed_findings:
                suppression = finding.get("suppression") or {}
                path = escape(_field(finding, "file_path", "target_name"))
                line = escape(_field(finding, "line_number"))
                detail.add_row(
                    _severity_badge(str(finding.get("severity", "INFO"))),
                    escape(_field(finding, "rule_id")),
                    f"{path}:{line}",
                    escape(
                        str(
                            suppression.get("reason")
                            or suppression.get("source")
                            or ""
                        )
                    ),
                )
            console.print(detail)

    resolved = summary.get("resolved_since_baseline")
    if resolved is not None:
        console.print(f"Resolved since baseline: {resolved}")
    for warning in summary.get("expired_ignore_warnings") or []:
        console.print(f"[yellow]{escape(str(warning))}[/yellow]")

    console.print(f"[italic]{PRO_UPGRADE_FOOTER}[/italic]")
    return console.export_text()


def render_test_terminal(results: list[dict[str, Any]]) -> str:
    """Render probe/test results to plain terminal text."""
    console = _new_console()

    table = Table(title="Verity Test Results", show_header=True, header_style="bold")
    table.add_column("Status")
    table.add_column("Check")
    table.add_column("Severity")
    table.add_column("Message")

    if results:
        for result in results:
            status = _status_badge(str(result.get("status", "FAIL")))
            name = escape(_field(result, "name"))
            severity = escape(_field(result, "severity"))
            message = escape(_field(result, "message", "details"))
            table.add_row(status, name, severity, message)
    else:
        table.add_row("-", "-", "-", "No checks executed.")

    console.print(table)

    passed = sum(1 for r in results if str(r.get("status", "")).upper() == "PASS")
    failed = len(results) - passed
    console.print(f"Passed: [green]{passed}[/green]  Failed: [red]{failed}[/red]")
    console.print(f"[italic]{PRO_UPGRADE_FOOTER}[/italic]")
    return console.export_text()
