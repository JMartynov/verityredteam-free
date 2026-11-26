"""Report rendering helpers for terminal, Markdown, and HTML outputs."""

from __future__ import annotations

from verity.reporting.html import render_scan_html, render_test_html
from verity.reporting.markdown import render_scan_markdown, render_test_markdown
from verity.reporting.sbom import (
    build_audit_records,
    build_compliance_scorecard,
    build_inventory_snapshot,
    compare_inventory_snapshots,
    enrich_findings_with_owasp,
    load_inventory_baseline,
    render_scan_cyclonedx,
    render_scan_spdx,
    save_inventory_baseline,
)
from verity.reporting.terminal import render_scan_terminal, render_test_terminal

__all__ = [
    "build_audit_records",
    "build_compliance_scorecard",
    "build_inventory_snapshot",
    "compare_inventory_snapshots",
    "enrich_findings_with_owasp",
    "load_inventory_baseline",
    "render_scan_cyclonedx",
    "render_scan_html",
    "render_scan_markdown",
    "render_scan_spdx",
    "render_scan_terminal",
    "render_test_html",
    "render_test_markdown",
    "render_test_terminal",
    "save_inventory_baseline",
]
