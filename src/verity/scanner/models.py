"""Data models for Static MCP Code and AST Vulnerability Scanner."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

import verity


class ScannerSeverity(StrEnum):
    """Vulnerability severity levels for static code analysis."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True)
class AstFinding:
    """Represents a single static vulnerability finding identified by AST inspection."""

    rule_id: str
    cwe_id: str
    severity: ScannerSeverity
    title: str
    message: str
    file_path: str
    line_number: int
    column_number: int = 0
    end_line_number: int | None = None
    end_column_number: int | None = None
    snippet: str = ""
    remediation: str = ""
    mcp_tool_context: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to standard dictionary representation."""
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class ScanReport:
    """Aggregated report of static code security scan across MCP servers or source trees."""

    target_path: str
    scanned_files: list[str] = field(default_factory=list)
    findings: list[AstFinding] = field(default_factory=list)
    scan_duration_ms: float = 0.0
    error_count: int = 0

    @property
    def total_findings(self) -> int:
        """Return total number of scanner findings."""
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        """Return count of CRITICAL severity findings."""
        return sum(1 for f in self.findings if f.severity == ScannerSeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Return count of HIGH severity findings."""
        return sum(1 for f in self.findings if f.severity == ScannerSeverity.HIGH)

    @property
    def medium_count(self) -> int:
        """Return count of MEDIUM severity findings."""
        return sum(1 for f in self.findings if f.severity == ScannerSeverity.MEDIUM)

    @property
    def low_count(self) -> int:
        """Return count of LOW severity findings."""
        return sum(1 for f in self.findings if f.severity == ScannerSeverity.LOW)

    @property
    def info_count(self) -> int:
        """Return count of INFO severity findings."""
        return sum(1 for f in self.findings if f.severity == ScannerSeverity.INFO)

    def to_dict(self) -> dict[str, Any]:
        """Convert scan report to dictionary."""
        return {
            "summary": {
                "target_path": self.target_path,
                "scanned_files_count": len(self.scanned_files),
                "total_findings": self.total_findings,
                "scan_duration_ms": round(self.scan_duration_ms, 2),
                "error_count": self.error_count,
                "severity_counts": {
                    "CRITICAL": self.critical_count,
                    "HIGH": self.high_count,
                    "MEDIUM": self.medium_count,
                    "LOW": self.low_count,
                    "INFO": self.info_count,
                },
            },
            "scanned_files": self.scanned_files,
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_sarif(self) -> dict[str, Any]:
        """Export findings to standardized OASIS SARIF v2.1.0 format."""
        rules_map: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []

        level_map = {
            ScannerSeverity.CRITICAL: "error",
            ScannerSeverity.HIGH: "error",
            ScannerSeverity.MEDIUM: "warning",
            ScannerSeverity.LOW: "note",
            ScannerSeverity.INFO: "none",
        }

        for finding in self.findings:
            if finding.rule_id not in rules_map:
                sec_sev = "5.0"
                if finding.severity == ScannerSeverity.CRITICAL:
                    sec_sev = "9.0"
                elif finding.severity == ScannerSeverity.HIGH:
                    sec_sev = "7.5"
                elif finding.severity == ScannerSeverity.LOW:
                    sec_sev = "2.5"

                rules_map[finding.rule_id] = {
                    "id": finding.rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.message},
                    "help": {"text": finding.remediation or finding.message},
                    "properties": {
                        "cwe": [finding.cwe_id],
                        "precision": "high",
                        "security-severity": sec_sev,
                    },
                }

            result_entry: dict[str, Any] = {
                "ruleId": finding.rule_id,
                "level": level_map.get(finding.severity, "warning"),
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file_path},
                            "region": {
                                "startLine": max(1, finding.line_number),
                                "startColumn": max(1, finding.column_number),
                                "snippet": {"text": finding.snippet},
                            },
                        }
                    }
                ],
            }
            results.append(result_entry)

        sarif_schema = (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/"
            "sarif-schema-2.1.0.json"
        )
        return {
            "$schema": sarif_schema,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Verity-AST-Scanner",
                            "semanticVersion": verity.__version__,
                            "informationUri": "https://github.com/JMartynov/verityredteam",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

    def format_text(self, use_color: bool = True) -> str:
        """Format the report into clean terminal output."""
        c_reset = "\033[0m" if use_color else ""
        c_bold = "\033[1m" if use_color else ""
        c_red = "\033[31m" if use_color else ""
        c_yellow = "\033[33m" if use_color else ""
        c_cyan = "\033[36m" if use_color else ""
        c_gray = "\033[90m" if use_color else ""
        c_green = "\033[32m" if use_color else ""

        border = "═" * 75
        divider = "─" * 75

        lines = [
            f"{c_bold}{border}{c_reset}",
            f"{c_bold}  🔍 VERITY STATIC MCP CODE & AST VULNERABILITY AUDIT REPORT{c_reset}",
            f"{c_bold}{border}{c_reset}",
            f"  Target: {c_cyan}{self.target_path}{c_reset}",
            f"  Scanned Files: {len(self.scanned_files)} files in {self.scan_duration_ms:.2f}ms",
            (
                f"  Findings: {c_red if self.total_findings else c_green}"
                f"{self.total_findings} total{c_reset} "
                f"({c_red}{self.critical_count} CRITICAL{c_reset}, "
                f"{c_yellow}{self.high_count} HIGH{c_reset}, "
                f"{self.medium_count} MEDIUM, {self.low_count} LOW)"
            ),
            f"{c_bold}{divider}{c_reset}",
        ]

        if not self.findings:
            clean_msg = "✅ No AST security vulnerabilities or dangerous patterns identified."
            lines.append(f"  {c_green}{clean_msg}{c_reset}")
        else:
            for idx, f in enumerate(self.findings, 1):
                sev_color = (
                    c_red
                    if f.severity in (ScannerSeverity.CRITICAL, ScannerSeverity.HIGH)
                    else c_yellow
                    if f.severity == ScannerSeverity.MEDIUM
                    else c_gray
                )
                tool_ctx = f" (Tool: {f.mcp_tool_context})" if f.mcp_tool_context else ""
                lines.append(
                    f"  {idx}. [{sev_color}{f.severity.value}{c_reset}] {c_bold}{f.title}{c_reset} "
                    f"({f.cwe_id} | {f.rule_id}){tool_ctx}"
                )
                loc_str = f"{f.file_path}:{f.line_number}:{f.column_number}"
                lines.append(f"     Location: {c_cyan}{loc_str}{c_reset}")
                if f.snippet:
                    lines.append(f"     Snippet:  {c_gray}{f.snippet.strip()}{c_reset}")
                lines.append(f"     Details:  {f.message}")
                if f.remediation:
                    lines.append(f"     Fix:      {c_green}{f.remediation}{c_reset}")
                lines.append("")

        lines.append(f"{c_bold}{border}{c_reset}")
        return "\n".join(lines)
