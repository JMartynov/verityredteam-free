"""Verity Active Exploit Bridge for routing vulnerable MCP servers to VAIB."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from verity.discovery.models import FindingSeverity, ServerAuditRecord

logger = logging.getLogger("verity.discovery.active_bridge")


@dataclass
class ActiveExploitPlan:
    """Exploit test plan targeting a discovered concrete MCP server."""

    server_name: str
    target_purl: str
    target_version: str
    target_tools: list[str] = field(default_factory=list)
    cve_id: str | None = None
    cwe_ids: list[str] = field(default_factory=list)
    exploit_payload_family: str = "generic_injection"
    recommended_cli_command: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize active exploit bridge plan to a dictionary."""
        return {
            "server_name": self.server_name,
            "target_purl": self.target_purl,
            "target_version": self.target_version,
            "target_tools": self.target_tools,
            "cve_id": self.cve_id,
            "cwe_ids": self.cwe_ids,
            "exploit_payload_family": self.exploit_payload_family,
            "recommended_cli_command": self.recommended_cli_command,
        }


class ActiveExploitBridge:
    """Constructs deterministic VAIB red-team test plans for discovered vulnerable MCP servers."""

    DEFAULT_CLI_COMMAND_TEMPLATE = "verity test --command 'npx -y {package}'"

    @classmethod
    def generate_plans_for_record(
        cls,
        record: ServerAuditRecord,
        cli_command_template: str | None = None,
    ) -> list[ActiveExploitPlan]:
        """Convert security findings on a server into executable VAIB exploit plans."""
        template = cli_command_template or cls.DEFAULT_CLI_COMMAND_TEMPLATE
        plans: list[ActiveExploitPlan] = []
        if not record.matched_purl or not record.matched_version:
            return plans

        for f in record.findings:
            if f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH) and (
                f.cve_id or f.issue_id.startswith("VULN-")
            ):
                # Infer exploit family
                family = "generic_command_injection"
                if any("78" in c or "command" in c.lower() for c in f.cwe_ids):
                    family = "os_command_injection"
                elif any("22" in c or "path" in c.lower() for c in f.cwe_ids):
                    family = "path_traversal"
                elif any("89" in c or "sql" in c.lower() for c in f.cwe_ids):
                    family = "sql_injection"
                elif any("94" in c or "code" in c.lower() for c in f.cwe_ids):
                    family = "code_execution"

                cli_cmd = template.format(
                    package=record.matched_package,
                    vuln_id=f.cve_id or f.issue_id,
                )

                plans.append(
                    ActiveExploitPlan(
                        server_name=record.server_name,
                        target_purl=record.matched_purl,
                        target_version=record.matched_version,
                        target_tools=list(f.vulnerable_tools),
                        cve_id=f.cve_id,
                        cwe_ids=list(f.cwe_ids),
                        exploit_payload_family=family,
                        recommended_cli_command=cli_cmd,
                    )
                )

        return plans
