"""Cross-server MCP tool-name collision detection."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from verity.discovery.models import DiscoveredServerConfig, LiveServerCapability

logger = logging.getLogger("verity.scanner.conflicts")


def _schema_signature(tool: dict[str, Any]) -> tuple[str, frozenset[str], frozenset[str]]:
    description = str(tool.get("description") or "").strip()
    schema = tool.get("inputSchema") or {}
    props = schema.get("properties") if isinstance(schema, dict) else {}
    required = schema.get("required") if isinstance(schema, dict) else []
    prop_keys = frozenset(props.keys()) if isinstance(props, dict) else frozenset()
    required_set = frozenset(required) if isinstance(required, list) else frozenset()
    return description, prop_keys, required_set


class ConflictDetector:
    """Detects tool name collisions across MCP servers with divergent semantics."""

    def scan_configs(
        self,
        configs: list[DiscoveredServerConfig],
        live_capabilities: list[LiveServerCapability] | None = None,
    ) -> list[dict[str, Any]]:
        tool_owners: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)

        for cfg in configs:
            raw = cfg.raw_config if isinstance(cfg.raw_config, dict) else {}
            tools = raw.get("tools")
            if isinstance(tools, list):
                for tool in tools:
                    if isinstance(tool, dict) and tool.get("name"):
                        tool_owners[str(tool["name"])].append((cfg.server_name, tool))

        for capability in live_capabilities or []:
            for tool in capability.tools:
                if isinstance(tool, dict) and tool.get("name"):
                    tool_owners[str(tool["name"])].append(
                        (capability.server_name, tool)
                    )

        findings: list[dict[str, Any]] = []
        for tool_name, owners in tool_owners.items():
            distinct_servers = {server for server, _ in owners}
            if len(distinct_servers) < 2:
                continue
            if not self._has_divergence([tool for _, tool in owners]):
                continue
            findings.append(
                {
                    "rule_id": "VERITY-CONFLICT-001",
                    "scanner": "conflict",
                    "severity": "HIGH",
                    "cwe_id": "CWE-693",
                    "cwe_ids": ["CWE-693"],
                    "title": f"Cross-server tool collision: '{tool_name}'",
                    "message": (
                        f"Tool '{tool_name}' is exposed by multiple servers "
                        f"with divergent semantics: {sorted(distinct_servers)}"
                    ),
                    "mcp_tool": tool_name,
                    "server_names": sorted(distinct_servers),
                }
            )
        return findings

    @staticmethod
    def _has_divergence(tool_specs: list[dict[str, Any]]) -> bool:
        if len(tool_specs) < 2:
            return False
        first = _schema_signature(tool_specs[0])
        return any(_schema_signature(other) != first for other in tool_specs[1:])
