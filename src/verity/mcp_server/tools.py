"""Tool definitions and implementations for the Verity Discovery & Security Audit MCP Server."""

from __future__ import annotations

import logging
from typing import Any

from verity.mcp_server.bootstrap import ServerContext
from verity.mcp_server.handlers import (
    DatabaseGuardHandlerMixin,
    DatabaseOracleHandlerMixin,
    LegacyToolsHandlerMixin,
    RemediationHandlerMixin,
    SecurityScanHandlerMixin,
)
from verity.mcp_server.protocols import DatabaseOracleProtocol
from verity.mcp_server.schemas import (
    LEGACY_TOOL_DEFINITIONS,
    TOOL_DEFINITIONS,
    UNIFIED_TOOL_DEFINITIONS,
)

logger = logging.getLogger("verity.mcp_server.tools")

__all__ = [
    "LEGACY_TOOL_DEFINITIONS",
    "TOOL_DEFINITIONS",
    "UNIFIED_TOOL_DEFINITIONS",
    "VerityToolDispatcher",
]


class VerityToolDispatcher(
    SecurityScanHandlerMixin,
    DatabaseGuardHandlerMixin,
    DatabaseOracleHandlerMixin,
    RemediationHandlerMixin,
    LegacyToolsHandlerMixin,
):
    """Dispatches tool calls against the ServerContext, guards, and discovery transports."""

    def __init__(
        self,
        context: ServerContext,
        oracle: DatabaseOracleProtocol | None = None,
        load_plugins: bool = True,
    ) -> None:
        self.context = context
        self._oracle: DatabaseOracleProtocol | None = oracle
        self._guards: dict[str, Any] = {}
        self._plan_provider: Any = None
        self._canary_manifest: dict[str, str] | None = None
        self._remediation_pro_enabled: bool = False
        self.loaded_plugins: list[str] = []
        if load_plugins:
            from verity.mcp_server.plugin_loader import (
                discover_and_load_plugins,
                register_in_tree_pro_defaults,
            )

            self.loaded_plugins = discover_and_load_plugins(self)
            register_in_tree_pro_defaults(self)

    def register_guard(self, name: str, guard: Any) -> None:
        self._guards[name] = guard

    def set_database_oracle(self, oracle: DatabaseOracleProtocol) -> None:
        self._oracle = oracle

    def set_plan_provider(self, provider: Any) -> None:
        self._plan_provider = provider

    def set_canary_manifest(self, manifest: dict[str, str]) -> None:
        self._canary_manifest = manifest

    def set_remediation_pro_enabled(self, enabled: bool = True) -> None:
        self._remediation_pro_enabled = enabled

    @property
    def oracle(self) -> DatabaseOracleProtocol:
        """Lazily instantiate and return the database verification oracle."""
        if self._oracle is None:
            from verity.mcp_server.protocols import BasicResponseOracle

            self._oracle = BasicResponseOracle()
        return self._oracle

    @staticmethod
    def _log_tool_event(tool_name: str, args: dict[str, Any], res: dict[str, Any]) -> None:
        """Write clean event log to artifacts/mcp_stream.log and artifacts/demo.log."""
        from verity.mcp_server.stream_logger import log_tool_event

        log_tool_event(tool_name, args, res)

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Dispatch and execute an MCP tool invocation."""
        res: dict[str, Any]

        # 1. Unified Tools Dispatch
        if tool_name == "verity_security_scan":
            res = self._execute_security_scan(arguments)
        elif tool_name == "verity_database_guard":
            res = self._execute_database_guard(arguments)
        elif tool_name == "verity_database_oracle":
            res = self._execute_database_oracle(arguments)
        elif tool_name == "verity_remediation_ops":
            res = self._execute_remediation_ops(arguments)
        else:
            # 2. Legacy Atomic Tools Dispatch
            norm_name = tool_name.removeprefix("verity_")
            if norm_name in ("discover_mcp_endpoints", "audit_target"):
                res = self._discover_mcp_endpoints(arguments)
            elif norm_name in ("discover_client_environment", "scan_environment"):
                res = self._discover_client_environment(arguments)
            elif norm_name in ("fingerprint_mcp_server", "fingerprint_target"):
                res = self._fingerprint_mcp_server(arguments)
            elif norm_name in ("lookup_mcp_vulnerabilities", "lookup_vulnerabilities"):
                res = self._lookup_mcp_vulnerabilities(arguments)
            elif norm_name == "audit_and_generate_exploit_plan":
                res = self._audit_and_generate_exploit_plan(arguments)
            elif norm_name == "health_check":
                res = self.health_check()
            else:
                res = {
                    "ok": False,
                    "error": f"Unknown tool: '{tool_name}'",
                }

        self._log_tool_event(tool_name, arguments, res)
        return res

    # =========================================================================

    # Unified Tool 1: verity_security_scan
    # =========================================================================

    def health_check(self) -> dict[str, Any]:
        """Verify health of context and database engines."""
        from verity.mcp_server.server import health_check

        return health_check()

    def verity_health_check(self) -> dict[str, Any]:
        """Alias for health_check."""
        return self.health_check()

    def __getattr__(self, name: str) -> Any:
        """Allow calling dispatcher.<tool_name>(**kwargs) or
        dispatcher.verity_<tool_name>(**kwargs).
        """

        clean_name = name.removeprefix("verity_")
        if clean_name == "health_check":
            return self.health_check

        def _caller(**kwargs: Any) -> dict[str, Any]:
            return self.execute_tool(clean_name, kwargs)

        return _caller

    # =========================================================================
    # Internal / Legacy Helper Methods
    # =========================================================================

