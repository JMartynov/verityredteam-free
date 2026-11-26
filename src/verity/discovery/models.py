"""Data models for Universal MCP Client Discovery, Matcher & Consolidated Audit Service."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ClientType(StrEnum):
    """Supported LLM clients and IDE MCP configurations."""

    CLAUDE_DESKTOP = "claude_desktop"
    CLAUDE_CODE = "claude_code"
    CURSOR = "cursor"
    VSCODE_CLINE = "vscode_cline"
    VSCODE_ROO = "vscode_roo"
    GOOSE = "goose"
    CONTINUE = "continue"
    WINDSURF = "windsurf"
    ZED = "zed"
    VSCODE = "vscode"
    JUNIE = "junie"
    ANTIGRAVITY = "antigravity"
    OPENHANDS = "openhands"
    TRAE = "trae"
    LMSTUDIO = "lmstudio"
    LIBRECHAT = "librechat"
    WORKSPACE = "workspace"
    CUSTOM = "custom"

    @classmethod
    def from_str(cls, value: str) -> ClientType:
        """Resolve a case-insensitive token or alias into a ``ClientType``."""
        token = str(value).strip().lower().replace("-", "_")
        if not token:
            raise ValueError(f"Unknown client type: {value!r}")
        aliases: dict[str, ClientType] = {
            "claude": cls.CLAUDE_DESKTOP,
            "cline": cls.VSCODE_CLINE,
            "roo": cls.VSCODE_ROO,
            "roo_code": cls.VSCODE_ROO,
            "copilot": cls.VSCODE,
            "github_copilot": cls.VSCODE,
            "lm_studio": cls.LMSTUDIO,
            "open_hands": cls.OPENHANDS,
        }
        if token in aliases:
            return aliases[token]
        try:
            return cls(token)
        except ValueError:
            raise ValueError(f"Unknown client type: {value!r}") from None


class TransportType(StrEnum):
    """Transport mechanism used to communicate with the MCP server."""

    STDIO = "stdio"
    SSE = "sse"
    HTTP = "http"
    WEBSOCKET = "websocket"
    UNKNOWN = "unknown"


class FindingSeverity(StrEnum):
    """Security finding severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True)
class DiscoveredServerConfig:
    """Represents a statically discovered MCP server configuration."""

    client_type: ClientType
    server_name: str
    command: str | None = None
    args: tuple[str, ...] = ()
    env: dict[str, str] = field(default_factory=dict)
    env_keys: tuple[str, ...] = ()
    transport_type: TransportType = TransportType.STDIO
    url: str | None = None
    config_path: str = ""
    is_disabled: bool = False
    raw_config: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize discovered server config to a dictionary."""
        return {
            "client_type": self.client_type.value,
            "server_name": self.server_name,
            "command": self.command,
            "args": list(self.args),
            "env_keys": list(self.env_keys),
            "transport_type": self.transport_type.value,
            "url": self.url,
            "config_path": self.config_path,
            "is_disabled": self.is_disabled,
        }


@dataclass(frozen=True)
class LiveServerCapability:
    """Represents live dynamically inspected capabilities of an MCP server."""

    server_name: str
    protocol_version: str = "2024-11-05"
    tools: tuple[dict[str, Any], ...] = ()
    prompts: tuple[dict[str, Any], ...] = ()
    resources: tuple[dict[str, Any], ...] = ()
    is_responsive: bool = True
    error_message: str | None = None
    response_time_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize live server capabilities to a dictionary."""
        return {
            "server_name": self.server_name,
            "protocol_version": self.protocol_version,
            "tool_count": len(self.tools),
            "prompt_count": len(self.prompts),
            "resource_count": len(self.resources),
            "is_responsive": self.is_responsive,
            "error_message": self.error_message,
            "response_time_ms": round(self.response_time_ms, 2),
            "tools": list(self.tools),
            "prompts": list(self.prompts),
            "resources": list(self.resources),
        }


@dataclass(frozen=True)
class SecurityAuditFinding:
    """Represents a discrete security finding, vulnerability match, or configuration flaw."""

    issue_id: str
    severity: FindingSeverity
    title: str
    description: str
    server_name: str
    client_type: ClientType
    config_path: str = ""
    cve_id: str | None = None
    cwe_ids: tuple[str, ...] = ()
    cvss_score: float | None = None
    vulnerable_tools: tuple[str, ...] = ()
    remediation: str = ""
    redacted_evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize security audit finding to a dictionary."""
        return {
            "issue_id": self.issue_id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "server_name": self.server_name,
            "client_type": self.client_type.value,
            "config_path": self.config_path,
            "cve_id": self.cve_id,
            "cwe_ids": list(self.cwe_ids),
            "cvss_score": self.cvss_score,
            "vulnerable_tools": list(self.vulnerable_tools),
            "remediation": self.remediation,
            "redacted_evidence": self.redacted_evidence,
        }


@dataclass(frozen=True)
class ServerAuditRecord:
    """Comprehensive audit result for a single concrete MCP server."""

    server_name: str
    client_type: ClientType
    config_path: str
    matched_package: str | None = None
    matched_purl: str | None = None
    matched_version: str | None = None
    confidence_score: float = 0.0
    match_layer: str = "NONE"
    is_live_inspected: bool = False
    tools_exposed: tuple[str, ...] = ()
    findings: tuple[SecurityAuditFinding, ...] = ()
    highest_severity: FindingSeverity = FindingSeverity.INFO
    live_probe_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize live server capabilities to a dictionary."""
        return {
            "server_name": self.server_name,
            "client_type": self.client_type.value,
            "config_path": self.config_path,
            "matched_package": self.matched_package,
            "matched_purl": self.matched_purl,
            "matched_version": self.matched_version,
            "confidence_score": round(self.confidence_score, 4),
            "match_layer": self.match_layer,
            "is_live_inspected": self.is_live_inspected,
            "tools_exposed": list(self.tools_exposed),
            "highest_severity": self.highest_severity.value,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class ConsolidatedAuditReport:
    """Aggregated audit report covering all discovered clients and servers."""

    scanned_clients: list[str] = field(default_factory=list)
    scanned_files: list[str] = field(default_factory=list)
    servers_discovered: int = 0
    servers_audited: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    server_records: list[ServerAuditRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize consolidated audit report to a dictionary."""
        return {
            "summary": {
                "scanned_clients": self.scanned_clients,
                "scanned_files_count": len(self.scanned_files),
                "servers_discovered": self.servers_discovered,
                "servers_audited": self.servers_audited,
                "total_findings": self.total_findings,
                "severity_counts": {
                    "CRITICAL": self.critical_count,
                    "HIGH": self.high_count,
                    "MEDIUM": self.medium_count,
                    "LOW": self.low_count,
                    "INFO": self.info_count,
                },
            },
            "scanned_files": self.scanned_files,
            "servers": [s.to_dict() for s in self.server_records],
        }
