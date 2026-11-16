"""Universal Client Discovery, Matcher & Consolidated Audit Service."""

from verity.discovery.active_bridge import ActiveExploitBridge, ActiveExploitPlan
from verity.discovery.auditor import ConsolidatedSecurityAuditor
from verity.discovery.config_scanner import MultiClientConfigScanner
from verity.discovery.matcher import HybridDiscoveryMatcher
from verity.discovery.models import (
    ClientType,
    ConsolidatedAuditReport,
    DiscoveredServerConfig,
    FindingSeverity,
    LiveServerCapability,
    SecurityAuditFinding,
    ServerAuditRecord,
    TransportType,
)

__all__ = [
    "ActiveExploitBridge",
    "ActiveExploitPlan",
    "ClientType",
    "ConsolidatedAuditReport",
    "ConsolidatedSecurityAuditor",
    "DiscoveredServerConfig",
    "FindingSeverity",
    "HybridDiscoveryMatcher",
    "LiveServerCapability",
    "MultiClientConfigScanner",
    "SecurityAuditFinding",
    "ServerAuditRecord",
    "TransportType",
]
