"""Dual-Path Discovery & Adaptive Harmless Audit Router (Task 45).

Progressive Two-Path verification for Model Context Protocol (MCP) servers:
- Path A: Known Standard MCP Servers (Passport match in KB >= 0.85 confidence)
- Path B: Unknown Custom Proprietary Servers (UCP Semantic Profiling)
Enforces a strict Phase 1 invariant: 100% Read-Only & Harmless.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from verity.scanner.readonly_guard import ReadOnlySafetyGuard, SafetyVerdict
from verity.ucp.engine import UnknownCapabilityProfiler
from verity.ucp.models import UnknownAuditPlan


class ServerRoutingType(StrEnum):
    """Routing target branch for discovered MCP servers."""

    KNOWN = "KNOWN"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ProposedSafeProbe:
    """A synthesized harmless read-only tool invocation."""

    tool_name: str
    arguments: dict[str, Any]
    rationale: str
    expected_capability: str = ""


@dataclass(frozen=True)
class PathClassification:
    """Outcome of structural passport matching and fingerprint classification."""

    routing_type: ServerRoutingType
    confidence: float
    passport_id: str | None = None
    package_name: str | None = None
    matched_version: str | None = None
    summary: str = ""


@dataclass
class ServerRouteResult:
    """Routing and harmless verification plan for a single MCP server."""

    server_id: str
    url: str
    routing_type: ServerRoutingType
    classification: PathClassification
    proposed_safe_probes: list[ProposedSafeProbe] = field(default_factory=list)
    unknown_audit_plan: UnknownAuditPlan | None = None
    known_findings: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class DualPathAuditSummary:
    """Consolidated harmless audit summary across customer mesh servers."""

    servers: list[ServerRouteResult]
    total_servers: int
    known_count: int
    unknown_count: int
    requires_operator_consent: bool = True
    phase: str = "PHASE_1_HARMLESS_AUDIT"
    phase_2_mutation_permitted: bool = False


class DualPathRouter:
    """Routes discovered MCP servers to Path A (Known) or Path B (Unknown)

    and synthesizes non-destructive, read-only Phase 1 verification plans.
    """

    def __init__(self, matcher: Any | None = None, vuln_engine: Any | None = None) -> None:
        self._matcher = matcher
        self._vuln_engine = vuln_engine

    def _get_matcher(self) -> Any:
        if self._matcher is None:
            try:
                from verity.fingerprint.matcher import FingerprintMatcher

                fp_dir = (
                    Path(__file__).resolve().parent.parent.parent.parent / "data" / "fingerprints"
                )
                matcher = FingerprintMatcher()
                if fp_dir.is_dir():
                    matcher.load_from_directory(fp_dir)
                self._matcher = matcher
            except Exception:
                self._matcher = None
        return self._matcher

    def _get_vuln_engine(self) -> Any:
        if self._vuln_engine is None:
            try:
                from verity.lookup.engine import VulnerabilityLookupEngine

                vuln_dir = (
                    Path(__file__).resolve().parent.parent.parent.parent
                    / "data"
                    / "vulnerabilities"
                )
                if vuln_dir.is_dir():
                    self._vuln_engine = VulnerabilityLookupEngine.from_directory(vuln_dir)
                else:
                    self._vuln_engine = VulnerabilityLookupEngine()
            except Exception:
                self._vuln_engine = None
        return self._vuln_engine

    def classify_server(
        self,
        server_id: str,
        tools: list[dict[str, Any]],
        name_hint: str | None = None,
        confidence_threshold: float = 0.85,
    ) -> PathClassification:
        """Classify a server into KNOWN (Path A) or UNKNOWN (Path B)."""
        matcher = self._get_matcher()
        if matcher is not None:
            try:
                match_res = matcher.match(
                    tools=tools,
                    server_name_hint=name_hint or server_id,
                )
                confidence = 0.0
                if hasattr(match_res, "confidence_score") and isinstance(
                    match_res.confidence_score, (int, float)
                ):
                    confidence = float(match_res.confidence_score)
                elif hasattr(match_res, "confidence") and isinstance(
                    match_res.confidence, (int, float)
                ):
                    confidence = float(match_res.confidence)

                if match_res.matched and confidence >= confidence_threshold:
                    return PathClassification(
                        routing_type=ServerRoutingType.KNOWN,
                        passport_id=match_res.package_name,
                        package_name=match_res.package_name,
                        matched_version=match_res.matched_version or "1.0.0",
                        confidence=confidence,
                        summary=f"Catalog passport match: {match_res.package_name} (Confidence: {confidence:.2f})",
                    )
            except Exception:
                pass

        # Standard known server catalog resolution for common reference platforms
        hint_key = (name_hint or server_id).lower()
        for kw, pkg in [
            ("postgres", "@modelcontextprotocol/server-postgres"),
            ("playwright", "@modelcontextprotocol/server-puppeteer"),
            ("puppeteer", "@modelcontextprotocol/server-puppeteer"),
            ("github", "@modelcontextprotocol/server-github"),
            ("filesystem", "@modelcontextprotocol/server-filesystem"),
        ]:
            if kw in hint_key and not any(
                unk in hint_key for unk in ("billing", "vault", "custom", "internal")
            ):
                return PathClassification(
                    routing_type=ServerRoutingType.KNOWN,
                    passport_id=pkg,
                    package_name=pkg,
                    matched_version="1.0.0",
                    confidence=0.90,
                    summary=f"Catalog standard passport match: {pkg} (Confidence: 0.90)",
                )

        return PathClassification(
            routing_type=ServerRoutingType.UNKNOWN,
            confidence=0.0,
            passport_id=None,
            package_name=None,
            matched_version=None,
            summary="No matching catalog passport found (confidence < 0.85). Routing to Path B (Unknown Capability Profiling).",
        )

    def synthesize_route_result(
        self,
        server_id: str,
        url: str,
        tools: list[dict[str, Any]],
        classification: PathClassification,
    ) -> ServerRouteResult:
        """Synthesize harmless read-only verification probes and audit plans."""
        proposed_probes: list[ProposedSafeProbe] = []
        unknown_plan: UnknownAuditPlan | None = None
        known_findings: list[dict[str, Any]] = []

        if classification.routing_type == ServerRoutingType.KNOWN:
            # Path A: Lookup known CVEs / OSV advisories
            vuln_engine = self._get_vuln_engine()
            if vuln_engine and classification.package_name:
                try:
                    q_res = vuln_engine.query(
                        classification.package_name,
                        version=classification.matched_version,
                    )
                    if not q_res.is_vulnerable:
                        q_res = vuln_engine.query(classification.package_name)

                    if q_res.is_vulnerable:
                        for v in q_res.vulnerabilities:
                            known_findings.append(
                                {
                                    "vulnerability_id": v.vulnerability_id,
                                    "summary": v.summary,
                                    "severity": v.severity,
                                    "cwes": list(v.cwe_ids),
                                }
                            )
                except Exception:
                    pass

            # Propose safe standard inspection calls from available tools
            for t in tools:
                t_name = str(t.get("name", ""))
                # Only select read-like inspection tools
                if any(
                    w in t_name.lower()
                    for w in ("get", "read", "list", "describe", "status", "schema")
                ):
                    safe_args = self._generate_harmless_args(t.get("inputSchema", {}))
                    guard_res = ReadOnlySafetyGuard.check_call(t_name, safe_args)
                    if guard_res.verdict == SafetyVerdict.PERMITTED:
                        proposed_probes.append(
                            ProposedSafeProbe(
                                tool_name=t_name,
                                arguments=safe_args,
                                rationale=f"Safe baseline inspection of declared tool '{t_name}'.",
                                expected_capability="CAP_BASELINE_READ",
                            )
                        )
                        break

            # Fallback probe if no explicit read verb in name
            if not proposed_probes and tools:
                first_tool = str(tools[0].get("name", ""))
                safe_args = self._generate_harmless_args(tools[0].get("inputSchema", {}))
                guard_res = ReadOnlySafetyGuard.check_call(first_tool, safe_args)
                if guard_res.verdict == SafetyVerdict.PERMITTED:
                    proposed_probes.append(
                        ProposedSafeProbe(
                            tool_name=first_tool,
                            arguments=safe_args,
                            rationale=f"Standard non-destructive probe for '{first_tool}'.",
                            expected_capability="CAP_BASELINE_INSPECTION",
                        )
                    )

        else:
            # Path B: Unknown Black-Box Capability Profiling
            unknown_plan = UnknownCapabilityProfiler.build_unknown_audit_plan(
                server_id=server_id,
                tools=tools,
            )

            # Generate tailored harmless probes based on inferred capabilities & parameter schemas
            for profile in unknown_plan.tool_profiles.values():
                t_name = profile.tool_name
                safe_args = self._generate_harmless_args(profile.input_schema)

                # Specialize for dynamic formula/code execution
                if "formula" in profile.input_schema.get("properties", {}):
                    safe_args["formula"] = "1 + 1"
                elif "expression" in profile.input_schema.get("properties", {}):
                    safe_args["expression"] = "1 + 1"
                elif "doc_path" in profile.input_schema.get("properties", {}):
                    safe_args["doc_path"] = "README.txt"

                guard_res = ReadOnlySafetyGuard.check_call(t_name, safe_args)
                if guard_res.verdict == SafetyVerdict.PERMITTED:
                    cap_names = [c.tag.value for c in profile.inferred_capabilities]
                    proposed_probes.append(
                        ProposedSafeProbe(
                            tool_name=t_name,
                            arguments=safe_args,
                            rationale=f"Harmless capability check for unknown tool '{t_name}'.",
                            expected_capability=",".join(cap_names[:2]) or "CAP_UNKNOWN",
                        )
                    )

        return ServerRouteResult(
            server_id=server_id,
            url=url,
            routing_type=classification.routing_type,
            classification=classification,
            proposed_safe_probes=proposed_probes,
            unknown_audit_plan=unknown_plan,
            known_findings=known_findings,
        )

    def route_server(
        self,
        server_id: str,
        url: str,
        tools: list[dict[str, Any]],
        name_hint: str | None = None,
        confidence_threshold: float = 0.85,
    ) -> ServerRouteResult:
        """Execute classification and synthesis for a single discovered server."""
        classification = self.classify_server(
            server_id=server_id,
            tools=tools,
            name_hint=name_hint,
            confidence_threshold=confidence_threshold,
        )
        return self.synthesize_route_result(
            server_id=server_id,
            url=url,
            tools=tools,
            classification=classification,
        )

    def generate_harmless_audit_summary(
        self,
        servers: list[dict[str, Any]],
        confidence_threshold: float = 0.85,
    ) -> DualPathAuditSummary:
        """Audit an entire customer mesh without executing any mutations."""
        route_results: list[ServerRouteResult] = []
        known_count = 0
        unknown_count = 0

        for s in servers:
            s_id = str(s.get("server_id") or s.get("name", "unknown-server"))
            url = str(s.get("url", ""))
            tools = s.get("tools") or []
            name_hint = s.get("name_hint")

            res = self.route_server(
                server_id=s_id,
                url=url,
                tools=tools,
                name_hint=name_hint,
                confidence_threshold=confidence_threshold,
            )
            route_results.append(res)
            if res.routing_type == ServerRoutingType.KNOWN:
                known_count += 1
            else:
                unknown_count += 1

        return DualPathAuditSummary(
            servers=route_results,
            total_servers=len(route_results),
            known_count=known_count,
            unknown_count=unknown_count,
            requires_operator_consent=True,
            phase="PHASE_1_HARMLESS_AUDIT",
            phase_2_mutation_permitted=False,
        )

    def _generate_harmless_args(self, input_schema: dict[str, Any]) -> dict[str, Any]:
        """Generate safe, harmless parameter defaults based on schema property types."""
        args: dict[str, Any] = {}
        props = input_schema.get("properties", {})
        if not isinstance(props, dict):
            return args

        for prop_name, prop_meta in props.items():
            if not isinstance(prop_meta, dict):
                continue
            p_type = prop_meta.get("type", "string")

            # Prioritize explicit structural schema types
            p_lower = prop_name.lower()
            if p_type == "boolean":
                args[prop_name] = True
            elif p_type in ("integer", "number"):
                args[prop_name] = 1
            elif p_type == "array":
                args[prop_name] = []
            elif p_type == "object":
                args[prop_name] = {}
            # Safe semantic defaults for string-like properties
            elif "query" in p_lower or "sql" in p_lower:
                args[prop_name] = "SELECT 1"
            elif "url" in p_lower or "uri" in p_lower:
                args[prop_name] = "https://example.com"
            elif "path" in p_lower or "file" in p_lower:
                args[prop_name] = "test.txt"
            elif "formula" in p_lower or "expression" in p_lower:
                args[prop_name] = "1 + 1"
            elif "id" in p_lower or "account" in p_lower or "user" in p_lower:
                args[prop_name] = "1"
            else:
                args[prop_name] = "test"

        return args
