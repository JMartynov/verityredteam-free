"""Unified Unknown Capability Profiler (UCP) Engine."""

from __future__ import annotations

from typing import Any

from verity.ucp.canonicalizer import (
    compute_tool_canonical_hash,
)
from verity.ucp.inference import CapabilityInferenceEngine
from verity.ucp.models import (
    CapabilityTag,
    CWEHypothesis,
    ProvenanceLabel,
    RugPullDetectionResult,
    ToolProfile,
    UnknownAuditPlan,
)
from verity.ucp.normalizer import MetadataNormalizer


class UnknownCapabilityProfiler:
    """Core engine for profiling unseen MCP tools without trusting target declarations."""

    @classmethod
    def profile_tool(cls, tool_def: dict[str, Any]) -> ToolProfile:
        """Profile a single MCP tool definition."""
        name = str(tool_def.get("name", ""))
        raw_desc = str(tool_def.get("description", ""))
        input_schema = (
            tool_def.get("inputSchema", {}) if isinstance(tool_def.get("inputSchema"), dict) else {}
        )
        output_schema = (
            tool_def.get("outputSchema") if isinstance(tool_def.get("outputSchema"), dict) else None
        )
        annotations = (
            tool_def.get("annotations", {}) if isinstance(tool_def.get("annotations"), dict) else {}
        )

        # 1. Canonical Hash (order-independent SHA-256)
        canonical_hash = compute_tool_canonical_hash(tool_def)

        # 2. Metadata Inspection & Defanging
        has_unicode_anomalies = MetadataNormalizer.detect_unicode_anomalies(
            name
        ) or MetadataNormalizer.detect_unicode_anomalies(raw_desc)
        has_prompt_injection = MetadataNormalizer.detect_prompt_injection(
            name
        ) or MetadataNormalizer.detect_prompt_injection(raw_desc)
        sanitized_desc = MetadataNormalizer.sanitize_text(raw_desc)

        # 3. Capability Tag Inference
        inferred = tuple(
            CapabilityInferenceEngine.infer_capabilities(
                tool_name=name,
                description=raw_desc,
                input_schema=input_schema,
                annotations=annotations,
            )
        )

        # 4. Declared vs Inferred Mutation Check
        # Annotations like readOnlyHint=True are untrusted declarations
        is_declared_read_only = bool(annotations.get("readOnlyHint") is True)
        is_mutating_declared = not is_declared_read_only

        # If profiler inferred DESTRUCTIVE_WRITE or DATA_WRITE, it is mutating
        mutating_tags = {CapabilityTag.DATA_WRITE, CapabilityTag.DESTRUCTIVE_WRITE}
        is_mutating_inferred = any(cap.tag in mutating_tags for cap in inferred)

        return ToolProfile(
            tool_name=name,
            canonical_hash=canonical_hash,
            raw_description=raw_desc,
            sanitized_description=sanitized_desc,
            input_schema=input_schema,
            output_schema=output_schema,
            untrusted_annotations=annotations,
            inferred_capabilities=inferred,
            has_unicode_anomalies=has_unicode_anomalies,
            has_prompt_injection_indicators=has_prompt_injection,
            is_mutating_declared=is_mutating_declared,
            is_mutating_inferred=is_mutating_inferred,
            provenance=ProvenanceLabel.UNTRUSTED_TARGET_DECLARATION,
        )

    @classmethod
    def profile_toolset(cls, tools: list[dict[str, Any]]) -> dict[str, ToolProfile]:
        """Profile a full collection of MCP tools returned by tools/list."""
        profiles: dict[str, ToolProfile] = {}
        for tool_def in tools:
            if isinstance(tool_def, dict) and "name" in tool_def:
                profile = cls.profile_tool(tool_def)
                profiles[profile.tool_name] = profile
        return profiles

    @classmethod
    def detect_rug_pull(
        cls,
        authorized_hashes: dict[str, str],
        current_tools: list[dict[str, Any]],
    ) -> list[RugPullDetectionResult]:
        """Compare current live tools/list against authorized tool canonical hashes."""
        results: list[RugPullDetectionResult] = []
        current_profiles = cls.profile_toolset(current_tools)

        # 1. Check all authorized tools against current live tools
        for tool_name, auth_hash in authorized_hashes.items():
            if tool_name not in current_profiles:
                results.append(
                    RugPullDetectionResult(
                        tool_name=tool_name,
                        is_rug_pull=True,
                        authorized_hash=auth_hash,
                        current_hash="",
                        changed_fields=("tool_removed",),
                        details=(
                            f"Authorized tool '{tool_name}' was removed by target mid-session."
                        ),
                    )
                )
            else:
                current_profile = current_profiles[tool_name]
                if current_profile.canonical_hash != auth_hash:
                    results.append(
                        RugPullDetectionResult(
                            tool_name=tool_name,
                            is_rug_pull=True,
                            authorized_hash=auth_hash,
                            current_hash=current_profile.canonical_hash,
                            changed_fields=("definition_or_schema_modified",),
                            details=(
                                f"Authorized tool '{tool_name}' definition changed mid-session "
                                f"(baseline: {auth_hash[:16]}..., "
                                f"current: {current_profile.canonical_hash[:16]}...)."
                            ),
                        )
                    )
                else:
                    results.append(
                        RugPullDetectionResult(
                            tool_name=tool_name,
                            is_rug_pull=False,
                            authorized_hash=auth_hash,
                            current_hash=auth_hash,
                            changed_fields=(),
                            details=f"Tool '{tool_name}' matches authorized canonical hash.",
                        )
                    )

        # 2. Check for unexpected newly injected tools not in authorization profile
        for tool_name, current_profile in current_profiles.items():
            if tool_name not in authorized_hashes:
                results.append(
                    RugPullDetectionResult(
                        tool_name=tool_name,
                        is_rug_pull=True,
                        authorized_hash="",
                        current_hash=current_profile.canonical_hash,
                        changed_fields=("unauthorized_tool_injected",),
                        details=(
                            f"Target injected unauthorized new tool '{tool_name}' mid-session."
                        ),
                    )
                )

        return results

    @classmethod
    def build_unknown_audit_plan(
        cls,
        server_id: str,
        tools: list[dict[str, Any]],
    ) -> UnknownAuditPlan:
        """Construct an empirical audit plan with prioritized CWE hypotheses for an unknown MCP server."""
        tool_profiles = cls.profile_toolset(tools)
        all_hypotheses: list[CWEHypothesis] = []
        seen_keys: set[tuple[str, str]] = set()

        for profile in tool_profiles.values():
            hypotheses = CapabilityInferenceEngine.infer_cwe_hypotheses(
                tool_name=profile.tool_name,
                description=profile.raw_description,
                input_schema=profile.input_schema,
                inferred_capabilities=profile.inferred_capabilities,
            )
            for hyp in hypotheses:
                key = (hyp.cwe_id, hyp.affected_tool)
                if key not in seen_keys:
                    seen_keys.add(key)
                    all_hypotheses.append(hyp)

        # Sort hypotheses by confidence descending and severity (CRITICAL > HIGH > MEDIUM > LOW)
        severity_weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        all_hypotheses.sort(
            key=lambda h: (severity_weight.get(h.severity, 0), h.confidence),
            reverse=True,
        )

        recommended_checks = tuple(dict.fromkeys(h.suggested_check_file for h in all_hypotheses))

        return UnknownAuditPlan(
            server_id=server_id,
            tool_profiles=tool_profiles,
            hypotheses=tuple(all_hypotheses),
            recommended_checks=recommended_checks,
        )

