"""Deterministic capability tag inference engine with confidence scoring and rule provenance."""

from __future__ import annotations

from typing import Any

from verity.ucp.models import CapabilityTag, CWEHypothesis, InferredCapability


class CapabilityInferenceEngine:
    """Infers capability tags from tool names, descriptions, input schemas, and annotations."""

    READ_PREFIXES = (
        "get_",
        "read_",
        "query_",
        "find_",
        "search_",
        "fetch_",
        "list_",
        "select_",
        "view_",
        "inspect_",
    )
    WRITE_PREFIXES = (
        "insert_",
        "create_",
        "update_",
        "set_",
        "modify_",
        "write_",
        "save_",
        "put_",
        "upsert_",
        "add_",
    )
    DESTRUCTIVE_PREFIXES = (
        "delete_",
        "remove_",
        "drop_",
        "truncate_",
        "purge_",
        "destroy_",
        "clear_",
        "revoke_",
    )
    SIDE_EFFECT_PREFIXES = (
        "send_",
        "notify_",
        "trigger_",
        "dispatch_",
        "execute_",
        "run_",
        "settle_",
    )

    @classmethod
    def infer_capabilities(
        cls,
        tool_name: str,
        description: str,
        input_schema: dict[str, Any],
        annotations: dict[str, Any] | None = None,
    ) -> list[InferredCapability]:
        """Infer capability tags with confidence scores and contributing rules."""
        capabilities: list[InferredCapability] = []
        name_lower = tool_name.lower()
        desc_lower = description.lower()
        props = input_schema.get("properties", {}) if isinstance(input_schema, dict) else {}
        prop_keys = [k.lower() for k in props]

        # 1. DESTRUCTIVE_WRITE
        if any(name_lower.startswith(prefix) for prefix in cls.DESTRUCTIVE_PREFIXES):
            capabilities.append(
                InferredCapability(
                    tag=CapabilityTag.DESTRUCTIVE_WRITE,
                    confidence=0.95,
                    contributing_rules=(
                        f"name_prefix:{name_lower.split('_')[0]}",
                        "destructive_action",
                    ),
                )
            )
        elif any(
            word in desc_lower
            for word in ("permanently delete", "destroy", "drop table", "truncate")
        ):
            capabilities.append(
                InferredCapability(
                    tag=CapabilityTag.DESTRUCTIVE_WRITE,
                    confidence=0.85,
                    contributing_rules=("description_destructive_keywords",),
                )
            )

        # 2. DATA_WRITE (if not already destructive or in addition to it)
        if any(name_lower.startswith(prefix) for prefix in cls.WRITE_PREFIXES):
            capabilities.append(
                InferredCapability(
                    tag=CapabilityTag.DATA_WRITE,
                    confidence=0.90,
                    contributing_rules=(
                        f"name_prefix:{name_lower.split('_')[0]}",
                        "write_mutation",
                    ),
                )
            )

        # 3. DATA_READ
        if (
            any(name_lower.startswith(prefix) for prefix in cls.READ_PREFIXES)
            or "read" in desc_lower
            or "query" in desc_lower
        ):
            capabilities.append(
                InferredCapability(
                    tag=CapabilityTag.DATA_READ,
                    confidence=0.90,
                    contributing_rules=("read_prefix_or_description",),
                )
            )

        # 4. TENANT_SELECTOR
        tenant_props = [
            k
            for k in prop_keys
            if any(t in k for t in ("tenant", "org_id", "workspace", "account_id"))
        ]
        if tenant_props:
            capabilities.append(
                InferredCapability(
                    tag=CapabilityTag.TENANT_SELECTOR,
                    confidence=0.95,
                    contributing_rules=(f"schema_properties:{','.join(tenant_props)}",),
                )
            )

        # 5. IDENTIFIER_LOOKUP
        id_props = [
            k for k in prop_keys if k.endswith("_id") or k in ("id", "key", "code", "reference")
        ]
        if id_props:
            capabilities.append(
                InferredCapability(
                    tag=CapabilityTag.IDENTIFIER_LOOKUP,
                    confidence=0.85,
                    contributing_rules=(f"schema_id_properties:{','.join(id_props)}",),
                )
            )

        # 6. FILE_ACCESS
        file_indicators = [
            k
            for k in prop_keys
            if any(f in k for f in ("file", "path", "stage", "upload", "download"))
        ]
        if file_indicators or any(f in name_lower for f in ("file", "stage", "export")):
            capabilities.append(
                InferredCapability(
                    tag=CapabilityTag.FILE_ACCESS,
                    confidence=0.90,
                    contributing_rules=("file_path_schema_or_name",),
                )
            )

        # 7. NETWORK_ACCESS
        net_props = [
            k
            for k in prop_keys
            if any(n in k for n in ("url", "endpoint", "webhook", "http", "host"))
        ]
        if net_props or any(n in name_lower for n in ("http", "fetch", "webhook")):
            capabilities.append(
                InferredCapability(
                    tag=CapabilityTag.NETWORK_ACCESS,
                    confidence=0.90,
                    contributing_rules=("network_url_schema_or_name",),
                )
            )

        # 8. EXTERNAL_SIDE_EFFECT
        if any(name_lower.startswith(prefix) for prefix in cls.SIDE_EFFECT_PREFIXES):
            capabilities.append(
                InferredCapability(
                    tag=CapabilityTag.EXTERNAL_SIDE_EFFECT,
                    confidence=0.85,
                    contributing_rules=("side_effect_name_prefix",),
                )
            )

        return capabilities

    @classmethod
    def infer_cwe_hypotheses(
        cls,
        tool_name: str,
        description: str,
        input_schema: dict[str, Any],
        inferred_capabilities: list[InferredCapability] | tuple[InferredCapability, ...] | None = None,
    ) -> list[CWEHypothesis]:
        """Infer prioritized CWE hypotheses with actionable check suggestions."""
        hypotheses: list[CWEHypothesis] = []
        name_lower = tool_name.lower()
        desc_lower = description.lower()
        props = input_schema.get("properties", {}) if isinstance(input_schema, dict) else {}
        prop_keys = [k.lower() for k in props]

        caps = {c.tag for c in inferred_capabilities} if inferred_capabilities else set()

        # 1. CWE-22: Path Traversal
        path_props = [
            k for k in prop_keys
            if any(p in k for p in ("path", "file", "dir", "filename", "filepath", "folder"))
        ]
        if path_props or CapabilityTag.FILE_ACCESS in caps or any(p in name_lower for p in ("file", "read_file", "path")):
            hypotheses.append(
                CWEHypothesis(
                    cwe_id="CWE-22",
                    name="Path Traversal (Arbitrary File Access)",
                    confidence=0.92 if path_props else 0.75,
                    severity="HIGH",
                    affected_tool=tool_name,
                    affected_parameters=tuple(path_props) if path_props else ("file_path",),
                    suggested_check_file="checks/check-cwe-22-path-traversal.md",
                    rationale="Tool accepts filesystem paths or file identifiers without guaranteed sandbox containment.",
                )
            )

        # 2. CWE-94: Dynamic Code & Command Injection
        eval_props = [
            k for k in prop_keys
            if any(e in k for e in ("expression", "formula", "eval", "code", "script", "command", "cmd"))
        ]
        if eval_props or any(e in name_lower for e in ("eval", "exec", "calc", "formula", "run_script", "execute")):
            hypotheses.append(
                CWEHypothesis(
                    cwe_id="CWE-94",
                    name="Code & Command Injection (Dynamic Evaluation)",
                    confidence=0.95 if eval_props else 0.80,
                    severity="CRITICAL",
                    affected_tool=tool_name,
                    affected_parameters=tuple(eval_props) if eval_props else ("expression",),
                    suggested_check_file="checks/check-cwe-94-code-injection.md",
                    rationale="Tool parses or executes dynamic formulas, expressions, or commands.",
                )
            )

        # 3. CWE-502: Deserialization of Untrusted Data
        serde_props = [
            k for k in prop_keys
            if any(s in k for s in ("payload", "bundle", "serialized", "b64", "pickle", "data_raw", "dump"))
        ]
        if serde_props or any(s in name_lower for s in ("import", "bundle", "restore", "deserialize", "load_state")):
            hypotheses.append(
                CWEHypothesis(
                    cwe_id="CWE-502",
                    name="Unsafe Deserialization",
                    confidence=0.88 if serde_props else 0.70,
                    severity="CRITICAL",
                    affected_tool=tool_name,
                    affected_parameters=tuple(serde_props) if serde_props else ("payload_b64",),
                    suggested_check_file="checks/check-cwe-502-deserialization.md",
                    rationale="Tool accepts serialized data payloads, bundles, or binary dumps.",
                )
            )

        # 4. CWE-79: Cross-Site Scripting (XSS in Web/UI Widgets)
        ui_props = [
            k for k in prop_keys
            if any(u in k for u in ("html", "markdown", "template", "svg", "widget", "content", "document"))
        ]
        if ui_props and any(u in name_lower for u in ("render", "widget", "view", "preview", "display", "export_html")):
            hypotheses.append(
                CWEHypothesis(
                    cwe_id="CWE-79",
                    name="Cross-Site Scripting (UI Widget DOM Injection)",
                    confidence=0.85,
                    severity="MEDIUM",
                    affected_tool=tool_name,
                    affected_parameters=tuple(ui_props),
                    suggested_check_file="checks/check-cwe-79-web-xss.md",
                    rationale="Tool dynamically renders HTML/Markdown widgets without guaranteed DOM sanitization.",
                )
            )

        # 5. CWE-352: Cross-Site Request Forgery / Gateway CSRF
        net_props = [
            k for k in prop_keys
            if any(n in k for n in ("url", "webhook", "target", "callback", "endpoint"))
        ]
        if net_props and (CapabilityTag.NETWORK_ACCESS in caps or any(n in name_lower for n in ("webhook", "notify", "dispatch"))):
            hypotheses.append(
                CWEHypothesis(
                    cwe_id="CWE-352",
                    name="Cross-Site Request Forgery / Gateway Proxy Abuse",
                    confidence=0.80,
                    severity="HIGH",
                    affected_tool=tool_name,
                    affected_parameters=tuple(net_props),
                    suggested_check_file="checks/check-cwe-352-csrf-gateway.md",
                    rationale="Tool triggers external webhooks or network calls without origin/token headers.",
                )
            )

        # 6. CWE-287 / CWE-862: Confused Deputy / Missing Authorization / BOLA
        tenant_props = [
            k for k in prop_keys
            if any(t in k for t in ("tenant", "org_id", "workspace", "account_id"))
        ]
        has_crypto_token = any(tok in k for tok in ("token", "jwt", "bearer", "signature", "auth_header") for k in prop_keys)
        has_tenant_boundary_risk = bool(tenant_props and (not has_crypto_token or any(t in k for t in ("target_tenant", "resource_tenant") for k in prop_keys)))
        is_deputy_action = any(d in name_lower or d in desc_lower for d in ("delegat", "deputy", "cross_tenant", "tenant_document", "proxy_action"))
        if has_tenant_boundary_risk or is_deputy_action or (tenant_props and any(m in name_lower for m in ("admin", "manage", "update", "delete", "set", "get", "read"))):
            hypotheses.append(
                CWEHypothesis(
                    cwe_id="CWE-862",
                    name="Confused Deputy & Broken Object Level Authorization (BOLA)",
                    confidence=0.90,
                    severity="HIGH",
                    affected_tool=tool_name,
                    affected_parameters=tuple(tenant_props) if tenant_props else ("target_tenant",),
                    suggested_check_file="checks/check-cwe-287-confused-deputy.md",
                    rationale="Privileged multi-tenant tool lacks per-caller cryptographic identity delegation or boundary enforcement.",
                )
            )

        # 7. CWE-89 / CWE-943: SQL & NoSQL Injection
        query_props = [
            k for k in prop_keys
            if any(q in k for q in ("sql", "query", "filter", "statement", "where", "collection"))
        ]
        if query_props or any(q in name_lower for q in ("sql", "query", "find", "search_db", "execute_sql")):
            hypotheses.append(
                CWEHypothesis(
                    cwe_id="CWE-89",
                    name="SQL/NoSQL Query Injection & BOLA",
                    confidence=0.90 if query_props else 0.75,
                    severity="CRITICAL",
                    affected_tool=tool_name,
                    affected_parameters=tuple(query_props) if query_props else ("query",),
                    suggested_check_file="checks/check-cwe-89-sql-injection.md",
                    rationale="Tool accepts unstructured query or filter clauses vulnerable to injection or tenant boundary escape.",
                )
            )

        # 8. Tool Poisoning & Shadowing
        if any(w in desc_lower for w in ("ignore previous", "system prompt", "exfiltrate", "secret_override", "<script>")):
            hypotheses.append(
                CWEHypothesis(
                    cwe_id="CWE-506",
                    name="Tool Description Poisoning / Hostile Instructions",
                    confidence=0.98,
                    severity="CRITICAL",
                    affected_tool=tool_name,
                    affected_parameters=(),
                    suggested_check_file="checks/check-tool-poisoning-shadowing.md",
                    rationale="Tool docstring contains adversarial prompt injection directives.",
                )
            )

        return hypotheses

