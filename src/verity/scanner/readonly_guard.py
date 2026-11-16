"""Read-Only Safety Guard for Phase 1 MCP Discovery & Verification.

Enforces the strict invariant: 100% Read-Only & Harmless during initial
reconnaissance and capability profiling. Prevents destructive or mutating
actions (DROP, DELETE, UPDATE, WRITE, EXECUTE_SCRIPT) from reaching customer
mesh environments.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class SafetyVerdict(StrEnum):
    """Verdict returned by the safety guard."""

    PERMITTED = "PERMITTED"
    BLOCKED = "BLOCKED"


class MutationProhibitedError(PermissionError):
    """Raised when an operation attempts to mutate or destroy state during Phase 1."""

    pass


@dataclass(frozen=True)
class GuardEvaluationResult:
    """Result of inspecting a tool call through the Read-Only Safety Guard."""

    verdict: SafetyVerdict
    tool_name: str
    is_mutating: bool
    matched_keyword: str | None = None
    reason: str = ""


class ReadOnlySafetyGuard:
    """Zero-overhead interceptor guarding MCP tool invocations against Phase-1 mutations."""

    FORBIDDEN_TOOL_KEYWORDS: tuple[str, ...] = (
        "delete",
        "drop",
        "truncate",
        "update",
        "alter",
        "modify",
        "write",
        "destroy",
        "wipe",
        "purge",
        "kill",
        "remove",
        "rmdir",
        "create_customer",
        "execute_script",
        "exec_cmd",
        "charge_card",
    )

    FORBIDDEN_ARGUMENT_PATTERNS: tuple[re.Pattern[str], ...] = (
        re.compile(r"(?i)\b(DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE)\b"),
        re.compile(r"(?i)\b(DELETE\s+FROM|UPDATE\s+\w+\s+SET|INSERT\s+INTO)\b"),
        re.compile(r"(?i);\s*(DROP|DELETE|TRUNCATE|ALTER|UPDATE|INSERT)\b"),
        re.compile(r"(?i)\brm\s+-[a-zA-Z]*[rf]"),
        re.compile(r"(?i)\bmkfs(\.[a-z0-9]+)?\b"),
        re.compile(r"(?i)\bdd\s+if="),
        re.compile(r"(?i)\bkill\s+-9\b"),
        re.compile(r"(?i)>\s*/(etc|bin|usr|root|var|dev)"),
    )

    @classmethod
    def check_call(
        cls,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        phase: str = "PHASE_1",
    ) -> GuardEvaluationResult:
        """Inspect a tool call and determine whether it represents a prohibited mutation."""
        arguments = arguments or {}

        # If not Phase 1, the read-only restriction does not apply
        if phase.upper() != "PHASE_1":
            return GuardEvaluationResult(
                verdict=SafetyVerdict.PERMITTED,
                tool_name=tool_name,
                is_mutating=False,
                reason="Non-Phase-1 execution permitted.",
            )

        # 1. Inspect tool name
        norm_tool = tool_name.lower().replace("-", "_")
        for kw in cls.FORBIDDEN_TOOL_KEYWORDS:
            if kw in norm_tool:
                return GuardEvaluationResult(
                    verdict=SafetyVerdict.BLOCKED,
                    tool_name=tool_name,
                    is_mutating=True,
                    matched_keyword=kw,
                    reason=f"MUTATION_PROHIBITED_IN_PHASE_1: Destructive tool '{tool_name}' matches forbidden keyword '{kw}'.",
                )

        # 2. Inspect argument values recursively
        flat_strings: list[str] = []

        def _extract_strings(obj: Any) -> None:
            if isinstance(obj, str):
                flat_strings.append(obj)
            elif isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(k, str):
                        flat_strings.append(k)
                    _extract_strings(v)
            elif isinstance(obj, (list, tuple, set)):
                for item in obj:
                    _extract_strings(item)

        _extract_strings(arguments)

        for text in flat_strings:
            for pattern in cls.FORBIDDEN_ARGUMENT_PATTERNS:
                m = pattern.search(text)
                if m:
                    matched_kw = m.group(0)
                    return GuardEvaluationResult(
                        verdict=SafetyVerdict.BLOCKED,
                        tool_name=tool_name,
                        is_mutating=True,
                        matched_keyword=matched_kw,
                        reason=f"MUTATION_PROHIBITED_IN_PHASE_1: Destructive argument payload '{matched_kw}' rejected.",
                    )

        return GuardEvaluationResult(
            verdict=SafetyVerdict.PERMITTED,
            tool_name=tool_name,
            is_mutating=False,
            reason="Safe read-only call.",
        )

    @classmethod
    def enforce(
        cls,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        phase: str = "PHASE_1",
    ) -> GuardEvaluationResult:
        """Evaluate the tool call and raise MutationProhibitedError if blocked."""
        res = cls.check_call(tool_name, arguments, phase=phase)
        if res.verdict == SafetyVerdict.BLOCKED:
            raise MutationProhibitedError(res.reason)
        return res
