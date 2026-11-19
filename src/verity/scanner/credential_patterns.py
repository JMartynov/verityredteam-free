"""Shared credential value detection patterns for MCP configs and static rules.

This module is the single source of truth for cloud credential value shapes so
that configuration scanning (:mod:`verity.discovery.config_scanner`) and static
rule evaluation (:mod:`verity.scanner.static_rules`) never drift apart.
"""

from __future__ import annotations

import re

CREDENTIAL_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})"),
    re.compile(r"eyJ[A-Za-z0-9_-]{20,}"),
)

PEM_PRIVATE_KEY_BLOCK_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----"
    r"[\s\S]*?"
    r"(?:-----END (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----|$)"
)

_PLACEHOLDER_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bYOUR[_-][A-Z0-9_]+\b"),
    re.compile(r"(?i)<\s*YOUR[^>]*>"),
    re.compile(r"(?i)\bREPLACE[_-]?WITH(?:[_-][A-Z0-9_]+)?\b"),
    re.compile(r"(?i)\bINSERT[_-][A-Z0-9_]+\b"),
    re.compile(r"(?i)\bCHANGE[_-]?ME\b"),
    re.compile(r"(?i)\bPLACEHOLDER\b"),
    re.compile(r"(?i)\bTODO\b"),
    re.compile(r"(?i)\bX{4,}\b"),
    re.compile(r"^\*{3,}$"),
)


def is_placeholder_value(text: str) -> bool:
    """Return True when ``text`` is an obvious credential placeholder."""
    value = (text or "").strip()
    if not value:
        return True
    return any(pattern.search(value) for pattern in _PLACEHOLDER_PATTERNS)
