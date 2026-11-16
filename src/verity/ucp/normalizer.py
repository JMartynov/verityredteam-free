"""Metadata normalizer and defanger for Unicode anomalies and prompt injection payloads."""

from __future__ import annotations

import re
import unicodedata
from typing import ClassVar


class MetadataNormalizer:
    """Sanitizes untrusted MCP tool metadata.

    Strips invisible characters and defangs indirect prompt injections.
    """

    # Zero-width spaces, joiners, BOM, and bidirectional control characters
    ZERO_WIDTH_AND_BIDI_CHARS: ClassVar[set[str]] = {
        "\u200b",  # Zero-width space
        "\u200c",  # Zero-width non-joiner
        "\u200d",  # Zero-width joiner
        "\u200e",  # Left-to-right mark
        "\u200f",  # Right-to-left mark
        "\u202a",  # Left-to-right embedding
        "\u202b",  # Right-to-left embedding
        "\u202c",  # Pop directional formatting
        "\u202d",  # Left-to-right override
        "\u202e",  # Right-to-left override
        "\u2060",  # Word joiner
        "\u2066",  # Left-to-right isolate
        "\u2067",  # Right-to-left isolate
        "\u2068",  # First strong isolate
        "\u2069",  # Pop directional isolate
        "\ufeff",  # Zero-width no-break space (BOM)
    }

    # Prompt injection patterns commonly embedded in malicious tool descriptions
    PROMPT_INJECTION_PATTERNS: ClassVar[list[re.Pattern[str]]] = [
        re.compile(
            r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
            re.IGNORECASE,
        ),
        re.compile(r"system\s+prompt\s*:", re.IGNORECASE),
        re.compile(r"\[INST\].*?\[/INST\]", re.IGNORECASE | re.DOTALL),
        re.compile(r"<<SYS>>.*?<</SYS>>", re.IGNORECASE | re.DOTALL),
        re.compile(
            r"you\s+(must|should)\s+(always\s+)?(silently\s+)?(send|exfiltrate|post)",
            re.IGNORECASE,
        ),
        re.compile(r"developer\s+mode\s+enabled", re.IGNORECASE),
        re.compile(r"override\s+(all\s+)?safety\s+filters", re.IGNORECASE),
    ]

    @classmethod
    def detect_unicode_anomalies(cls, text: str) -> bool:
        """Return True if text contains invisible, zero-width, or bidi control characters."""
        if not text:
            return False
        for char in text:
            if char in cls.ZERO_WIDTH_AND_BIDI_CHARS:
                return True
            # Non-printable controls
            category = unicodedata.category(char)
            if category.startswith("C") and char not in ("\t", "\n", "\r"):
                return True
        return False

    @classmethod
    def detect_prompt_injection(cls, text: str) -> bool:
        """Return True if text matches known indirect prompt injection patterns."""
        if not text:
            return False
        return any(pattern.search(text) for pattern in cls.PROMPT_INJECTION_PATTERNS)

    @classmethod
    def sanitize_text(cls, text: str) -> str:
        """Strip invisible/bidi characters, normalize NFKC unicode, and defang prompt injections."""
        if not text:
            return ""

        # 1. Strip zero-width and bidi characters
        cleaned_chars = [
            char
            for char in text
            if char not in cls.ZERO_WIDTH_AND_BIDI_CHARS
            and not (unicodedata.category(char).startswith("C") and char not in ("\t", "\n", "\r"))
        ]
        cleaned_str = "".join(cleaned_chars)

        # 2. NFKC Unicode normalization (homoglyph folding)
        normalized = unicodedata.normalize("NFKC", cleaned_str)

        # 3. Defang prompt injection tokens by replacing dangerous keywords
        defanged = normalized
        for pattern in cls.PROMPT_INJECTION_PATTERNS:
            defanged = pattern.sub("[DEFANGED_PROMPT_INJECTION]", defanged)

        return defanged
