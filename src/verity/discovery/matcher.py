"""Hybrid Two-Tier Matcher for connecting observed MCP capabilities to Passport Knowledge Base."""

from __future__ import annotations

import logging
from pathlib import Path

from verity.discovery.models import DiscoveredServerConfig, LiveServerCapability
from verity.fingerprint.matcher import FingerprintMatcher
from verity.fingerprint.models import FingerprintMatchResult

logger = logging.getLogger("verity.discovery.matcher")

_FLOATING_VERSION_MARKERS = frozenset({"", "*", "latest", "next", "canary"})
_FLOATING_VERSION_PREFIXES = ("^", "~", ">", "<")


def is_floating_version(version: str | None) -> bool:
    """Return True when ``version`` does not pin an exact release."""
    if version is None:
        return True
    text = version.strip().lower()
    if text in _FLOATING_VERSION_MARKERS:
        return True
    return text.startswith(_FLOATING_VERSION_PREFIXES)


class HybridDiscoveryMatcher:
    """Combines Tier 1 exact cryptographic matching with Tier 2 topological graph matching."""

    def __init__(self, fingerprint_dir: str | Path = "data/fingerprints") -> None:
        self.fingerprint_dir = Path(fingerprint_dir)
        self.matcher = FingerprintMatcher()
        self.matcher.load_auto(self.fingerprint_dir)

    def match_live_capability(
        self,
        capability: LiveServerCapability,
        config: DiscoveredServerConfig | None = None,
        min_confidence: float = 0.60,
    ) -> FingerprintMatchResult:
        """Match observed live tools against the 3,784 MCP passport database."""
        hint = config.server_name if config else capability.server_name
        return self.matcher.match(
            tools=list(capability.tools),
            server_name_hint=hint,
            min_confidence_threshold=min_confidence,
        )

    @staticmethod
    def _split_specifier(token: str) -> tuple[str, str | None]:
        """Split a package token into ``(name, version)`` for ``@`` and ``==`` specifiers."""
        text = token.strip()
        if not text:
            return text, None
        if "://" in text:
            return text, None
        if "==" in text:
            name, _, version = text.partition("==")
            return name, version or None
        if text.startswith("@"):
            body = text[1:]
            if "@" in body:
                name_part, _, version = body.partition("@")
                return "@" + name_part, version or None
            return text, None
        if "@" in text:
            name, _, version = text.partition("@")
            return name, version or None
        return text, None

    def match_static_config(
        self,
        config: DiscoveredServerConfig,
    ) -> FingerprintMatchResult:
        """Match static configuration against package naming heuristics and aliases in O(1) time."""
        tokens: list[str] = [config.server_name]
        tokens.extend(config.args)
        if config.command:
            tokens.append(Path(config.command).name)

        parsed_tokens: list[tuple[str, str | None]] = []
        matched_spec = None
        for token in tokens:
            clean_token, version = self._split_specifier(token)
            if not clean_token:
                continue
            parsed_tokens.append((clean_token, version))
            if matched_spec is None:
                matched_spec = self.matcher.fast_index.find_package_by_hint_or_alias(
                    clean_token
                )

        if matched_spec is None:
            return FingerprintMatchResult(
                matched=False,
                match_layer="NONE",
                confidence_score=0.0,
            )

        target_version: str | None = None
        for clean_token, version in parsed_tokens:
            if is_floating_version(version):
                continue
            spec = self.matcher.fast_index.find_package_by_hint_or_alias(clean_token)
            if spec and spec.package_name == matched_spec.package_name:
                target_version = version

        is_pinned = target_version is not None
        return FingerprintMatchResult(
            matched=True,
            package_name=matched_spec.package_name,
            purl=matched_spec.purl,
            matched_version=target_version if is_pinned else None,
            confidence_score=0.85 if is_pinned else 0.65,
            match_layer="STATIC_CONFIG_MATCH",
            matched_tool_count=(
                len(matched_spec.versions[-1].tool_signatures)
                if matched_spec.versions
                else 0
            ),
        )
