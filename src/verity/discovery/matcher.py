"""Hybrid Two-Tier Matcher for connecting observed MCP capabilities to Passport Knowledge Base."""

from __future__ import annotations

import logging
from pathlib import Path

from verity.discovery.models import DiscoveredServerConfig, LiveServerCapability
from verity.fingerprint.matcher import FingerprintMatcher
from verity.fingerprint.models import FingerprintMatchResult

logger = logging.getLogger("verity.discovery.matcher")


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

    def match_static_config(
        self,
        config: DiscoveredServerConfig,
    ) -> FingerprintMatchResult:
        """Match static configuration against package naming heuristics and aliases in O(1) time."""
        server_name = config.server_name
        target_version: str | None = None
        clean_server_name = server_name

        if "@" in server_name:
            if server_name.startswith("@"):
                parts = server_name[1:].split("@")
                clean_server_name = "@" + parts[0]
                if len(parts) > 1:
                    target_version = parts[1]
            else:
                parts = server_name.split("@")
                clean_server_name = parts[0]
                if len(parts) > 1:
                    target_version = parts[1]

        # 1. Fast O(1) lookup by server name
        spec = self.matcher.fast_index.find_package_by_hint_or_alias(clean_server_name)

        # 2. Fast lookup by tokens in args (e.g. npx @modelcontextprotocol/server-postgres@0.1.0)
        if config.args:
            for arg in config.args:
                clean_arg = arg
                # If scoped e.g. @scope/pkg@version or pkg@version
                if arg.startswith("@"):
                    parts = arg[1:].split("@")
                    clean_arg = "@" + parts[0]
                    if len(parts) > 1:
                        target_version = parts[1]
                elif "@" in arg:
                    parts = arg.split("@")
                    clean_arg = parts[0]
                    if len(parts) > 1:
                        target_version = parts[1]

                if not spec:
                    spec = self.matcher.fast_index.find_package_by_hint_or_alias(clean_arg)

        if spec:
            matched_v = target_version or (spec.versions[-1].version if spec.versions else "1.0.0")
            return FingerprintMatchResult(
                matched=True,
                package_name=spec.package_name,
                purl=spec.purl,
                matched_version=matched_v,
                confidence_score=0.85,
                match_layer="STATIC_CONFIG_MATCH",
                matched_tool_count=(len(spec.versions[-1].tool_signatures) if spec.versions else 0),
            )

        return FingerprintMatchResult(
            matched=False,
            match_layer="NONE",
            confidence_score=0.0,
        )
