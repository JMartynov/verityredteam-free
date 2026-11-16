"""Bootstrap loader initializing on-board fingerprint and vulnerability databases."""

from __future__ import annotations

import logging
from pathlib import Path

from verity.fingerprint.matcher import FingerprintMatcher
from verity.lookup.engine import VulnerabilityLookupEngine

logger = logging.getLogger("verity.mcp_server.bootstrap")


class ServerContext:
    """In-memory container holding local on-board database engines."""

    def __init__(
        self,
        fingerprint_matcher: FingerprintMatcher,
        vuln_engine: VulnerabilityLookupEngine,
    ) -> None:
        self.matcher = fingerprint_matcher
        self.vuln_engine = vuln_engine


def initialize_server_context(
    fingerprint_dir: str | Path = "data/fingerprints",
    vuln_dir: str | Path = "data/vulnerabilities",
) -> ServerContext:
    """Load local on-board databases and return an initialized ServerContext."""
    fp_path = Path(fingerprint_dir)
    vuln_path = Path(vuln_dir)

    # 1. Initialize fast fingerprint matcher
    matcher = FingerprintMatcher()
    matcher.load_auto(fp_path)

    # 2. Initialize vulnerability lookup engine
    vuln_engine = VulnerabilityLookupEngine.from_auto(vuln_path)

    logger.info(
        "ServerContext initialized with %d passports and %d vulnerability advisories.",
        matcher.total_packages,
        vuln_engine.index.total_vulnerabilities,
    )

    return ServerContext(
        fingerprint_matcher=matcher,
        vuln_engine=vuln_engine,
    )


bootstrap_server_context = initialize_server_context
# Alias for backwards compatibility and agent scripting resilience
create_server_context = initialize_server_context

