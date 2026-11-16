"""Tri-Layer Fingerprint Matcher and in-memory knowledge base registry."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp_fingerprints.matcher import FingerprintMatcher as UpstreamFingerprintMatcher

from verity.fingerprint.index import FingerprintFastIndex


class FingerprintMatcher(UpstreamFingerprintMatcher):
    """High-performance Tri-Layer matching engine with O(1) multi-indexing.
    
    Includes Verity-specific extensions.
    """

    def __init__(self, index: FingerprintFastIndex | None = None) -> None:
        super().__init__(index=index or FingerprintFastIndex())

    def load_from_directory(self, directory: str | Path) -> int:
        """Load from directory, falling back to snapshot if directory has no json files."""
        p = Path(directory)
        json_files = list(p.glob("*.json")) if p.is_dir() else []
        if json_files:
            return super().load_from_directory(p)
        from mcp_fingerprints.data_loader import get_passports_path
        target = get_passports_path(download_if_missing=True)
        if target.is_file():
            return self.load_from_snapshot(target)
        return super().load_from_directory(p)

    def load_from_snapshot(self, snapshot_data: dict[str, Any] | str | Path | bytes) -> int:
        """Load and index all passports from consolidated snapshot."""
        return self.fast_index.load_from_snapshot(snapshot_data)

    def load_auto(
        self, directory: str | Path = "data/fingerprints", force_refresh: bool = False
    ) -> int:
        """Load from local directory if populated, else fetch latest public snapshot."""
        p = Path(directory)
        if p.is_dir() and any(p.glob("*.json")):
            return self.load_from_directory(p)
        from verity.data_fetcher import fetch_passports_snapshot

        snapshot = fetch_passports_snapshot(force_refresh=force_refresh)
        if snapshot:
            return self.load_from_snapshot(snapshot)
        return self.load_from_directory(p)


__all__ = ["FingerprintMatcher"]
