"""Tri-Layer Fingerprint Matcher and in-memory knowledge base registry."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from mcp_fingerprints.matcher import FingerprintMatcher as UpstreamFingerprintMatcher

from verity.fingerprint.index import FingerprintFastIndex

logger = logging.getLogger("verity.fingerprint.matcher")


class FingerprintMatcher(UpstreamFingerprintMatcher):
    """High-performance Tri-Layer matching engine with O(1) multi-indexing.
    
    Includes Verity-specific extensions.
    """

    def __init__(self, index: FingerprintFastIndex | None = None) -> None:
        super().__init__(index=index or FingerprintFastIndex())

    def load_from_directory(self, directory: str | Path) -> int:
        """Load passports from a directory, cached snapshot, or packaged baseline."""
        p = Path(directory)
        json_files = list(p.glob("*.json")) if p.is_dir() else []
        if json_files:
            return super().load_from_directory(p)

        from verity.data_fetcher import (
            _is_offline,
            resolve_cached_snapshot,
            resolve_packaged_baseline,
        )

        if _is_offline():
            cached = resolve_cached_snapshot("passports.json.gz")
            if cached is not None:
                try:
                    loaded = self.load_from_snapshot(cached)
                    if loaded > 0:
                        return loaded
                except Exception as exc:  # pragma: no cover - defensive
                    logger.warning("Failed to load cached passports snapshot: %s", exc)
            packaged = resolve_packaged_baseline("passports.json.gz")
            if packaged:
                try:
                    loaded = self.load_from_snapshot(packaged)
                    if loaded > 0:
                        return loaded
                except Exception as exc:  # pragma: no cover - defensive
                    logger.warning("Failed to load packaged passports baseline: %s", exc)
            logger.warning(
                "Offline mode: no cached or packaged baseline fingerprint data "
                "available (0 passports loaded); fingerprint lookups will "
                "return 0 matches."
            )
            return 0

        try:
            from mcp_fingerprints.data_loader import get_passports_path

            target = Path(get_passports_path(download_if_missing=True))
        except Exception:
            target = None
        if target is not None and target.is_file():
            try:
                return self.load_from_snapshot(target)
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("Failed to load passports snapshot %s: %s", target, exc)

        if p.is_dir():
            try:
                return super().load_from_directory(p)
            except Exception:  # pragma: no cover - defensive
                return 0
        return 0

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

        from verity.data_fetcher import _is_offline, fetch_passports_snapshot

        if _is_offline():
            return self.load_from_directory(p)

        snapshot = fetch_passports_snapshot(force_refresh=force_refresh)
        if snapshot:
            return self.load_from_snapshot(snapshot)
        return self.load_from_directory(p)


__all__ = ["FingerprintMatcher"]
