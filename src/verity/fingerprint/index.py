"""In-memory indexing for O(1) fingerprint matching."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp_fingerprints.index import FingerprintFastIndex as UpstreamFingerprintFastIndex
from mcp_fingerprints.models import ServerPackageSpec


class FingerprintFastIndex(UpstreamFingerprintFastIndex):
    """In-memory fast index extending upstream with dict and bytes snapshot support."""

    def load_from_snapshot(self, snapshot_data: dict[str, Any] | str | Path | bytes) -> int:
        """Load and index all passports directly from a consolidated snapshot payload or file."""
        if isinstance(snapshot_data, dict):
            pkg_dict = snapshot_data.get("passports", snapshot_data)
            count = 0
            if isinstance(pkg_dict, dict):
                for pkg_data in pkg_dict.values():
                    if isinstance(pkg_data, dict) and "package_name" in pkg_data:
                        spec = ServerPackageSpec.from_dict(pkg_data)
                        self.register_package(spec)
                        count += 1
            elif isinstance(pkg_dict, list):
                for pkg_data in pkg_dict:
                    if isinstance(pkg_data, dict) and "package_name" in pkg_data:
                        spec = ServerPackageSpec.from_dict(pkg_data)
                        self.register_package(spec)
                        count += 1
            return count
        elif isinstance(snapshot_data, bytes):
            import gzip
            try:
                data = json.loads(gzip.decompress(snapshot_data).decode("utf-8"))
            except Exception:
                data = json.loads(snapshot_data.decode("utf-8"))
            return self.load_from_snapshot(data)
        return super().load_from_snapshot(snapshot_data)


__all__ = ["FingerprintFastIndex"]
