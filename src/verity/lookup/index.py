"""In-memory multi-key and substring/grep inverted index for OSV vulnerabilities."""

from __future__ import annotations

import contextlib
import json
import logging
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from mcp_vulnerabilities.models import OsvVulnerability

from verity.lookup.sqlite_cache import (
    SqliteIndexReader,
    build_sqlite_cache,
    open_valid_cache,
)

logger = logging.getLogger("verity.lookup.index")


class VulnerabilityIndex:
    """High-performance in-memory index over canonical OSV vulnerability documents."""

    def __init__(self) -> None:
        # $O(1)$ Hash Maps
        self._by_id: dict[str, OsvVulnerability] = {}
        self._by_package_name: dict[str, list[OsvVulnerability]] = defaultdict(list)
        self._by_purl: dict[str, list[OsvVulnerability]] = defaultdict(list)
        self._by_alias: dict[str, list[OsvVulnerability]] = defaultdict(list)
        self._by_tool: dict[str, list[OsvVulnerability]] = defaultdict(list)
        self._by_cwe: dict[str, list[OsvVulnerability]] = defaultdict(list)

        # Inverted Token / Trigram Index for Fast Substring / Partial Matching
        self._trigram_to_packages: dict[str, set[str]] = defaultdict(set)
        self._all_packages: set[str] = set()
        self._is_loaded: bool = False
        self._sqlite_reader: SqliteIndexReader | None = None

    def _reset_state(self) -> None:
        """Reset all in-memory indexes and detach any SQLite reader."""
        if self._sqlite_reader is not None:
            self._sqlite_reader.close()
            self._sqlite_reader = None
        self._by_id = {}
        self._by_package_name = defaultdict(list)
        self._by_purl = defaultdict(list)
        self._by_alias = defaultdict(list)
        self._by_tool = defaultdict(list)
        self._by_cwe = defaultdict(list)
        self._trigram_to_packages = defaultdict(set)
        self._all_packages = set()
        self._is_loaded = False

    def close(self) -> None:
        """Release any resources held by the index."""
        if self._sqlite_reader is not None:
            self._sqlite_reader.close()
            self._sqlite_reader = None

    def __del__(self) -> None:
        with contextlib.suppress(Exception):
            self.close()

    def _attach_sqlite_reader(self, reader: SqliteIndexReader, path: Path) -> int:
        """Attach a SQLite reader as the backing store and return its vuln count."""
        self._reset_state()
        self._sqlite_reader = reader
        self._is_loaded = True
        logger.info(
            "VulnerabilityIndex loaded %d advisories across %d packages "
            "from SQLite cache %s",
            reader.total_vulnerabilities,
            reader.total_packages,
            path,
        )
        return reader.total_vulnerabilities

    @property
    def is_loaded(self) -> bool:
        """Return True if the vulnerability index has been loaded."""
        return self._is_loaded

    @property
    def total_vulnerabilities(self) -> int:
        """Return total number of indexed vulnerabilities."""
        if self._sqlite_reader is not None:
            return self._sqlite_reader.total_vulnerabilities
        return len(self._by_id)

    @property
    def total_packages(self) -> int:
        """Return total number of distinct indexed package names."""
        if self._sqlite_reader is not None:
            return self._sqlite_reader.total_packages
        return len(self._all_packages)

    def load_from_directory(self, directory: str | Path) -> int:
        """Load and index all OSV JSON files from the specified directory."""
        dir_path = Path(directory)
        if not dir_path.is_dir():
            from verity.data_fetcher import _is_offline

            if _is_offline():
                return self._load_offline_fallback()
            from verity.data_fetcher import fetch_vulnerabilities_snapshot
            snapshot = fetch_vulnerabilities_snapshot()
            if snapshot:
                return self.load_from_snapshot(snapshot)
            logger.warning("Vulnerability directory does not exist: %s", dir_path)
            return 0

        count = 0
        json_files = [f for f in sorted(dir_path.glob("*.json")) if f.name not in ("index.json", "sync_state.json")]
        if not json_files:
            from verity.data_fetcher import _is_offline

            if _is_offline():
                return self._load_offline_fallback()
            from verity.data_fetcher import fetch_vulnerabilities_snapshot
            snapshot = fetch_vulnerabilities_snapshot()
            if snapshot:
                return self.load_from_snapshot(snapshot)

        for j_file in json_files:
            try:
                data = json.loads(j_file.read_text(encoding="utf-8"))
                if not isinstance(data, dict) or not data.get("id"):
                    continue
                vuln = OsvVulnerability.from_dict(data)
                self.index_vulnerability(vuln)
                count += 1
            except Exception as exc:
                logger.debug("Failed to index %s: %s", j_file.name, exc)

        self._is_loaded = True
        logger.info(
            "VulnerabilityIndex loaded %d advisories across %d packages from %s",
            len(self._by_id),
            len(self._all_packages),
            dir_path,
        )
        return count

    @staticmethod
    def _parse_snapshot_records(
        data: dict[str, Any],
    ) -> list[tuple[OsvVulnerability, dict[str, Any]]]:
        """Parse snapshot payload into (vuln, raw_dict) pairs, skipping invalid entries."""
        records: list[tuple[OsvVulnerability, dict[str, Any]]] = []
        vulns_map = data.get("vulnerabilities", {})
        if not isinstance(vulns_map, dict):
            return records
        for _, vuln_dict in vulns_map.items():
            if isinstance(vuln_dict, dict) and vuln_dict.get("id"):
                try:
                    vuln = OsvVulnerability.from_dict(vuln_dict)
                except Exception as exc:
                    logger.debug("Failed to index snapshot record: %s", exc)
                    continue
                records.append((vuln, vuln_dict))
        return records

    def _load_records(
        self, records: list[tuple[OsvVulnerability, dict[str, Any]]]
    ) -> int:
        """Index parsed records into the in-memory structures."""
        count = 0
        for vuln, _ in records:
            self.index_vulnerability(vuln)
            count += 1
        return count

    def load_from_snapshot(self, snapshot_data: dict[str, Any] | str | Path | bytes) -> int:
        """Load and index all OSV vulnerabilities directly from a snapshot payload or file."""
        import gzip

        if isinstance(snapshot_data, (str, Path)):
            path = Path(snapshot_data)
            reader = open_valid_cache(path)
            if reader is not None:
                return self._attach_sqlite_reader(reader, path)

            if str(path).endswith(".gz"):
                with gzip.open(path, "rt", encoding="utf-8") as f:
                    data = json.load(f)
            else:
                data = json.loads(path.read_text(encoding="utf-8"))

            records = self._parse_snapshot_records(data)
            build_sqlite_cache(path, records)
            reader = open_valid_cache(path)
            if reader is not None:
                return self._attach_sqlite_reader(reader, path)

            self._reset_state()
            count = self._load_records(records)
            self._is_loaded = True
            logger.info(
                "VulnerabilityIndex loaded %d advisories across %d packages from snapshot",
                len(self._by_id),
                len(self._all_packages),
            )
            return count

        if isinstance(snapshot_data, bytes):
            try:
                data = json.loads(gzip.decompress(snapshot_data).decode("utf-8"))
            except Exception:
                data = json.loads(snapshot_data.decode("utf-8"))
        elif isinstance(snapshot_data, dict):
            data = snapshot_data
        else:
            raise ValueError(f"Unsupported snapshot type: {type(snapshot_data)}")

        records = self._parse_snapshot_records(data)
        self._reset_state()
        count = self._load_records(records)
        self._is_loaded = True
        logger.info(
            "VulnerabilityIndex loaded %d advisories across %d packages from snapshot",
            len(self._by_id),
            len(self._all_packages),
        )
        return count

    @staticmethod
    def _existing_cache_snapshot() -> Path | None:
        """Return an existing on-disk vulnerabilities cache path, if any."""
        try:
            from verity.data_fetcher import resolve_cached_snapshot
        except Exception:
            return None
        return resolve_cached_snapshot("vulnerabilities.json.gz")

    def _load_offline_fallback(self) -> int:
        """Load cached or packaged advisory data without any network access."""
        cached = self._existing_cache_snapshot()
        if cached is not None:
            try:
                loaded = self.load_from_snapshot(cached)
                if loaded > 0:
                    return loaded
            except Exception as exc:
                logger.warning("Failed to load cached snapshot %s: %s", cached, exc)

        try:
            from verity.data_fetcher import resolve_packaged_baseline
        except Exception:
            resolve_packaged_baseline = None  # type: ignore[assignment]

        if resolve_packaged_baseline is not None:
            packaged = resolve_packaged_baseline("vulnerabilities.json.gz")
            if packaged:
                try:
                    loaded = self.load_from_snapshot(packaged)
                    if loaded > 0:
                        return loaded
                except Exception as exc:
                    logger.warning("Failed to load packaged baseline: %s", exc)

        logger.warning(
            "Offline mode: no cached or packaged baseline vulnerability data "
            "available (0 advisories loaded); vulnerability lookups will "
            "return 0 matches."
        )
        return 0

    def load_auto(
        self, directory: str | Path = "data/vulnerabilities", force_refresh: bool = False
    ) -> int:
        """Load from local directory if populated, else fetch latest public snapshot."""
        p = Path(directory)
        if p.is_dir() and any(p.glob("*.json")):
            return self.load_from_directory(p)

        from verity.data_fetcher import _is_offline

        if _is_offline():
            return self._load_offline_fallback()

        from verity.data_fetcher import DEFAULT_TTL_SECONDS, fetch_vulnerabilities_snapshot

        if not force_refresh:
            cached = self._existing_cache_snapshot()
            if cached is not None:
                try:
                    if (time.time() - cached.stat().st_mtime) < DEFAULT_TTL_SECONDS:
                        loaded = self.load_from_snapshot(cached)
                        if loaded > 0 and self._is_loaded:
                            return loaded
                except Exception as exc:
                    logger.warning("Failed to load cached snapshot %s: %s", cached, exc)

        snapshot = fetch_vulnerabilities_snapshot(force_refresh=force_refresh)
        if snapshot:
            cached_after = self._existing_cache_snapshot()
            if cached_after is not None:
                reader = open_valid_cache(cached_after)
                if reader is None:
                    records = self._parse_snapshot_records(snapshot)
                    build_sqlite_cache(cached_after, records)
                    reader = open_valid_cache(cached_after)
                if reader is not None:
                    return self._attach_sqlite_reader(reader, cached_after)
            return self.load_from_snapshot(snapshot)
        return 0

    def index_vulnerability(self, vuln: OsvVulnerability) -> None:
        """Add a single OsvVulnerability record to all in-memory indexes."""
        vuln_id_norm = vuln.id.strip().upper()
        self._by_id[vuln_id_norm] = vuln

        # Index aliases
        for alias in vuln.aliases:
            self._by_alias[alias.strip().upper()].append(vuln)

        # Index affected packages, PURLs, tools, and CWEs
        for aff in vuln.affected:
            pkg_name = aff.package.name.strip()
            if pkg_name:
                pkg_norm = pkg_name.lower()
                if vuln not in self._by_package_name[pkg_norm]:
                    self._by_package_name[pkg_norm].append(vuln)
                self._all_packages.add(pkg_name)
                self._index_trigrams(pkg_name)

            if aff.package.purl:
                purl_norm = aff.package.purl.strip().lower()
                # Strip version component if present (e.g. pkg:npm/mcp-remote@0.0.8)
                base_purl = purl_norm.split("@")[0]
                if vuln not in self._by_purl[base_purl]:
                    self._by_purl[base_purl].append(vuln)

            db = aff.database_specific
            if db:
                for tool in db.vulnerable_tools:
                    tool_norm = tool.strip().lower()
                    if vuln not in self._by_tool[tool_norm]:
                        self._by_tool[tool_norm].append(vuln)

                for cwe in db.cwe_ids:
                    cwe_norm = cwe.strip().upper()
                    if vuln not in self._by_cwe[cwe_norm]:
                        self._by_cwe[cwe_norm].append(vuln)

    def _index_trigrams(self, text: str) -> None:
        """Populate character trigram index for partial / substring matching."""
        clean = text.lower().strip()
        if len(clean) < 3:
            self._trigram_to_packages[clean].add(text)
            return
        for i in range(len(clean) - 2):
            trigram = clean[i : i + 3]
            self._trigram_to_packages[trigram].add(text)

    def get_by_package_name(self, package_name: str) -> list[OsvVulnerability]:
        """Fetch all vulnerabilities for an exact package name."""
        if self._sqlite_reader is not None:
            return self._sqlite_reader.get_by_package_name(package_name)
        norm = package_name.strip().lower()
        if norm in self._by_package_name:
            return list(self._by_package_name[norm])
        if "/" in norm:
            short_name = norm.split("/")[-1]
            if short_name in self._by_package_name:
                return list(self._by_package_name[short_name])
        return []

    def get_by_purl(self, purl: str) -> list[OsvVulnerability]:
        """Fetch all vulnerabilities for a Package URL."""
        if self._sqlite_reader is not None:
            return self._sqlite_reader.get_by_purl(purl)
        base_purl = purl.strip().lower().split("@")[0]
        return list(self._by_purl.get(base_purl, []))

    def get_by_id_or_alias(self, identifier: str) -> list[OsvVulnerability]:
        """Fetch vulnerabilities matching a CVE/GHSA ID or alias."""
        if self._sqlite_reader is not None:
            return self._sqlite_reader.get_by_id_or_alias(identifier)
        norm = identifier.strip().upper()
        if norm in self._by_id:
            return [self._by_id[norm]]
        return list(self._by_alias.get(norm, []))

    def get_by_tool(self, tool_name: str) -> list[OsvVulnerability]:
        """Fetch all vulnerabilities exposing the specified tool name."""
        if self._sqlite_reader is not None:
            return self._sqlite_reader.get_by_tool(tool_name)
        norm = tool_name.strip().lower()
        return list(self._by_tool.get(norm, []))

    def get_by_cwe(self, cwe_id: str) -> list[OsvVulnerability]:
        """Fetch all vulnerabilities categorized under the given CWE identifier."""
        if self._sqlite_reader is not None:
            return self._sqlite_reader.get_by_cwe(cwe_id)
        norm = cwe_id.strip().upper()
        return list(self._by_cwe.get(norm, []))

    def search_packages(self, query: str, limit: int = 50) -> list[str]:
        """Search packages using fast trigram & substring matching (grep-style)."""
        if self._sqlite_reader is not None:
            return self._sqlite_reader.search_packages(query, limit=limit)
        clean_q = query.strip().lower()
        if not clean_q:
            return sorted(self._all_packages)[:limit]

        exact_prefix: list[str] = []
        substring_matches: list[str] = []

        for pkg in self._all_packages:
            pkg_lower = pkg.lower()
            if pkg_lower == clean_q or pkg_lower.startswith(clean_q):
                exact_prefix.append(pkg)
            elif clean_q in pkg_lower:
                substring_matches.append(pkg)

        results = sorted(exact_prefix) + sorted(substring_matches)
        return results[:limit]

    def get_all_packages(self) -> list[str]:
        """Return a sorted list of all indexed package names."""
        if self._sqlite_reader is not None:
            return self._sqlite_reader.get_all_packages()
        return sorted(self._all_packages)
