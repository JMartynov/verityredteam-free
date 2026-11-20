"""SQLite + FTS5 on-disk cache for the vulnerability index."""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import sqlite3
import tempfile
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any

from mcp_vulnerabilities.models import OsvVulnerability

logger = logging.getLogger("verity.lookup.sqlite_cache")

SCHEMA_VERSION = "1"

_SCHEMA_SQL = """
CREATE TABLE cache_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE vulnerabilities (
    id_norm TEXT PRIMARY KEY,
    raw_json TEXT NOT NULL
);
CREATE TABLE packages (
    pkg_name TEXT PRIMARY KEY,
    pkg_lower TEXT NOT NULL
);
CREATE INDEX idx_packages_lower ON packages(pkg_lower);
CREATE VIRTUAL TABLE packages_fts USING fts5(pkg_name, tokenize='trigram');
CREATE TABLE package_vulns (
    pkg_norm TEXT NOT NULL,
    vuln_id_norm TEXT NOT NULL,
    seq INTEGER NOT NULL,
    PRIMARY KEY (pkg_norm, vuln_id_norm)
);
CREATE INDEX idx_package_vulns_pkg ON package_vulns(pkg_norm, seq);
CREATE TABLE purl_vulns (
    base_purl TEXT NOT NULL,
    vuln_id_norm TEXT NOT NULL,
    seq INTEGER NOT NULL,
    PRIMARY KEY (base_purl, vuln_id_norm)
);
CREATE INDEX idx_purl_vulns_purl ON purl_vulns(base_purl, seq);
CREATE TABLE alias_vulns (
    alias_norm TEXT NOT NULL,
    vuln_id_norm TEXT NOT NULL,
    seq INTEGER NOT NULL,
    PRIMARY KEY (alias_norm, vuln_id_norm)
);
CREATE INDEX idx_alias_vulns_alias ON alias_vulns(alias_norm, seq);
CREATE TABLE tool_vulns (
    tool_norm TEXT NOT NULL,
    vuln_id_norm TEXT NOT NULL,
    seq INTEGER NOT NULL,
    PRIMARY KEY (tool_norm, vuln_id_norm)
);
CREATE INDEX idx_tool_vulns_tool ON tool_vulns(tool_norm, seq);
CREATE TABLE cwe_vulns (
    cwe_norm TEXT NOT NULL,
    vuln_id_norm TEXT NOT NULL,
    seq INTEGER NOT NULL,
    PRIMARY KEY (cwe_norm, vuln_id_norm)
);
CREATE INDEX idx_cwe_vulns_cwe ON cwe_vulns(cwe_norm, seq);
"""


def cache_db_path_for(snapshot_path: Path) -> Path:
    """Return the SQLite cache path that sits alongside a snapshot file."""
    return snapshot_path.parent / f"{snapshot_path.name}.sqlite"


def read_etag(snapshot_path: Path) -> str:
    """Return the stored ETag for a snapshot, or an empty string."""
    etag_path = Path(f"{snapshot_path}.etag")
    with contextlib.suppress(OSError):
        if etag_path.is_file():
            return etag_path.read_text(encoding="utf-8").strip()
    return ""


def compute_file_sha256(path: Path) -> str:
    """Return the hex SHA-256 digest of a file's bytes."""
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class SqliteIndexReader:
    """Read-only query interface over a SQLite vulnerability index cache."""

    _VULN_CACHE_MAX = 512

    def __init__(
        self, db_path: Path, conn: sqlite3.Connection | None = None
    ) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        if conn is not None:
            self._conn = conn
        else:
            self._conn = sqlite3.connect(
                f"{db_path.resolve().as_uri()}?mode=ro",
                uri=True,
                check_same_thread=False,
            )
        self._vuln_cache: OrderedDict[str, OsvVulnerability] = OrderedDict()
        self._total_vulnerabilities = self._scalar(
            "SELECT COUNT(*) FROM vulnerabilities"
        )
        self._total_packages = self._scalar("SELECT COUNT(*) FROM packages")

    def _scalar(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        with self._lock:
            cur = self._conn.execute(sql, params)
            row = cur.fetchone()
        return int(row[0]) if row else 0

    def _load_vuln(self, id_norm: str) -> OsvVulnerability | None:
        with self._lock:
            cached = self._vuln_cache.get(id_norm)
            if cached is not None:
                self._vuln_cache.move_to_end(id_norm)
                return cached
            cur = self._conn.execute(
                "SELECT raw_json FROM vulnerabilities WHERE id_norm = ?", (id_norm,)
            )
            row = cur.fetchone()
            if not row:
                return None
            try:
                vuln = OsvVulnerability.from_dict(json.loads(row[0]))
            except Exception as exc:
                logger.debug("Failed to deserialize cached vuln %s: %s", id_norm, exc)
                return None
            self._vuln_cache[id_norm] = vuln
            self._vuln_cache.move_to_end(id_norm)
            while len(self._vuln_cache) > self._VULN_CACHE_MAX:
                self._vuln_cache.popitem(last=False)
            return vuln

    def _collect(self, sql: str, params: tuple[Any, ...]) -> list[OsvVulnerability]:
        with self._lock:
            id_norms = [row[0] for row in self._conn.execute(sql, params)]
        results: list[OsvVulnerability] = []
        for id_norm in id_norms:
            vuln = self._load_vuln(id_norm)
            if vuln is not None:
                results.append(vuln)
        return results

    @property
    def total_vulnerabilities(self) -> int:
        return self._total_vulnerabilities

    @property
    def total_packages(self) -> int:
        return self._total_packages

    def get_by_package_name(self, package_name: str) -> list[OsvVulnerability]:
        norm = package_name.strip().lower()
        results = self._collect(
            "SELECT vuln_id_norm FROM package_vulns WHERE pkg_norm = ? ORDER BY seq",
            (norm,),
        )
        if results:
            return results
        if "/" in norm:
            short_name = norm.split("/")[-1]
            return self._collect(
                "SELECT vuln_id_norm FROM package_vulns WHERE pkg_norm = ? ORDER BY seq",
                (short_name,),
            )
        return []

    def get_by_purl(self, purl: str) -> list[OsvVulnerability]:
        base_purl = purl.strip().lower().split("@")[0]
        return self._collect(
            "SELECT vuln_id_norm FROM purl_vulns WHERE base_purl = ? ORDER BY seq",
            (base_purl,),
        )

    def get_by_id_or_alias(self, identifier: str) -> list[OsvVulnerability]:
        norm = identifier.strip().upper()
        vuln = self._load_vuln(norm)
        if vuln is not None:
            return [vuln]
        return self._collect(
            "SELECT vuln_id_norm FROM alias_vulns WHERE alias_norm = ? ORDER BY seq",
            (norm,),
        )

    def get_by_tool(self, tool_name: str) -> list[OsvVulnerability]:
        norm = tool_name.strip().lower()
        return self._collect(
            "SELECT vuln_id_norm FROM tool_vulns WHERE tool_norm = ? ORDER BY seq",
            (norm,),
        )

    def get_by_cwe(self, cwe_id: str) -> list[OsvVulnerability]:
        norm = cwe_id.strip().upper()
        return self._collect(
            "SELECT vuln_id_norm FROM cwe_vulns WHERE cwe_norm = ? ORDER BY seq",
            (norm,),
        )

    def search_packages(self, query: str, limit: int = 50) -> list[str]:
        clean_q = query.strip().lower()
        with self._lock:
            if not clean_q:
                cur = self._conn.execute(
                    "SELECT pkg_name FROM packages ORDER BY pkg_name LIMIT ?", (limit,)
                )
                return [row[0] for row in cur]

            candidates: list[str] = []
            if len(clean_q) >= 3:
                match_expr = '"' + clean_q.replace('"', '""') + '"'
                try:
                    cur = self._conn.execute(
                        "SELECT pkg_name FROM packages_fts WHERE packages_fts MATCH ?",
                        (match_expr,),
                    )
                    candidates = [row[0] for row in cur]
                except sqlite3.Error as exc:
                    logger.debug("FTS query failed for %r: %s", clean_q, exc)
                    candidates = []
            else:
                cur = self._conn.execute(
                    "SELECT pkg_name FROM packages WHERE instr(pkg_lower, ?) > 0",
                    (clean_q,),
                )
                candidates = [row[0] for row in cur]

        exact_prefix: list[str] = []
        substring_matches: list[str] = []
        for pkg in candidates:
            pkg_lower = pkg.lower()
            if pkg_lower == clean_q or pkg_lower.startswith(clean_q):
                exact_prefix.append(pkg)
            elif clean_q in pkg_lower:
                substring_matches.append(pkg)

        return (sorted(exact_prefix) + sorted(substring_matches))[:limit]

    def get_all_packages(self) -> list[str]:
        with self._lock:
            cur = self._conn.execute("SELECT pkg_name FROM packages ORDER BY pkg_name")
            return [row[0] for row in cur]

    def close(self) -> None:
        with self._lock, contextlib.suppress(sqlite3.Error):
            self._conn.close()


def _read_meta(conn: sqlite3.Connection) -> dict[str, str]:
    try:
        cur = conn.execute("SELECT key, value FROM cache_meta")
        return {str(k): str(v) for k, v in cur}
    except sqlite3.Error:
        return {}


def open_valid_cache(
    snapshot_path: Path, db_path: Path | None = None
) -> SqliteIndexReader | None:
    """Open a SQLite cache if it is present and matches the snapshot file."""
    target = db_path or cache_db_path_for(snapshot_path)
    try:
        if not target.is_file() or not snapshot_path.is_file():
            return None
        st = snapshot_path.stat()
        conn = sqlite3.connect(f"{target.resolve().as_uri()}?mode=ro", uri=True)
        try:
            meta = _read_meta(conn)

            if meta.get("schema_version") != SCHEMA_VERSION:
                return None
            if meta.get("etag", "") != read_etag(snapshot_path):
                return None
            if meta.get("size") != str(st.st_size):
                return None

            if meta.get("mtime_ns") != str(st.st_mtime_ns):
                if compute_file_sha256(snapshot_path) != meta.get("sha256"):
                    return None
                with contextlib.suppress(sqlite3.Error):
                    rw = sqlite3.connect(str(target))
                    try:
                        with rw:
                            rw.execute(
                                "INSERT OR REPLACE INTO cache_meta(key, value) VALUES (?, ?)",
                                ("mtime_ns", str(st.st_mtime_ns)),
                            )
                    finally:
                        rw.close()

            reader = SqliteIndexReader(target, conn=conn)
            conn = None
            return reader
        finally:
            if conn is not None:
                with contextlib.suppress(sqlite3.Error):
                    conn.close()
    except (OSError, sqlite3.Error) as exc:
        logger.debug("SQLite cache validation failed for %s: %s", target, exc)
        return None


def build_sqlite_cache(
    snapshot_path: Path,
    records: list[tuple[OsvVulnerability, dict[str, Any]]],
    db_path: Path | None = None,
) -> Path | None:
    """Build a SQLite index cache atomically from parsed snapshot records."""
    target = db_path or cache_db_path_for(snapshot_path)
    tmp_path: str | None = None
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        st = snapshot_path.stat()
        etag = read_etag(snapshot_path)
        sha256 = compute_file_sha256(snapshot_path)

        with tempfile.NamedTemporaryFile(
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as tmp:
            tmp_path = tmp.name

        conn = sqlite3.connect(tmp_path)
        try:
            conn.execute("PRAGMA journal_mode=DELETE")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(_SCHEMA_SQL)

            packages: dict[str, str] = {}
            with conn:
                for seq, (vuln, vuln_dict) in enumerate(records):
                    id_norm = vuln.id.strip().upper()
                    conn.execute(
                        "INSERT OR REPLACE INTO vulnerabilities(id_norm, raw_json) "
                        "VALUES (?, ?)",
                        (id_norm, json.dumps(vuln_dict)),
                    )

                    for alias in vuln.aliases:
                        alias_norm = alias.strip().upper()
                        conn.execute(
                            "INSERT OR IGNORE INTO alias_vulns"
                            "(alias_norm, vuln_id_norm, seq) VALUES (?, ?, ?)",
                            (alias_norm, id_norm, seq),
                        )

                    for aff in vuln.affected:
                        pkg_name = aff.package.name.strip()
                        if pkg_name:
                            pkg_norm = pkg_name.lower()
                            packages[pkg_name] = pkg_norm
                            conn.execute(
                                "INSERT OR IGNORE INTO package_vulns"
                                "(pkg_norm, vuln_id_norm, seq) VALUES (?, ?, ?)",
                                (pkg_norm, id_norm, seq),
                            )

                        if aff.package.purl:
                            base_purl = aff.package.purl.strip().lower().split("@")[0]
                            conn.execute(
                                "INSERT OR IGNORE INTO purl_vulns"
                                "(base_purl, vuln_id_norm, seq) VALUES (?, ?, ?)",
                                (base_purl, id_norm, seq),
                            )

                        db = aff.database_specific
                        if db:
                            for tool in db.vulnerable_tools:
                                conn.execute(
                                    "INSERT OR IGNORE INTO tool_vulns"
                                    "(tool_norm, vuln_id_norm, seq) VALUES (?, ?, ?)",
                                    (tool.strip().lower(), id_norm, seq),
                                )
                            for cwe in db.cwe_ids:
                                conn.execute(
                                    "INSERT OR IGNORE INTO cwe_vulns"
                                    "(cwe_norm, vuln_id_norm, seq) VALUES (?, ?, ?)",
                                    (cwe.strip().upper(), id_norm, seq),
                                )

                for pkg_name, pkg_lower in packages.items():
                    conn.execute(
                        "INSERT OR REPLACE INTO packages(pkg_name, pkg_lower) "
                        "VALUES (?, ?)",
                        (pkg_name, pkg_lower),
                    )
                    conn.execute(
                        "INSERT INTO packages_fts(pkg_name) VALUES (?)", (pkg_name,)
                    )

                meta = {
                    "schema_version": SCHEMA_VERSION,
                    "etag": etag,
                    "mtime_ns": str(st.st_mtime_ns),
                    "size": str(st.st_size),
                    "sha256": sha256,
                    "total_vulnerabilities": str(len(records)),
                    "total_packages": str(len(packages)),
                }
                conn.executemany(
                    "INSERT OR REPLACE INTO cache_meta(key, value) VALUES (?, ?)",
                    list(meta.items()),
                )
        finally:
            conn.close()

        os.replace(tmp_path, target)
        tmp_path = None
        return target
    except (OSError, sqlite3.Error) as exc:
        logger.warning("Failed to build SQLite cache %s: %s", target, exc)
        return None
    finally:
        if tmp_path is not None:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)
