"""Unit tests for the SQLite + FTS5 vulnerability index cache."""

from __future__ import annotations

import gzip
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest

import verity.data_fetcher as data_fetcher
from verity.lookup.engine import VulnerabilityLookupEngine
from verity.lookup.index import VulnerabilityIndex
from verity.lookup.sqlite_cache import (
    SCHEMA_VERSION,
    cache_db_path_for,
    open_valid_cache,
    read_etag,
)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _vuln(
    vuln_id: str,
    *,
    summary: str = "",
    aliases: list[str] | None = None,
    packages: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "id": vuln_id,
        "summary": summary or f"summary for {vuln_id}",
        "details": f"details for {vuln_id}",
        "aliases": aliases or [],
        "affected": packages or [],
    }


def _affected(
    name: str,
    *,
    ecosystem: str = "npm",
    purl: str | None = None,
    introduced: str = "0.0.1",
    fixed: str = "9.9.9",
    tools: list[str] | None = None,
    cwes: list[str] | None = None,
    severity: str = "HIGH",
    cvss_score: float = 7.5,
) -> dict[str, Any]:
    pkg: dict[str, Any] = {"name": name, "ecosystem": ecosystem}
    if purl:
        pkg["purl"] = purl
    db: dict[str, Any] = {"severity": severity, "cvss_score": cvss_score}
    if tools:
        db["vulnerable_tools"] = tools
    if cwes:
        db["cwe_ids"] = cwes
    return {
        "package": pkg,
        "ranges": [
            {
                "type": "SEMVER",
                "events": [{"introduced": introduced}, {"fixed": fixed}],
            }
        ],
        "database_specific": db,
    }


def _payload() -> dict[str, Any]:
    return {
        "vulnerabilities": {
            "CVE-2025-6514": _vuln(
                "CVE-2025-6514",
                summary="mcp-remote OS command injection",
                aliases=["GHSA-aaaa-bbbb-cccc"],
                packages=[
                    _affected(
                        "mcp-remote",
                        purl="pkg:npm/mcp-remote",
                        introduced="0.0.1",
                        fixed="0.1.16",
                        tools=["remote_exec"],
                        cwes=["CWE-78"],
                        severity="CRITICAL",
                        cvss_score=9.6,
                    )
                ],
            ),
            "GHSA-1111-2222-3333": _vuln(
                "GHSA-1111-2222-3333",
                summary="mcp-server-filesystem path traversal",
                aliases=["CVE-2025-0001"],
                packages=[
                    _affected(
                        "@modelcontextprotocol/server-filesystem",
                        purl="pkg:npm/%40modelcontextprotocol/server-filesystem",
                        tools=["read_file"],
                        cwes=["CWE-22"],
                        severity="HIGH",
                        cvss_score=8.1,
                    )
                ],
            ),
            "GHSA-9999-8888-7777": _vuln(
                "GHSA-9999-8888-7777",
                summary="mcp-remote credential leak",
                packages=[
                    _affected(
                        "mcp-remote",
                        purl="pkg:npm/mcp-remote",
                        introduced="0.0.1",
                        fixed="0.1.20",
                        tools=["remote_exec"],
                        cwes=["CWE-200"],
                        severity="MEDIUM",
                        cvss_score=5.0,
                    )
                ],
            ),
            "CVE-2024-1234": _vuln(
                "CVE-2024-1234",
                summary="unrelated package vuln",
                packages=[
                    _affected(
                        "left-pad",
                        purl="pkg:npm/left-pad",
                        severity="LOW",
                        cvss_score=2.0,
                    )
                ],
            ),
        }
    }


def _write_gz(
    path: Path,
    payload: dict[str, Any],
    *,
    etag: str | None = None,
    compresslevel: int = 9,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        gzip.compress(
            json.dumps(payload).encode("utf-8"), compresslevel=compresslevel
        )
    )
    if etag is not None:
        Path(f"{path}.etag").write_text(etag, encoding="utf-8")


def _forbid_network(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket
    import urllib.request

    def _forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("Network call forbidden in offline mode")

    monkeypatch.setattr(socket, "create_connection", _forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", _forbidden)


def _forbid_gunzip(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*args: object, **kwargs: object) -> None:
        raise AssertionError("Should not gunzip on warm cache hit")

    monkeypatch.setattr(gzip, "open", _boom)
    monkeypatch.setattr(gzip, "decompress", _boom)


def _sqlite_tables(db_path: Path) -> set[str]:
    conn = sqlite3.connect(str(db_path))
    try:
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view')")
        return {row[0] for row in cur}
    finally:
        conn.close()


def _sqlite_meta(db_path: Path) -> dict[str, str]:
    conn = sqlite3.connect(str(db_path))
    try:
        cur = conn.execute("SELECT key, value FROM cache_meta")
        return {str(k): str(v) for k, v in cur}
    finally:
        conn.close()


@pytest.fixture
def cache_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolate VERITY_CACHE_DIR and cwd; forbid network by default."""
    cache_dir = tmp_path / "verity_cache"
    cache_dir.mkdir()
    monkeypatch.setenv("VERITY_CACHE_DIR", str(cache_dir))
    monkeypatch.setenv("VERITY_OFFLINE", "1")
    monkeypatch.chdir(tmp_path)
    _forbid_network(monkeypatch)
    return cache_dir


def _snapshot_path(cache_dir: Path) -> Path:
    return cache_dir / "vulnerabilities.json.gz"


def _assert_warm_state(idx: VulnerabilityIndex) -> None:
    assert idx._sqlite_reader is not None
    assert idx._by_id == {}
    assert idx._by_package_name == {}
    assert idx._by_purl == {}
    assert idx._by_alias == {}
    assert idx._by_tool == {}
    assert idx._by_cwe == {}
    assert idx._all_packages == set()
    assert idx._trigram_to_packages == {}


def _assert_equivalent(idx: VulnerabilityIndex, ref: VulnerabilityIndex) -> None:
    assert idx.total_vulnerabilities == ref.total_vulnerabilities
    assert idx.total_packages == ref.total_packages
    assert idx.is_loaded is True

    # get_by_package_name: exact, case-insensitive, scoped fallback
    for name in ("mcp-remote", "MCP-Remote", "left-pad"):
        assert [v.id for v in idx.get_by_package_name(name)] == [
            v.id for v in ref.get_by_package_name(name)
        ]
    assert [v.id for v in idx.get_by_package_name("server-filesystem")] == [
        v.id for v in ref.get_by_package_name("server-filesystem")
    ]
    assert [v.id for v in idx.get_by_package_name("nope")] == []

    # get_by_purl with and without @version
    for purl in (
        "pkg:npm/mcp-remote",
        "pkg:npm/mcp-remote@0.1.15",
        "pkg:npm/left-pad",
        "pkg:npm/unknown",
    ):
        assert [v.id for v in idx.get_by_purl(purl)] == [
            v.id for v in ref.get_by_purl(purl)
        ]

    # get_by_id_or_alias: ID and alias
    for ident in (
        "CVE-2025-6514",
        "cve-2025-6514",
        "GHSA-aaaa-bbbb-cccc",
        "CVE-2025-0001",
        "GHSA-1111-2222-3333",
        "CVE-9999-0000",
    ):
        assert [v.id for v in idx.get_by_id_or_alias(ident)] == [
            v.id for v in ref.get_by_id_or_alias(ident)
        ]

    # get_by_tool
    for tool in ("remote_exec", "REMOTE_EXEC", "read_file", "missing"):
        assert [v.id for v in idx.get_by_tool(tool)] == [
            v.id for v in ref.get_by_tool(tool)
        ]

    # get_by_cwe
    for cwe in ("CWE-78", "cwe-78", "CWE-22", "CWE-200", "CWE-999"):
        assert [v.id for v in idx.get_by_cwe(cwe)] == [
            v.id for v in ref.get_by_cwe(cwe)
        ]

    # search_packages: empty, <3 chars, >=3 chars, ordering, limit
    for query in ("", "ab", "mc", "rem", "mcp-", "MCP-", "server", "left", "zzz"):
        assert idx.search_packages(query) == ref.search_packages(query)
    assert idx.search_packages("mcp-", limit=1) == ref.search_packages("mcp-", limit=1)
    assert idx.search_packages("", limit=2) == ref.search_packages("", limit=2)

    # exact-prefix before substring ordering
    results = idx.search_packages("mcp")
    assert results == ref.search_packages("mcp")
    if "mcp-remote" in results and "@modelcontextprotocol/server-filesystem" in results:
        assert results.index("mcp-remote") < results.index(
            "@modelcontextprotocol/server-filesystem"
        )

    # get_all_packages
    assert idx.get_all_packages() == ref.get_all_packages()

    # Engine query / search
    engine = VulnerabilityLookupEngine(index=idx)
    ref_engine = VulnerabilityLookupEngine(index=ref)
    for ident, ver in (
        ("mcp-remote", "0.1.15"),
        ("mcp-remote", "0.1.20"),
        ("mcp-remote@0.1.15", None),
        ("pkg:npm/mcp-remote@0.1.15", None),
        ("CVE-2025-6514", None),
        ("left-pad", "1.0.0"),
    ):
        got = engine.query(ident, ver)
        want = ref_engine.query(ident, ver)
        assert got.is_vulnerable == want.is_vulnerable
        assert got.max_severity == want.max_severity
        assert got.max_cvss_score == want.max_cvss_score
        assert [m.vulnerability_id for m in got.vulnerabilities] == [
            m.vulnerability_id for m in want.vulnerabilities
        ]
        assert got.all_vulnerable_tools == want.all_vulnerable_tools
        assert got.all_cwe_ids == want.all_cwe_ids

    for kwargs in (
        {"query": "mcp"},
        {"query": "rem"},
        {"query": ""},
        {"query": "", "by_tool": "remote_exec"},
        {"query": "", "by_cwe": "CWE-78"},
    ):
        assert engine.search(**kwargs) == ref_engine.search(**kwargs)


# ---------------------------------------------------------------------------
# 1. First load builds the SQLite + FTS5 cache
# ---------------------------------------------------------------------------


def test_first_load_from_snapshot_builds_sqlite_cache(cache_env: Path) -> None:
    snap = _snapshot_path(cache_env)
    _write_gz(snap, _payload(), etag='"etag-1"')
    db_path = cache_db_path_for(snap)
    assert not db_path.exists()

    idx = VulnerabilityIndex()
    try:
        loaded = idx.load_from_snapshot(snap)
        assert loaded == 4
        assert idx.is_loaded is True
        assert db_path.is_file()
        assert idx._sqlite_reader is not None
        _assert_warm_state(idx)

        tables = _sqlite_tables(db_path)
        assert "packages_fts" in tables
        assert "cache_meta" in tables
        assert "vulnerabilities" in tables
        assert "package_vulns" in tables

        meta = _sqlite_meta(db_path)
        assert meta["schema_version"] == SCHEMA_VERSION
        assert meta["etag"] == '"etag-1"'
        assert meta["total_vulnerabilities"] == "4"
    finally:
        idx.close()


def test_first_load_auto_offline_builds_sqlite_cache(
    cache_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snap = _snapshot_path(cache_env)
    _write_gz(snap, _payload(), etag='"etag-auto"')
    db_path = cache_db_path_for(snap)

    monkeypatch.setattr(
        data_fetcher, "resolve_cached_snapshot", lambda name: snap
    )

    idx = VulnerabilityIndex()
    try:
        loaded = idx.load_auto(cache_env / "missing_kb")
        assert loaded == 4
        assert db_path.is_file()
        assert idx._sqlite_reader is not None
        _assert_warm_state(idx)
        assert "packages_fts" in _sqlite_tables(db_path)
        assert "cache_meta" in _sqlite_tables(db_path)
    finally:
        idx.close()


def test_first_load_auto_online_fetch_builds_sqlite_cache(
    cache_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("VERITY_OFFLINE", raising=False)
    snap = _snapshot_path(cache_env)
    db_path = cache_db_path_for(snap)
    payload = _payload()
    raw = gzip.compress(json.dumps(payload).encode("utf-8"))

    def _fake_fetch(force_refresh: bool = False) -> dict[str, Any]:
        _write_gz(snap, payload, etag='"etag-online"')
        return payload

    monkeypatch.setattr(
        data_fetcher, "fetch_vulnerabilities_snapshot", _fake_fetch
    )
    monkeypatch.setattr(
        data_fetcher, "resolve_cached_snapshot", lambda name: snap
    )

    idx = VulnerabilityIndex()
    try:
        loaded = idx.load_auto(cache_env / "missing_kb", force_refresh=True)
        assert loaded == 4
        assert db_path.is_file()
        assert idx._sqlite_reader is not None
        _assert_warm_state(idx)
        assert "packages_fts" in _sqlite_tables(db_path)
        assert "cache_meta" in _sqlite_tables(db_path)
        assert raw  # sanity: payload was gzip-encodable
    finally:
        idx.close()


# ---------------------------------------------------------------------------
# 2. Warm cache hit: no gunzip, no in-memory dicts, identical results
# ---------------------------------------------------------------------------


def _build_reference(payload: dict[str, Any]) -> VulnerabilityIndex:
    ref = VulnerabilityIndex()
    ref.load_from_snapshot(payload)
    return ref


def test_warm_load_from_snapshot_skips_gunzip_and_matches_in_memory(
    cache_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = _payload()
    snap = _snapshot_path(cache_env)
    _write_gz(snap, payload, etag='"etag-warm"')

    cold = VulnerabilityIndex()
    try:
        assert cold.load_from_snapshot(snap) == 4
    finally:
        cold.close()

    _forbid_gunzip(monkeypatch)

    ref = _build_reference(payload)
    warm = VulnerabilityIndex()
    try:
        assert warm.load_from_snapshot(snap) == 4
        _assert_warm_state(warm)
        _assert_equivalent(warm, ref)
    finally:
        warm.close()
        ref.close()


def test_warm_load_auto_offline_skips_gunzip_and_matches_in_memory(
    cache_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = _payload()
    snap = _snapshot_path(cache_env)
    _write_gz(snap, payload, etag='"etag-warm-auto"')

    cold = VulnerabilityIndex()
    try:
        assert cold.load_from_snapshot(snap) == 4
    finally:
        cold.close()

    monkeypatch.setattr(
        data_fetcher, "resolve_cached_snapshot", lambda name: snap
    )
    _forbid_gunzip(monkeypatch)

    ref = _build_reference(payload)
    warm = VulnerabilityIndex()
    try:
        assert warm.load_auto(cache_env / "missing_kb") == 4
        _assert_warm_state(warm)
        _assert_equivalent(warm, ref)
    finally:
        warm.close()
        ref.close()


def test_warm_load_auto_online_within_ttl_skips_gunzip(
    cache_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("VERITY_OFFLINE", raising=False)
    payload = _payload()
    snap = _snapshot_path(cache_env)
    _write_gz(snap, payload, etag='"etag-warm-online"')

    cold = VulnerabilityIndex()
    try:
        assert cold.load_from_snapshot(snap) == 4
    finally:
        cold.close()

    monkeypatch.setattr(
        data_fetcher, "resolve_cached_snapshot", lambda name: snap
    )

    def _no_fetch(*args: object, **kwargs: object) -> None:
        raise AssertionError("fetch should not be called within TTL")

    monkeypatch.setattr(
        data_fetcher, "fetch_vulnerabilities_snapshot", _no_fetch
    )
    _forbid_gunzip(monkeypatch)

    ref = _build_reference(payload)
    warm = VulnerabilityIndex()
    try:
        assert warm.load_auto(cache_env / "missing_kb") == 4
        _assert_warm_state(warm)
        _assert_equivalent(warm, ref)
    finally:
        warm.close()
        ref.close()


# ---------------------------------------------------------------------------
# 3. ETag change invalidates and rebuilds
# ---------------------------------------------------------------------------


def test_etag_change_invalidates_and_rebuilds(cache_env: Path) -> None:
    payload = _payload()
    snap = _snapshot_path(cache_env)
    _write_gz(snap, payload, etag='"etag-old"')
    db_path = cache_db_path_for(snap)

    idx = VulnerabilityIndex()
    try:
        assert idx.load_from_snapshot(snap) == 4
        assert _sqlite_meta(db_path)["etag"] == '"etag-old"'
    finally:
        idx.close()

    Path(f"{snap}.etag").write_text('"etag-new"', encoding="utf-8")

    idx2 = VulnerabilityIndex()
    try:
        assert idx2.load_from_snapshot(snap) == 4
        assert _sqlite_meta(db_path)["etag"] == '"etag-new"'
        assert idx2._sqlite_reader is not None
    finally:
        idx2.close()


# ---------------------------------------------------------------------------
# 4. Snapshot content change invalidates and rebuilds
# ---------------------------------------------------------------------------


def test_snapshot_content_change_invalidates_and_rebuilds(cache_env: Path) -> None:
    snap = _snapshot_path(cache_env)
    _write_gz(snap, _payload(), etag='"etag-same"')
    db_path = cache_db_path_for(snap)

    idx = VulnerabilityIndex()
    try:
        assert idx.load_from_snapshot(snap) == 4
        assert idx.get_by_id_or_alias("CVE-2026-9999") == []
    finally:
        idx.close()

    new_payload = _payload()
    new_payload["vulnerabilities"]["CVE-2026-9999"] = _vuln(
        "CVE-2026-9999",
        summary="brand new advisory",
        packages=[_affected("mcp-remote", purl="pkg:npm/mcp-remote")],
    )
    _write_gz(snap, new_payload, etag='"etag-same"')

    idx2 = VulnerabilityIndex()
    try:
        assert idx2.load_from_snapshot(snap) == 5
        assert [v.id for v in idx2.get_by_id_or_alias("CVE-2026-9999")] == [
            "CVE-2026-9999"
        ]
        assert _sqlite_meta(db_path)["total_vulnerabilities"] == "5"
    finally:
        idx2.close()


# ---------------------------------------------------------------------------
# 4b. Same-size, same-ETag, different-content change invalidates via SHA-256
# ---------------------------------------------------------------------------


def test_same_size_same_etag_content_change_invalidates_via_sha256(
    cache_env: Path,
) -> None:
    snap = _snapshot_path(cache_env)
    _write_gz(snap, _payload(), etag='"etag-sha"', compresslevel=0)
    db_path = cache_db_path_for(snap)

    idx = VulnerabilityIndex()
    try:
        assert idx.load_from_snapshot(snap) == 4
        assert idx.get_by_id_or_alias("CVE-2026-7777") == []
    finally:
        idx.close()

    before_meta = _sqlite_meta(db_path)
    before_size = snap.stat().st_size

    # Build a replacement payload with identical serialized size but different
    # content: swap one advisory ID for another of the same length.
    new_payload = _payload()
    vulns = new_payload["vulnerabilities"]
    vulns["CVE-2026-7777"] = _vuln(
        "CVE-2026-7777",
        summary="unrelated package vuln",
        packages=[
            _affected(
                "left-pad",
                purl="pkg:npm/left-pad",
                severity="LOW",
                cvss_score=2.0,
            )
        ],
    )
    vulns.pop("CVE-2024-1234")
    _write_gz(snap, new_payload, etag='"etag-sha"', compresslevel=0)

    assert snap.stat().st_size == before_size
    assert read_etag(snap) == before_meta["etag"]

    # Force a different mtime so validation falls through to SHA-256.
    future = time.time() + 7200
    os.utime(snap, (future, future))

    idx2 = VulnerabilityIndex()
    try:
        assert idx2.load_from_snapshot(snap) == 4
        assert [v.id for v in idx2.get_by_id_or_alias("CVE-2026-7777")] == [
            "CVE-2026-7777"
        ]
        assert idx2.get_by_id_or_alias("CVE-2024-1234") == []
        after_meta = _sqlite_meta(db_path)
        assert after_meta["sha256"] != before_meta["sha256"]
        assert after_meta["mtime_ns"] == str(snap.stat().st_mtime_ns)
    finally:
        idx2.close()


# ---------------------------------------------------------------------------
# 5. mtime-only change does not rebuild or gunzip
# ---------------------------------------------------------------------------


def test_mtime_only_change_does_not_rebuild_or_gunzip(
    cache_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snap = _snapshot_path(cache_env)
    _write_gz(snap, _payload(), etag='"etag-mtime"')
    db_path = cache_db_path_for(snap)

    idx = VulnerabilityIndex()
    try:
        assert idx.load_from_snapshot(snap) == 4
    finally:
        idx.close()

    before_meta = _sqlite_meta(db_path)
    before_mtime = db_path.stat().st_mtime_ns

    future = time.time() + 3600
    os.utime(snap, (future, future))

    _forbid_gunzip(monkeypatch)

    idx2 = VulnerabilityIndex()
    try:
        assert idx2.load_from_snapshot(snap) == 4
        _assert_warm_state(idx2)
    finally:
        idx2.close()

    after_meta = _sqlite_meta(db_path)
    assert after_meta["sha256"] == before_meta["sha256"]
    assert after_meta["etag"] == before_meta["etag"]
    assert after_meta["mtime_ns"] == str(snap.stat().st_mtime_ns)
    # Cache file itself was not rewritten (only meta row updated in place).
    assert db_path.stat().st_mtime_ns >= before_mtime


# ---------------------------------------------------------------------------
# 6. Corrupted SQLite cache is gracefully rebuilt
# ---------------------------------------------------------------------------


def test_corrupted_sqlite_cache_is_rebuilt(cache_env: Path) -> None:
    payload = _payload()
    snap = _snapshot_path(cache_env)
    _write_gz(snap, payload, etag='"etag-corrupt"')
    db_path = cache_db_path_for(snap)

    idx = VulnerabilityIndex()
    try:
        assert idx.load_from_snapshot(snap) == 4
    finally:
        idx.close()

    db_path.write_bytes(b"this is not a sqlite database")

    assert open_valid_cache(snap) is None

    idx2 = VulnerabilityIndex()
    try:
        assert idx2.load_from_snapshot(snap) == 4
        assert idx2._sqlite_reader is not None
        _assert_warm_state(idx2)
        assert "packages_fts" in _sqlite_tables(db_path)
        assert _sqlite_meta(db_path)["etag"] == '"etag-corrupt"'
    finally:
        idx2.close()
