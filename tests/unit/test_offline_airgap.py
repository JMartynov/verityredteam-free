"""Offline / air-gapped cold-start guarantees for Verity (M14)."""

from __future__ import annotations

import gzip
import json
import logging
import os
import socket
import time
import urllib.request
from pathlib import Path

import pytest

import verity.data_fetcher as data_fetcher
from verity import cli
from verity.discovery.auditor import ConsolidatedSecurityAuditor
from verity.fingerprint.matcher import FingerprintMatcher
from verity.lookup.index import VulnerabilityIndex

SECRET_VALUE = "sk-airgapped-secret-9876543210"


def _forbid_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def _forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("Network call forbidden in offline mode")

    monkeypatch.setattr(socket, "create_connection", _forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", _forbidden)


@pytest.fixture
def airgap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolate cwd, VERITY_CACHE_DIR and upstream caches; forbid all network."""
    cache_dir = tmp_path / "verity_cache"
    cache_dir.mkdir()
    monkeypatch.setenv("VERITY_CACHE_DIR", str(cache_dir))
    monkeypatch.setenv("VERITY_OFFLINE", "1")
    monkeypatch.chdir(tmp_path)

    data_loader = pytest.importorskip("mcp_fingerprints.data_loader")
    upstream_cache = tmp_path / "upstream_cache"
    upstream_cache.mkdir()
    monkeypatch.setattr(data_loader, "CACHE_DIR", upstream_cache, raising=False)

    _forbid_network(monkeypatch)
    return cache_dir


def _passports_payload() -> dict:
    return {
        "passports": {
            "mcp-remote": {
                "package_name": "mcp-remote",
                "purl": "pkg:npm/mcp-remote",
                "ecosystem": "npm",
                "versions": [
                    {
                        "version": "0.1.15",
                        "toolset_canonical_hash": "sha256:dummy",
                        "tool_signatures": [],
                    }
                ],
            }
        }
    }


def _vulnerabilities_payload() -> dict:
    return {
        "vulnerabilities": {
            "CVE-2025-6514": {
                "id": "CVE-2025-6514",
                "summary": "mcp-remote OS command injection",
                "details": "RCE in mcp-remote",
                "affected": [
                    {
                        "package": {
                            "name": "mcp-remote",
                            "ecosystem": "npm",
                            "purl": "pkg:npm/mcp-remote",
                        },
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [
                                    {"introduced": "0.0.1"},
                                    {"fixed": "0.1.16"},
                                ],
                            }
                        ],
                        "database_specific": {
                            "severity": "CRITICAL",
                            "cvss_score": 9.6,
                        },
                    }
                ],
            }
        }
    }


def _write_expired_gz(path: Path, payload: dict) -> None:
    path.write_bytes(gzip.compress(json.dumps(payload).encode("utf-8")))
    expired = time.time() - (data_fetcher.DEFAULT_TTL_SECONDS * 2)
    os.utime(path, (expired, expired))


def test_offline_scan_makes_zero_network_calls(
    airgap: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config_path = tmp_path / "airgap_mcp.json"
    config_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "leaky-workstation": {
                        "command": "bash",
                        "args": ["-c", "npx -y mcp-remote@0.1.15"],
                        "env": {"OPENAI_API_KEY": SECRET_VALUE},
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    ConsolidatedSecurityAuditor()

    started = time.monotonic()
    exit_code = cli.main(["scan", "--config-file", str(config_path), "--offline"])
    elapsed = time.monotonic() - started
    out = capsys.readouterr().out

    assert exit_code == 0
    assert elapsed < 1.0
    assert "SEC-STATIC-SECRET-IN-CONFIG" in out
    assert "SEC-STATIC-UNSAFE-SHELL-WRAPPER" in out
    assert SECRET_VALUE not in out


def test_offline_uses_expired_cache_and_detects_cve(
    airgap: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_expired_gz(airgap / "passports.json.gz", _passports_payload())
    _write_expired_gz(airgap / "vulnerabilities.json.gz", _vulnerabilities_payload())

    config_path = tmp_path / "mcp.json"
    config_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "remote": {
                        "command": "npx",
                        "args": ["-y", "mcp-remote@0.1.15"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    exit_code = cli.main(
        ["scan", "--config-file", str(config_path), "--offline", "--format", "json"]
    )
    out = capsys.readouterr().out
    report = json.loads(out)
    rule_ids = {f["rule_id"] for f in report["findings"]}

    assert exit_code == 0
    assert "VULN-CVE-2025-6514" in rule_ids


def test_load_from_directory_offline_is_network_free(
    airgap: Path, tmp_path: Path
) -> None:
    empty = tmp_path / "empty_kb"
    empty.mkdir()
    missing = tmp_path / "missing_kb"

    matcher = FingerprintMatcher()
    index = VulnerabilityIndex()

    assert matcher.load_from_directory(empty) == 0
    assert index.load_from_directory(empty) == 0
    assert matcher.load_from_directory(missing) == 0
    assert index.load_from_directory(missing) == 0


def test_online_fetch_still_performs_http(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("VERITY_OFFLINE", raising=False)
    cache_dir = tmp_path / "online_cache"
    monkeypatch.setenv("VERITY_CACHE_DIR", str(cache_dir))

    payload = gzip.compress(json.dumps({"passports": {}}).encode("utf-8"))
    calls: list[object] = []

    class _Response:
        status = 200

        def __init__(self) -> None:
            self.headers = {"ETag": '"abc123"'}

        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *exc: object) -> bool:
            return False

        def read(self) -> bytes:
            return payload

    def _fake_urlopen(req: object, *args: object, **kwargs: object) -> _Response:
        calls.append(req)
        return _Response()

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)

    data = data_fetcher.fetch_remote_snapshot(
        "https://example.invalid/snapshot.json.gz", "snapshot.json.gz"
    )

    assert data == {"passports": {}}
    assert len(calls) == 1
    assert (cache_dir / "snapshot.json.gz").is_file()


def test_offline_fetch_never_network_and_logs_notice(
    airgap: Path,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="verity.data_fetcher"):
        result = data_fetcher.fetch_remote_snapshot(
            "https://example.invalid/snapshot.json.gz",
            "unknown_snapshot.json.gz",
            force_refresh=True,
        )

    assert result is None
    assert capsys.readouterr().out == ""
    assert any("Offline mode" in record.message for record in caplog.records)


def test_offline_corrupted_cache_is_handled_gracefully(
    airgap: Path, caplog: pytest.LogCaptureFixture
) -> None:
    (airgap / "unknown_snapshot.json.gz").write_bytes(b"not-a-valid-gzip")

    with caplog.at_level(logging.WARNING, logger="verity.data_fetcher"):
        result = data_fetcher.fetch_remote_snapshot(
            "https://example.invalid/snapshot.json.gz", "unknown_snapshot.json.gz"
        )

    assert result is None
    assert any("Ignoring unreadable" in record.message for record in caplog.records)


def test_online_304_not_modified_uses_expired_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("VERITY_OFFLINE", raising=False)
    cache_dir = tmp_path / "online_cache"
    cache_dir.mkdir()
    monkeypatch.setenv("VERITY_CACHE_DIR", str(cache_dir))

    cache_path = cache_dir / "snapshot.json.gz"
    cache_path.write_bytes(
        gzip.compress(json.dumps({"passports": {"cached": 1}}).encode("utf-8"))
    )
    expired = time.time() - (data_fetcher.DEFAULT_TTL_SECONDS * 2)
    os.utime(cache_path, (expired, expired))
    (cache_dir / "snapshot.json.gz.etag").write_text('"abc123"', encoding="utf-8")

    seen_headers: list[dict[str, str]] = []

    class _NotModified:
        status = 304

        def __init__(self) -> None:
            self.headers: dict[str, str] = {}

        def __enter__(self) -> _NotModified:
            return self

        def __exit__(self, *exc: object) -> bool:
            return False

        def read(self) -> bytes:
            return b""

    def _fake_urlopen(
        req: urllib.request.Request, *args: object, **kwargs: object
    ) -> _NotModified:
        seen_headers.append(dict(req.header_items()))
        return _NotModified()

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)

    returned = data_fetcher.fetch_remote_snapshot(
        "https://example.invalid/snapshot.json.gz", "snapshot.json.gz"
    )

    assert returned == {"passports": {"cached": 1}}
    assert seen_headers
    assert "if-none-match" in {key.lower() for key in seen_headers[0]}
