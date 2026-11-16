"""Data fetcher and snapshot cache manager for public MCP knowledge base and advisory datasets."""

from __future__ import annotations

import contextlib
import gzip
import json
import logging
import os
import ssl
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

logger = logging.getLogger("verity.data_fetcher")

# Public repository endpoints
PUBLIC_PASSPORTS_URL = (
    "https://raw.githubusercontent.com/JMartynov/mcp-fingerprints/main/passports.json.gz"
)
PUBLIC_VULNERABILITIES_URL = (
    "https://raw.githubusercontent.com/JMartynov/mcp-vulnerabilities/main/vulnerabilities.json.gz"
)

DEFAULT_TTL_SECONDS = 86400.0


def _get_cache_dir() -> Path:
    """Return cache directory for verity datasets with write-permission verification."""
    env_dir = os.environ.get("VERITY_CACHE_DIR")
    candidate_paths: list[Path] = []
    if env_dir:
        candidate_paths.append(Path(env_dir))

    xdg_cache = os.environ.get("XDG_CACHE_HOME")
    if xdg_cache:
        candidate_paths.append(Path(xdg_cache) / "verity")

    candidate_paths.append(Path.home() / ".cache" / "verity")
    candidate_paths.append(Path(tempfile.gettempdir()) / "verity_cache")

    for p in candidate_paths:
        try:
            p.mkdir(parents=True, exist_ok=True)
            test_file = p / f".write_test_{os.getpid()}"
            test_file.write_text("ok", encoding="utf-8")
            test_file.unlink(missing_ok=True)
            return p
        except Exception:
            continue

    fallback = Path(tempfile.gettempdir()) / "verity_cache"
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


def _create_ssl_context() -> ssl.SSLContext:
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        pass
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch_remote_snapshot(
    url: str,
    cached_filename: str,
    max_age_seconds: float = DEFAULT_TTL_SECONDS,
    force_refresh: bool = False,
) -> dict[str, Any] | None:
    """Fetch a compressed JSON snapshot from a remote URL with disk caching."""
    cache_dir = _get_cache_dir()
    cache_path = cache_dir / cached_filename
    etag_path = cache_dir / f"{cached_filename}.etag"

    # Check local cache validity
    if not force_refresh and cache_path.is_file():
        mtime = cache_path.stat().st_mtime
        if (time.time() - mtime) < max_age_seconds:
            try:
                with gzip.open(cache_path, "rt", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning("Corrupted local snapshot cache %s: %s", cache_path, e)

    # Perform conditional HTTP GET
    headers = {"User-Agent": "VerityRedTeam-SnapshotFetcher/1.0"}
    if not force_refresh and cache_path.is_file() and etag_path.is_file():
        try:
            etag = etag_path.read_text(encoding="utf-8").strip()
            if etag:
                headers["If-None-Match"] = etag
        except Exception:
            pass

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, context=_create_ssl_context(), timeout=15.0) as resp:
            if resp.status == 304 and cache_path.is_file():
                # Server returned Not Modified; touch cache file
                with contextlib.suppress(Exception):
                    cache_path.touch()
                with gzip.open(cache_path, "rt", encoding="utf-8") as f:
                    return json.load(f)


            content = resp.read()
            etag = resp.headers.get("ETag")

            # Cache persistence is best-effort and must not fail the network fetch
            try:
                if etag:
                    etag_path.write_text(etag.strip(), encoding="utf-8")
                cache_path.write_bytes(content)
            except Exception as write_err:
                logger.warning("Could not persist cache to %s: %s", cache_path, write_err)

            # Decompress directly from in-memory content
            decompressed = gzip.decompress(content)
            data = json.loads(decompressed.decode("utf-8"))
            logger.info(
                "Successfully fetched remote snapshot from %s (%d bytes)",
                url,
                len(content),
            )
            return data
    except urllib.error.HTTPError as he:
        if he.code == 304 and cache_path.is_file():
            logger.debug("HTTP 304 Not Modified for %s, using cached data.", url)
            with gzip.open(cache_path, "rt", encoding="utf-8") as f:
                return json.load(f)
        logger.warning("HTTP error fetching %s: %s", url, he)
    except Exception as exc:
        logger.warning("Failed fetching %s: %s", url, exc)


    # Fallback to expired cache if available
    if cache_path.is_file():
        try:
            with gzip.open(cache_path, "rt", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass

    return None


def fetch_passports_snapshot(
    url: str = PUBLIC_PASSPORTS_URL,
    force_refresh: bool = False,
    local_override_dir: str | Path | None = "data/fingerprints",
) -> dict[str, Any] | None:
    """Fetch passports snapshot from public repo or local directory override."""
    return fetch_remote_snapshot(
        url=url,
        cached_filename="passports.json.gz",
        force_refresh=force_refresh,
    )


def fetch_vulnerabilities_snapshot(
    url: str = PUBLIC_VULNERABILITIES_URL,
    force_refresh: bool = False,
    local_override_dir: str | Path | None = "data/vulnerabilities",
) -> dict[str, Any] | None:
    """Fetch vulnerabilities snapshot from public repo or local directory override."""
    return fetch_remote_snapshot(
        url=url,
        cached_filename="vulnerabilities.json.gz",
        force_refresh=force_refresh,
    )
