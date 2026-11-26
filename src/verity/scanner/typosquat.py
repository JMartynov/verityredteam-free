"""Offline typosquat detection for npm/pypi MCP packages."""

from __future__ import annotations

import logging
from typing import Any

from verity.discovery.models import DiscoveredServerConfig

logger = logging.getLogger("verity.scanner.typosquat")

_LOCAL_PREFIXES = ("/", "./", "../", "~/")
_LOCAL_SUFFIXES = (".py", ".js", ".ts", ".mjs", ".cjs")

_shared_corpus_cache: set[str] | None = None

_RUNNERS: frozenset[str] = frozenset(
    {"npx", "pnpx", "bunx", "uvx", "pipx", "yarn", "pnpm", "bun", "uv"}
)

_RUNNER_SUBCOMMANDS: frozenset[str] = frozenset({"run", "dlx", "exec", "x", "tool"})

_PACKAGE_VALUE_FLAGS: frozenset[str] = frozenset(
    {"-p", "--package", "--from", "--with", "--spec"}
)


def _normalize_runner(command: str | None) -> str:
    """Return the lowercased basename of a runner command without extension."""
    if not command:
        return ""
    name = str(command).strip().replace("\\", "/").rsplit("/", 1)[-1].lower()
    for suffix in (".exe", ".cmd", ".bat"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _package_token(cfg: DiscoveredServerConfig) -> str | None:
    """Return the package argument token from a recognized runner invocation."""
    if _normalize_runner(cfg.command) not in _RUNNERS:
        return None
    tokens = [str(token) for token in cfg.args if str(token)]
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in _PACKAGE_VALUE_FLAGS:
            return tokens[index + 1] if index + 1 < len(tokens) else None
        if token.startswith("-"):
            index += 1
            continue
        if index == 0 and token in _RUNNER_SUBCOMMANDS:
            index += 1
            continue
        return token
    return None


def _is_local_or_url(token: str) -> bool:
    if not token:
        return False
    if "://" in token:
        return True
    if token.startswith(_LOCAL_PREFIXES):
        return True
    return token.lower().endswith(_LOCAL_SUFFIXES)


def _strip_version(pkg: str) -> str:
    if "==" in pkg:
        return pkg.partition("==")[0]
    if pkg.startswith("@"):
        body = pkg[1:]
        if "@" in body:
            return "@" + body.partition("@")[0]
        return pkg
    if "@" in pkg:
        return pkg.partition("@")[0]
    return pkg


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[-1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def _get_shared_corpus() -> set[str]:
    global _shared_corpus_cache
    if _shared_corpus_cache is not None:
        return _shared_corpus_cache

    corpus: set[str] = set()
    try:
        from mcp_vulnerabilities.analyzers.typosquat import get_default_corpus

        corpus.update(get_default_corpus())
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Default typosquat corpus unavailable: %s", exc)

    try:
        from verity.discovery.matcher import HybridDiscoveryMatcher

        matcher = HybridDiscoveryMatcher()
        fast_index = getattr(matcher.matcher, "fast_index", None)
        packages = getattr(fast_index, "packages", None)
        if isinstance(packages, dict):
            corpus.update(packages.keys())
        elif packages is not None:
            corpus.update(packages)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Fingerprint package corpus unavailable: %s", exc)

    _shared_corpus_cache = corpus
    return corpus


class TyposquatDetector:
    """Detects lookalike package names in MCP server launch strings."""

    def __init__(
        self,
        threshold: int = 2,
        corpus: set[str] | None = None,
    ) -> None:
        self.threshold = max(1, min(int(threshold), 3))
        self.corpus: set[str] = set(corpus) if corpus is not None else _get_shared_corpus()

    def scan_configs(self, configs: list[DiscoveredServerConfig]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for cfg in configs:
            finding = self._scan_config(cfg)
            if finding is not None:
                findings.append(finding)
        return findings

    def _scan_config(self, cfg: DiscoveredServerConfig) -> dict[str, Any] | None:
        package_raw = _package_token(cfg)
        if not package_raw or _is_local_or_url(package_raw):
            return None

        package_name = _strip_version(package_raw)
        if not package_name or _is_local_or_url(package_name):
            return None

        # A well-known package launched exactly is never a typosquat.
        if package_name in self.corpus:
            return None

        canonical = self._find_canonical(package_name)
        if canonical is None or canonical == package_name:
            return None

        return {
            "rule_id": "VERITY-TYPOSQUAT-001",
            "scanner": "typosquat",
            "severity": "CRITICAL",
            "cwe_id": "CWE-494",
            "cwe_ids": ["CWE-494"],
            "title": (
                f"Typosquat candidate: '{package_name}' resembles "
                f"'{canonical}'"
            ),
            "message": (
                f"Package '{package_name}' looks like the well-known "
                f"'{canonical}'. Launching a floating runner may install a "
                f"malicious lookalike package."
            ),
            "server_name": cfg.server_name,
            "client_type": cfg.client_type.value,
            "config_path": cfg.config_path,
            "package_name": package_name,
            "matched_package": canonical,
        }

    def _find_canonical(self, package_name: str) -> str | None:
        best: tuple[int, str] | None = None
        limit = self.threshold
        name_len = len(package_name)
        for entry in self.corpus:
            if not entry or entry == package_name:
                continue
            if abs(len(entry) - name_len) > limit:
                continue
            distance = _levenshtein(package_name, entry)
            if distance == 0 or distance > limit:
                continue
            if best is None or distance < best[0] or (
                distance == best[0] and entry < best[1]
            ):
                best = (distance, entry)
        return best[1] if best else None
