"""Ignore-file handling, policy config, and suppression application for Verity baselines."""

from __future__ import annotations

import fnmatch
import re
import tomllib
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

DEFAULT_IGNORE_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        "dist",
        "build",
        ".eggs",
        ".worktrees",
        ".aider-sessions",
    }
)


class PolicyValidationError(ValueError):
    """Raised when a Verity policy configuration is invalid."""


@dataclass
class IgnoreRule:
    """A single ``[[ignore]]`` entry from ``verity.toml``."""

    id: str = ""
    paths: list[str] = field(default_factory=list)
    servers: list[str] = field(default_factory=list)
    fingerprint: str | None = None
    reason: str = ""
    expires: date | None = None
    active: bool = True


@dataclass
class AllowlistRule:
    """A single ``[[allowlists]]`` entry from ``verity.toml``."""

    description: str = ""
    paths: list[str] = field(default_factory=list)
    servers: list[str] = field(default_factory=list)
    stopwords: list[str] = field(default_factory=list)
    regexes: list[str] = field(default_factory=list)
    regex_target: str = "match"


@dataclass
class PolicyConfig:
    """Parsed Verity policy configuration."""

    scan: dict[str, Any] = field(default_factory=dict)
    ignores: list[IgnoreRule] = field(default_factory=list)
    allowlists: list[AllowlistRule] = field(default_factory=list)
    expired_warnings: list[str] = field(default_factory=list)


class IgnoreMatcher:
    """Evaluate gitignore-style patterns with ordered negation and default ignores."""

    def __init__(
        self,
        project_root: Path,
        rules: list[tuple[str, bool]],
        default_dirs: frozenset[str] = frozenset(),
    ) -> None:
        self.project_root = Path(project_root).resolve()
        self._rules = list(rules)
        self._default_dirs = frozenset(default_dirs)

    def _relative(self, path: str | Path) -> str:
        p = Path(path)
        try:
            if p.is_absolute():
                resolved = p.resolve()
                try:
                    return resolved.relative_to(self.project_root).as_posix()
                except ValueError:
                    return resolved.as_posix()
        except OSError:
            pass
        normalized = p.as_posix()
        while normalized.startswith("./"):
            normalized = normalized[2:]
        return normalized

    def _match_default(self, parts: list[str], is_dir: bool | None) -> bool:
        if not self._default_dirs:
            return False
        dir_parts = parts if is_dir else parts[:-1]
        return any(part in self._default_dirs for part in dir_parts)

    def _match_pattern(self, rel: str, parts: list[str], pattern: str) -> bool:
        pat = pattern.strip()
        if not pat:
            return False

        dir_only = pat.endswith("/")
        if dir_only:
            pat = pat.rstrip("/")
            if "/" not in pat:
                if any(part == pat for part in parts):
                    return True
                return rel == pat or rel.startswith(pat + "/")
            return (
                rel == pat
                or rel.startswith(pat + "/")
                or _glob_match(rel, pat + "/**")
                or _glob_match(rel, "**/" + pat + "/**")
            )

        if _glob_match(rel, pat):
            return True
        if "/" not in pat:
            return any(fnmatch.fnmatch(part, pat) for part in parts)
        return False

    def is_ignored(self, path: str | Path, is_dir: bool | None = None) -> bool:
        """Return True when the path should be ignored."""
        rel = self._relative(path)
        parts = [part for part in rel.split("/") if part not in ("", ".")]
        ignored = self._match_default(parts, is_dir)
        for pattern, negate in self._rules:
            if self._match_pattern(rel, parts, pattern):
                ignored = not negate
        return ignored

    def matches_ignore_rules(self, path: str | Path, is_dir: bool | None = None) -> bool:
        """Return True when the path is ignored solely by explicit ignore-file rules."""
        rel = self._relative(path)
        parts = [part for part in rel.split("/") if part not in ("", ".")]
        ignored = False
        for pattern, negate in self._rules:
            if self._match_pattern(rel, parts, pattern):
                ignored = not negate
        return ignored

    def matches_ignore_file(self, path: str | Path) -> bool:
        """Return True when the path is matched by any ignore rule."""
        return self.is_ignored(path)


def _load_ignore_file(
    root: Path,
    file_path: Path,
    rules: list[tuple[str, bool]],
    visited: set[Path],
) -> None:
    try:
        resolved = file_path.resolve()
    except OSError:
        return
    try:
        resolved.relative_to(root)
    except ValueError:
        return
    if resolved in visited:
        return
    visited.add(resolved)
    try:
        lines = resolved.read_text(encoding="utf-8").splitlines()
    except OSError:
        return

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(":include"):
            parts = line.split(None, 1)
            if len(parts) == 2:
                _load_ignore_file(
                    root, resolved.parent / parts[1].strip(), rules, visited
                )
            continue
        negate = False
        if line.startswith("!"):
            negate = True
            line = line[1:].strip()
            if not line:
                continue
        rules.append((line, negate))


def load_ignore_spec(
    project_root: Path,
    ignore_file: str | Path | None = None,
    *,
    use_default_ignores: bool = True,
) -> IgnoreMatcher:
    """Load an ignore matcher from ``.verityignore``/``.gitignore`` and configured defaults."""
    root = Path(project_root).resolve()
    rules: list[tuple[str, bool]] = []
    default_dirs = DEFAULT_IGNORE_DIRS if use_default_ignores else frozenset()

    if ignore_file is not None:
        target = Path(ignore_file)
        if not target.is_absolute():
            target = root / target
        _load_ignore_file(root, target, rules, set())
    elif use_default_ignores:
        auto = root / ".verityignore"
        if auto.is_file():
            _load_ignore_file(root, auto, rules, set())

    return IgnoreMatcher(root, rules, default_dirs)


def _parse_date(value: Any) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(str(value))
    except (ValueError, TypeError):
        return None


def load_policy_config(
    project_root: Path,
    config_path: str | Path | None = None,
    *,
    strict_policy: bool = False,
    today: date | None = None,
) -> PolicyConfig:
    """Parse ``verity.toml`` policy configuration."""
    root = Path(project_root)
    path = Path(config_path) if config_path is not None else root / "verity.toml"
    policy = PolicyConfig()
    if not path.is_file():
        if config_path is not None:
            raise FileNotFoundError(f"Policy config not found: {config_path}")
        return policy

    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise PolicyValidationError(f"Invalid policy TOML '{path}': {exc}") from exc

    scan = data.get("scan")
    if isinstance(scan, dict):
        policy.scan = scan

    current = today or date.today()

    for raw in data.get("ignore", []) or []:
        if not isinstance(raw, dict):
            continue
        reason = str(raw.get("reason") or "").strip()
        if strict_policy and not reason:
            raise PolicyValidationError("[[ignore]] rule requires a non-empty reason")
        expires = _parse_date(raw.get("expires"))
        active = True
        if expires is not None and expires < current:
            active = False
            rule_id = raw.get("id", "")
            policy.expired_warnings.append(
                f"Ignore rule '{rule_id}' expired on {expires.isoformat()}"
            )
        policy.ignores.append(
            IgnoreRule(
                id=str(raw.get("id") or ""),
                paths=[str(p) for p in (raw.get("paths") or [])],
                servers=[str(s) for s in (raw.get("servers") or [])],
                fingerprint=raw.get("fingerprint"),
                reason=reason,
                expires=expires,
                active=active,
            )
        )

    for raw in data.get("allowlists", []) or []:
        if not isinstance(raw, dict):
            continue
        description = str(raw.get("description") or raw.get("reason") or "").strip()
        if strict_policy and not description:
            raise PolicyValidationError(
                "[[allowlists]] entry requires a non-empty description"
            )
        policy.allowlists.append(
            AllowlistRule(
                description=description,
                paths=[str(p) for p in (raw.get("paths") or [])],
                servers=[str(s) for s in (raw.get("servers") or [])],
                stopwords=[str(s) for s in (raw.get("stopwords") or [])],
                regexes=[str(s) for s in (raw.get("regexes") or [])],
                regex_target=str(raw.get("regex_target") or "match"),
            )
        )

    return policy


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    pat = str(pattern).replace("\\", "/").lstrip("/")
    out: list[str] = ["^"]
    idx = 0
    length = len(pat)
    while idx < length:
        if pat.startswith("**/", idx):
            out.append("(?:.*/)?")
            idx += 3
        elif pat.startswith("**", idx):
            out.append(".*")
            idx += 2
        elif pat[idx] == "*":
            out.append("[^/]*")
            idx += 1
        elif pat[idx] == "?":
            out.append("[^/]")
            idx += 1
        else:
            out.append(re.escape(pat[idx]))
            idx += 1
    out.append("$")
    return re.compile("".join(out))


def _glob_match(text: str, pattern: str) -> bool:
    pat = str(pattern).replace("\\", "/")
    if "**" in pat:
        return bool(_glob_to_regex(pat).match(text))
    if fnmatch.fnmatch(text, pat):
        return True
    if "/" not in pat:
        return fnmatch.fnmatch(Path(text).name, pat)
    return False


def _path_matches(globs: list[str], file_path: str) -> bool:
    if not globs:
        return True
    rel = str(file_path or "").replace("\\", "/")
    return any(_glob_match(rel, glob) for glob in globs)


def _candidate_ids(finding: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    for key in ("rule_id", "cwe_id", "advisory_id", "cve_id"):
        value = finding.get(key)
        if value:
            ids.add(str(value))
    aliases = finding.get("aliases")
    if isinstance(aliases, (list, tuple)):
        ids.update(str(alias) for alias in aliases)
    rule_id = str(finding.get("rule_id") or "")
    if rule_id.startswith("VULN-"):
        ids.add(rule_id[len("VULN-") :])
    return ids


def _ignore_matches(rule: IgnoreRule, finding: dict[str, Any]) -> bool:
    if rule.id and rule.id not in _candidate_ids(finding):
        return False
    if not _path_matches(rule.paths, str(finding.get("file_path") or "")):
        return False
    if rule.servers and str(finding.get("server_name") or "") not in rule.servers:
        return False
    return not (
        rule.fingerprint and str(finding.get("fingerprint") or "") != rule.fingerprint
    )


def _regex_target_text(
    target: str,
    finding: dict[str, Any],
    source_lines_cache: dict[str, list[str]] | None,
    default_text: str,
) -> str:
    if target == "secret":
        return str(finding.get("_raw_secret") or finding.get("raw_secret_value") or "")
    if target == "line" and source_lines_cache:
        file_path = finding.get("file_path")
        line_number = finding.get("line_number")
        if (
            file_path in source_lines_cache
            and isinstance(line_number, int)
            and not isinstance(line_number, bool)
            and 1 <= line_number <= len(source_lines_cache[file_path])
        ):
            return source_lines_cache[file_path][line_number - 1]
    return default_text


def _allowlist_matches(
    rule: AllowlistRule,
    finding: dict[str, Any],
    source_lines_cache: dict[str, list[str]] | None,
) -> bool:
    if rule.servers and str(finding.get("server_name") or "") not in rule.servers:
        return False
    file_path = str(finding.get("file_path") or "")
    if rule.paths and not _path_matches(rule.paths, file_path):
        return False

    text_parts = [
        str(finding.get(key) or "")
        for key in ("snippet", "matched_snippet", "message", "match", "line")
    ]
    text = "\n".join(part for part in text_parts if part)

    matched = False
    lowered_text = text.lower()
    for stopword in rule.stopwords:
        if stopword and stopword.lower() in lowered_text:
            matched = True
            break

    if not matched:
        for regex in rule.regexes:
            target = _regex_target_text(
                rule.regex_target, finding, source_lines_cache, text
            )
            try:
                if re.search(regex, target):
                    matched = True
                    break
            except re.error:
                continue

    return not (not matched and (rule.stopwords or rule.regexes))


def apply_policy_suppressions(
    findings: list[dict[str, Any]],
    policy: PolicyConfig,
    *,
    source_lines_cache: dict[str, list[str]] | None = None,
) -> list[dict[str, Any]]:
    """Apply policy ``[[ignore]]`` and ``[[allowlists]]`` suppressions to findings."""
    for finding in findings:
        if "suppression" in finding:
            continue

        for rule in policy.ignores:
            if not rule.active:
                continue
            if _ignore_matches(rule, finding):
                finding["suppression"] = {
                    "kind": "external",
                    "source": "policy",
                    "reason": rule.reason,
                    "id": rule.id,
                    "expires": rule.expires.isoformat() if rule.expires else None,
                }
                break
        if "suppression" in finding:
            continue

        for allow in policy.allowlists:
            if _allowlist_matches(allow, finding, source_lines_cache):
                finding["suppression"] = {
                    "kind": "external",
                    "source": "policy",
                    "reason": allow.description,
                }
                break

    return findings
