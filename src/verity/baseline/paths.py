"""Path resolution and canonicalization helpers for Verity baselines."""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path


def _nearest_git_root(start: Path) -> Path | None:
    try:
        current = start if start.is_dir() else start.parent
    except OSError:
        current = start.parent
    for candidate in (current, *current.parents):
        try:
            if (candidate / ".git").exists():
                return candidate
        except OSError:
            continue
    return None


def _target_base(paths: list[Path]) -> Path:
    resolved = [p.resolve() for p in paths]
    directories = [p if p.is_dir() else p.parent for p in resolved]
    if len(directories) == 1:
        return directories[0]
    return Path(os.path.commonpath([str(d) for d in directories]))


def resolve_project_root(
    target_paths: Iterable[str | Path] | None = None,
    explicit_root: str | Path | None = None,
    cwd: str | Path | None = None,
) -> Path:
    """Resolve the project root.

    Precedence: explicit root > nearest ``.git`` ancestor (from targets when
    provided, otherwise from cwd) > target directory/common parent > cwd.
    """
    cwd_path = Path(cwd) if cwd is not None else Path.cwd()

    if explicit_root is not None:
        return Path(explicit_root).resolve()

    if target_paths is not None:
        if isinstance(target_paths, (str, Path)):
            targets = [Path(target_paths)]
        else:
            targets = [Path(p) for p in target_paths]
        if targets:
            git_roots = [g for g in (_nearest_git_root(t) for t in targets) if g is not None]
            if git_roots:
                return max(git_roots, key=lambda p: len(p.parts)).resolve()
            return _target_base(targets).resolve()

    git_root = _nearest_git_root(cwd_path)
    if git_root is not None:
        return git_root.resolve()
    return cwd_path.resolve()


def canonicalize_path(
    file_path: str | Path,
    project_root: Path | None = None,
    home_dir: Path | None = None,
) -> str:
    """Normalize a path to a stable POSIX representation.

    Repo-relative when inside ``project_root``, ``~``-relative when inside the
    user's home directory, otherwise a plain POSIX string.
    """
    raw = str(file_path)
    if raw.startswith("~"):
        return raw.replace("\\", "/")

    normalized = raw.replace("\\", "/")
    path = Path(file_path)

    if not path.is_absolute():
        while normalized.startswith("./"):
            normalized = normalized[2:]
        return normalized or "."

    try:
        resolved = path.resolve()
    except OSError:
        resolved = path

    if project_root is not None:
        try:
            rel = resolved.relative_to(Path(project_root).resolve())
            return rel.as_posix()
        except (ValueError, OSError):
            pass

    home = Path(home_dir) if home_dir is not None else Path.home()
    try:
        rel_home = resolved.relative_to(home.resolve())
        rel_str = rel_home.as_posix()
        return "~" if rel_str in ("", ".") else f"~/{rel_str}"
    except (ValueError, OSError):
        pass

    return resolved.as_posix()
