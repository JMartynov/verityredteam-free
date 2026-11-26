#!/usr/bin/env python3
"""Generate a deterministic Homebrew formula for ``verity-redteam-core``.

The renderer pulls sdist URLs and SHA-256 digests from the PyPI JSON API,
sorts resources alphabetically, and does not require any third-party
dependencies. It is exercised by
``tests/unit/test_homebrew_formula_generator.py``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
import urllib.request
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Any

ROOT_PACKAGE = "verity-redteam-core"
PYPI_JSON_TEMPLATE = "https://pypi.org/pypi/{package}/{version}/json"
HOMEPAGE = "https://github.com/JMartynov/verityredteam-free"

_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[a-zA-Z0-9._-]*)?$")

PypiFetcher = Callable[[str, str], tuple[str, str]]
DependencyResolver = Callable[[Path], Sequence[tuple[str, str]]]


def validate_version(version: str) -> str:
    """Validate a semver string and return it, raising ``ValueError`` otherwise.

    Accepts ``MAJOR.MINOR.PATCH`` with an optional alphanumeric suffix
    (for example ``0.2.1`` or ``0.2.1rc1``). Anything else is rejected.
    """
    if not isinstance(version, str) or not _VERSION_RE.fullmatch(version):
        raise ValueError(f"Invalid semver version: {version!r}")
    return version


def _normalize(name: str) -> str:
    """Normalize a PEP 503-style distribution name for deterministic matching."""
    return name.strip().lower().replace("_", "-")


def extract_sdist_from_pypi_payload(
    payload: dict, package: str
) -> tuple[str, str]:
    """Return ``(url, sha256)`` for the sdist inside a PyPI JSON payload."""
    if not isinstance(payload, dict):
        raise ValueError(f"Invalid PyPI payload for {package!r}: expected mapping")
    urls = payload.get("urls")
    if not isinstance(urls, list):
        raise ValueError(f"PyPI payload for {package!r} has no 'urls' list")
    for entry in urls:
        if not isinstance(entry, dict):
            continue
        packagetype = entry.get("packagetype")
        url = entry.get("url")
        if not isinstance(url, str) or not url:
            continue
        is_sdist = packagetype == "sdist" or (
            packagetype is None and url.endswith(".tar.gz")
        )
        if not is_sdist:
            continue
        digests = entry.get("digests")
        sha = digests.get("sha256") if isinstance(digests, dict) else None
        if isinstance(sha, str) and sha:
            return url, sha
    raise ValueError(f"No sdist with SHA-256 available for {package!r}")


def fetch_pypi_sdist(
    package_name: str,
    version: str,
    opener: Callable[..., Any] | None = None,
) -> tuple[str, str]:
    """Fetch the sdist URL and SHA-256 digest for ``package_name==version``."""
    url = PYPI_JSON_TEMPLATE.format(package=package_name, version=version)
    open_url = opener or urllib.request.urlopen
    with open_url(url, timeout=15.0) as response:
        payload = json.loads(response.read().decode("utf-8"))
    return extract_sdist_from_pypi_payload(payload, package_name)


def render_homebrew_formula(
    version: str,
    root_sdist_url: str,
    root_sha256: str,
    resources: Iterable[tuple[str, str, str]],
) -> str:
    """Return a deterministic ``Formula/verity.rb`` string."""
    validate_version(version)
    if not isinstance(root_sdist_url, str) or not root_sdist_url:
        raise ValueError("root_sdist_url must be a non-empty string")
    if not isinstance(root_sha256, str) or not root_sha256:
        raise ValueError("root_sha256 must be a non-empty string")

    root_key = _normalize(ROOT_PACKAGE)
    filtered: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for resource in resources:
        if len(resource) != 3:
            raise ValueError("Each resource must be a (name, url, sha256) tuple")
        name, url, sha = resource
        if not all(isinstance(value, str) for value in (name, url, sha)):
            raise ValueError(
                "Each resource must be a (name, url, sha256) tuple of strings"
            )
        key = _normalize(name)
        if key == root_key or key in seen:
            continue
        seen.add(key)
        filtered.append((name, url, sha))

    filtered.sort(key=lambda item: _normalize(item[0]))

    lines: list[str] = [
        "class Verity < Formula",
        "  include Language::Python::Virtualenv",
        "",
        (
            '  desc "Deterministic SAST, DAST, and runtime query guard '
            'for Model Context Protocol (MCP) servers"'
        ),
        f'  homepage "{HOMEPAGE}"',
        f'  url "{root_sdist_url}"',
        f'  sha256 "{root_sha256}"',
        f'  version "{version}"',
        '  license "Apache-2.0"',
        "",
        '  depends_on "libyaml"',
        '  depends_on "python@3.13"',
        "",
    ]

    for name, url, sha in filtered:
        lines.extend(
            [
                f'  resource "{name}" do',
                f'    url "{url}"',
                f'    sha256 "{sha}"',
                "  end",
                "",
            ]
        )

    lines.extend(
        [
            "  def install",
            "    virtualenv_install_with_resources",
            "  end",
            "",
            "  test do",
            '    assert_match version.to_s, shell_output("#{bin}/verity --version")',
            (
                '    assert_match "CWE-89", '
                'shell_output("#{bin}/verity test --demo --format json")'
            ),
            "  end",
            "end",
        ]
    )
    return "\n".join(lines) + "\n"


def _read_project_version(repo_root: Path) -> str:
    pyproject_path = repo_root / "pyproject.toml"
    if not pyproject_path.is_file():
        raise ValueError(f"pyproject.toml not found at {pyproject_path}")
    with pyproject_path.open("rb") as handle:
        data = tomllib.load(handle)
    version = data.get("project", {}).get("version")
    if not isinstance(version, str) or not version:
        raise ValueError("pyproject.toml does not declare project.version")
    return version


def _resolve_runtime_dependencies_from_uv_lock(
    lock_path: Path,
) -> list[tuple[str, str]]:
    with lock_path.open("rb") as handle:
        data = tomllib.load(handle)
    packages = data.get("package")
    if not isinstance(packages, list):
        return []
    by_name: dict[str, dict] = {}
    for entry in packages:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str):
            continue
        by_name[_normalize(name)] = entry

    root_key = _normalize(ROOT_PACKAGE)
    root = by_name.get(root_key)
    if root is None:
        return []

    seen: set[str] = {root_key}
    queue: list[dict] = [
        dep for dep in root.get("dependencies", []) or [] if isinstance(dep, dict)
    ]
    resolved: dict[str, tuple[str, str]] = {}
    while queue:
        dep = queue.pop()
        dep_name = dep.get("name")
        if not isinstance(dep_name, str):
            continue
        key = _normalize(dep_name)
        if key in seen:
            continue
        seen.add(key)
        entry = by_name.get(key)
        if entry is None:
            continue
        version = entry.get("version")
        if isinstance(version, str):
            resolved[key] = (entry["name"], version)
        for child in entry.get("dependencies", []) or []:
            if isinstance(child, dict):
                queue.append(child)

    return sorted(resolved.values(), key=lambda item: _normalize(item[0]))


def _resolve_spec_dependencies(repo_root: Path) -> list[tuple[str, str]]:
    pyproject_path = repo_root / "pyproject.toml"
    if not pyproject_path.is_file():
        return []
    with pyproject_path.open("rb") as handle:
        data = tomllib.load(handle)
    dependencies = data.get("project", {}).get("dependencies", []) or []
    resolved: list[tuple[str, str]] = []
    for spec in dependencies:
        if not isinstance(spec, str):
            continue
        match = re.match(
            r"^(?P<name>[A-Za-z0-9_.\-]+)\s*==\s*(?P<version>\d+\.\d+\.\d+)$",
            spec.strip(),
        )
        if match is None:
            continue
        resolved.append((match.group("name"), match.group("version")))
    return resolved


def resolve_runtime_dependencies(repo_root: Path) -> list[tuple[str, str]]:
    """Return the full transitive runtime closure for ``verity-redteam-core``.

    The closure is derived from ``uv.lock`` (falling back to pinned ``==``
    specs in ``pyproject.toml``). The root ``verity-redteam-core`` package is
    excluded, and only runtime dependencies are walked, so ``dev``/``docs``
    extras never leak into the rendered Homebrew formula.
    """
    root = Path(repo_root)
    lock_path = root / "uv.lock"
    if lock_path.is_file():
        resolved = _resolve_runtime_dependencies_from_uv_lock(lock_path)
        if resolved:
            return resolved
    return _resolve_spec_dependencies(root)


def resolve_lock_sdists(repo_root: Path) -> dict[str, tuple[str, str]]:
    """Return ``{normalized_name: (sdist_url, sha256)}`` read from ``uv.lock``.

    The ``sha256:`` hash prefix used by uv is stripped so the value can be
    embedded directly in a Homebrew ``sha256`` stanza. Packages whose lock
    entry omits an sdist (or a hash) are skipped so callers can fall back to
    the PyPI JSON API.
    """
    lock_path = Path(repo_root) / "uv.lock"
    resolved: dict[str, tuple[str, str]] = {}
    if not lock_path.is_file():
        return resolved
    with lock_path.open("rb") as handle:
        data = tomllib.load(handle)
    for entry in data.get("package", []) or []:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        sdist = entry.get("sdist")
        if not isinstance(name, str) or not isinstance(sdist, dict):
            continue
        url = sdist.get("url")
        digest = sdist.get("hash") or sdist.get("sha256")
        if not isinstance(url, str) or not url or not isinstance(digest, str):
            continue
        sha = digest.split(":", 1)[1] if ":" in digest else digest
        if not sha:
            continue
        resolved[_normalize(name)] = (url, sha)
    return resolved


def generate_formula(
    version: str | None = None,
    repo_root: Path | None = None,
    pypi_fetcher: PypiFetcher | None = None,
    dependency_resolver: DependencyResolver | None = None,
    use_lock_sdist: bool = False,
) -> str:
    """Render the complete Homebrew formula for ``verity-redteam-core``.

    When ``use_lock_sdist`` is true, ``(url, sha256)`` pairs are read from
    ``uv.lock`` first and ``pypi_fetcher`` is only consulted for packages
    whose lock entry omits an sdist.
    """
    root = Path(repo_root) if repo_root is not None else Path.cwd()
    resolved_version = version or _read_project_version(root)
    validate_version(resolved_version)

    fetcher = pypi_fetcher or fetch_pypi_sdist
    resolver = dependency_resolver or resolve_runtime_dependencies
    lock_sdists = resolve_lock_sdists(root) if use_lock_sdist else {}

    def _sdist_for(name: str, dep_version: str) -> tuple[str, str]:
        cached = lock_sdists.get(_normalize(name))
        if cached is not None:
            return cached
        return fetcher(name, dep_version)

    root_url, root_sha = _sdist_for(ROOT_PACKAGE, resolved_version)

    resources: list[tuple[str, str, str]] = []
    for name, dep_version in resolver(root):
        if not isinstance(name, str) or not isinstance(dep_version, str):
            continue
        if _normalize(name) == _normalize(ROOT_PACKAGE):
            continue
        dep_url, dep_sha = _sdist_for(name, dep_version)
        resources.append((name, dep_url, dep_sha))

    return render_homebrew_formula(
        version=resolved_version,
        root_sdist_url=root_url,
        root_sha256=root_sha,
        resources=resources,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="generate_homebrew_formula",
        description="Render Formula/verity.rb for the JMartynov/homebrew-tap.",
    )
    parser.add_argument(
        "--version",
        default=None,
        help="Release semver (defaults to pyproject.toml project.version).",
    )
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Repository root containing pyproject.toml and uv.lock.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write the rendered formula to this path (default: stdout).",
    )
    parser.add_argument(
        "--from-lock",
        action="store_true",
        help="Prefer uv.lock sdist URLs and SHA-256 digests over the PyPI API.",
    )
    args = parser.parse_args(argv)

    try:
        formula = generate_formula(
            version=args.version,
            repo_root=Path(args.repo_root),
            use_lock_sdist=args.from_lock,
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(formula, encoding="utf-8")
    else:
        sys.stdout.write(formula)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
