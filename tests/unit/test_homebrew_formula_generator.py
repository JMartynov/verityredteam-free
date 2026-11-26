"""Unit tests for scripts/generate_homebrew_formula.py."""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GENERATOR_PATH = REPO_ROOT / "scripts" / "generate_homebrew_formula.py"


def _load_generator() -> ModuleType:
    if not GENERATOR_PATH.is_file():
        pytest.fail(f"Missing Homebrew formula generator script: {GENERATOR_PATH}")
    spec = importlib.util.spec_from_file_location("generate_homebrew_formula", GENERATOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generate_formula_deterministic_with_sorted_resources(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """AC-30.3: Renders deterministic Formula/verity.rb with sorted resources."""
    mod = _load_generator()

    rendered = mod.render_homebrew_formula(
        version="0.2.1",
        root_sdist_url="https://files.pythonhosted.org/packages/source/v/verity_redteam_core/verity_redteam_core-0.2.1.tar.gz",
        root_sha256="a" * 64,
        resources=[
            ("sqlglot", "https://files.pythonhosted.org/sqlglot-30.0.3.tar.gz", "b" * 64),
            ("click", "https://files.pythonhosted.org/click-8.3.1.tar.gz", "c" * 64),
            (
                "verity-redteam-core",
                "https://files.pythonhosted.org/verity_redteam_core-0.2.1.tar.gz",
                "a" * 64,
            ),
        ],
    )

    assert "class Verity < Formula" in rendered
    assert "include Language::Python::Virtualenv" in rendered
    assert 'depends_on "libyaml"' in rendered
    assert 'depends_on "python@3.13"' in rendered
    assert 'license "Apache-2.0"' in rendered
    assert "virtualenv_install_with_resources" in rendered
    assert "test do" in rendered
    assert 'assert_match version.to_s, shell_output("#{bin}/verity --version")' in rendered
    assert (
        'assert_match "CWE-89", shell_output("#{bin}/verity test --demo --format json")'
        in rendered
    )
    assert 'resource "verity-redteam-core"' not in rendered

    click_pos = rendered.index('resource "click" do')
    sqlglot_pos = rendered.index('resource "sqlglot" do')
    assert click_pos < sqlglot_pos

    # Also verify generate_formula() with custom pypi_fetcher / mocked urlopen + resolver
    payloads: dict[tuple[str, str], dict[str, Any]] = {
        ("verity-redteam-core", "0.2.1"): {
            "urls": [
                {
                    "packagetype": "sdist",
                    "url": "https://files.pythonhosted.org/packages/source/v/verity_redteam_core/verity_redteam_core-0.2.1.tar.gz",
                    "digests": {"sha256": "a" * 64},
                }
            ]
        },
        ("sqlglot", "30.0.3"): {
            "urls": [
                {
                    "packagetype": "sdist",
                    "url": "https://files.pythonhosted.org/sqlglot-30.0.3.tar.gz",
                    "digests": {"sha256": "b" * 64},
                }
            ]
        },
        ("click", "8.3.1"): {
            "urls": [
                {
                    "packagetype": "sdist",
                    "url": "https://files.pythonhosted.org/click-8.3.1.tar.gz",
                    "digests": {"sha256": "c" * 64},
                }
            ]
        },
    }

    def fake_urlopen(req: Any, timeout: float = 15.0) -> io.BytesIO:
        url = req if isinstance(req, str) else req.full_url
        for (pkg, ver), data in payloads.items():
            if f"/{pkg}/{ver}/json" in url:
                return io.BytesIO(json.dumps(data).encode("utf-8"))
        raise ValueError(f"Unexpected URL: {url}")

    monkeypatch.setattr(mod.urllib.request, "urlopen", fake_urlopen)

    generated = mod.generate_formula(
        version="0.2.1",
        repo_root=tmp_path,
        pypi_fetcher=lambda pkg, ver: mod.fetch_pypi_sdist(pkg, ver),
        dependency_resolver=lambda _root: [("sqlglot", "30.0.3"), ("click", "8.3.1")],
    )
    assert generated == rendered


def test_generate_formula_rejects_missing_sdist_or_invalid_version() -> None:
    """Negative control: invalid version strings and payloads without sdist fail cleanly."""
    mod = _load_generator()

    for bad_version in ("", "not-a-semver", "1.2"):
        with pytest.raises(ValueError):
            mod.render_homebrew_formula(
                version=bad_version,
                root_sdist_url="https://files.pythonhosted.org/verity_redteam_core-0.2.1.tar.gz",
                root_sha256="a" * 64,
                resources=[],
            )

    with pytest.raises(ValueError):
        mod.extract_sdist_from_pypi_payload(
            {
                "urls": [
                    {
                        "packagetype": "bdist_wheel",
                        "url": "https://files.pythonhosted.org/verity_redteam_core-0.2.1-py3-none-any.whl",
                        "digests": {"sha256": "d" * 64},
                    }
                ]
            },
            "verity-redteam-core",
        )

    assert mod.main(["--version", "not-a-semver"]) != 0
