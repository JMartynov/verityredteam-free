# M20: Add `README.md` Hero Badge Row (PyPI, License, Python 3.12+, CI) & Parity Guard

- **Task ID**: `M20`
- **Priority**: `P2` (Master Rank `#9`, Track B — Simple Fixes, Docs & CI Hygiene)
- **Status**: `Done`
- **Dependencies**: `M10`, `M11`
- **Target Repository**: `/Users/ivan/Project/3t.tools.intellij/verityredteam-free` (`verity-redteam-core`)
- **GitHub Project #5**: [Verity RedTeam Free Task Board](https://github.com/users/JMartynov/projects/5)

---

## 1. Context & Problem Statement

`README.md` opens with the H1 title and a one-line tagline but carries **no hero badge row**.
A visitor landing on PyPI or GitHub cannot tell at a glance:

- the published distribution name (`verity-redteam-core`) and current version,
- the supported Python floor (`3.12+`, already pinned in `pyproject.toml` `requires-python`),
- the license (`Apache-2.0`, already shipped as `LICENSE`),
- whether CI is green (`ci.yml`).

`tests/unit/test_documentation_parity.py` already guards CLI fidelity, relative links,
the demo asset, and stale `verity-core` package references, but it has **no assertion that a
badge row exists**, so a regression (a dropped badge, a badge pointing at a retired project
URL, or a badge block drifting below the hero fold) can land unnoticed. Result: the hero
block is unverified documentation surface, and wheel metadata (`Requires-Python`, `License`,
`Name`) is never cross-checked against what the README advertises.

---

## 2. Requirements & Target Files

1. **Hero badge row (`README.md` lines 1–8)**: insert a single badge row immediately beneath
   the H1 title and above the tagline, per M10 spec §2.1, keeping the hero block inside
   `README.md` lines 1–8. Exactly four badges, one per line, in this order:

   ```markdown
   [![PyPI](https://img.shields.io/pypi/v/verity-redteam-core.svg)](https://pypi.org/project/verity-redteam-core/)
   [![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://pypi.org/project/verity-redteam-core/)
   [![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
   [![CI](https://github.com/JMartynov/verityredteam-free/actions/workflows/ci.yml/badge.svg)](https://github.com/JMartynov/verityredteam-free/actions/workflows/ci.yml)
   ```

2. **Valid targets only**: every badge target must resolve —
   - PyPI/Python badges point at `https://pypi.org/project/verity-redteam-core/`,
   - License badge points at the relative `LICENSE` file (already covered by
     `test_relative_links_and_media_resolve`),
   - CI badge points at the existing `.github/workflows/ci.yml` and its
     `actions/workflows/ci.yml` URL.
3. **No stale package links**: zero `\bverity-core\b` occurrences anywhere in the hero block
   (reuse `_STALE_PACKAGE_RE`); retired `verity-core` URLs must not be introduced.
4. **Parity guard**: add `test_readme_hero_badges_present_and_valid` to
   `tests/unit/test_documentation_parity.py`, built on the existing `README_PATH`,
   `_LINK_RE`, and `_STALE_PACKAGE_RE` helpers — no new dependencies.
5. **Metadata consistency**: badge claims must match packaged wheel metadata (`Name`,
   `Requires-Python`, `License`) — the README must not advertise a Python floor, license, or
   distribution name the wheel does not declare.

---

## 3. Automated Tests to Verify (`tests/unit/test_documentation_parity.py`)

`test_readme_hero_badges_present_and_valid` must assert, over the first 8 lines of
`README.md` (`hero = text.splitlines()[:8]`) and with a parametrized `_HERO_BADGES`
mapping:

1. All four badge images are present in the hero block:
   `img.shields.io/pypi/v/verity-redteam-core.svg`,
   `img.shields.io/badge/python-3.12%2B-blue.svg`,
   `img.shields.io/badge/License-Apache_2.0-blue.svg`,
   `actions/workflows/ci.yml/badge.svg` (parametrized — one case per badge).
2. All four targets are present and valid: the PyPI project URL
   `https://pypi.org/project/verity-redteam-core/`, the relative `LICENSE` target, and the
   `.../actions/workflows/ci.yml` URL; relative targets resolve on disk via
   `(REPO_ROOT / target).is_file()`.
3. Ordering/location: the badge lines appear after the `# ` H1 line and before the tagline
   line, and every badge line matches `_LINK_RE` (image form `![[...](img)](target)`).
4. `_STALE_PACKAGE_RE.search(hero_text)` is `None` — zero stale `verity-core` references.
5. `(REPO_ROOT / ".github" / "workflows" / "ci.yml").is_file()` — the CI badge target
   exists in-tree.
6. Existing guard `test_no_stale_package_references` still passes unchanged.

---

## 4. Acceptance Scenario in Clean Container with Packaged Wheel Metadata

Extend `tests/e2e_containers/verify_all_scenarios.sh` with a documentation-metadata
scenario (or a new `docs-metadata` step in `run_e2e.sh`) that runs against the **packaged
wheel**, not the source tree:

1. Build and install the wheel exactly as the suite does today
   (`INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh`), then copy `README.md` into
   the container image so the shipped doc is asserted.
2. Extract wheel metadata and compare it with the README badges:

   ```bash
   python -c "from importlib.metadata import metadata; m = metadata('verity-redteam-core'); print(m['Name'], m['Version'], m['Requires-Python'], m['License'])"
   ```

3. **Assertions**:
   - `Name` is `verity-redteam-core` and the hero PyPI badge image URL contains that exact
     normalized name.
   - `Requires-Python` (e.g. `>=3.12`) is consistent with the `python-3.12%2B` badge.
   - `License` is `Apache-2.0` and the hero license badge image contains
     `License-Apache_2.0` and links to an existing `LICENSE` file.
   - `.github/workflows/ci.yml` exists in the checked-out tree and the CI badge URL matches
     its path.
   - `grep -rn "verity-core" README.md` returns no matches (no stale package links).
   - Full `INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh` passes.

---

## 5. Verification Commands

```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
uv run ruff check src tests
uv run pytest tests/unit/test_documentation_parity.py -v
uv run pytest tests/
INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh
```

---

## 6. Acceptance Criteria

- [ ] `README.md` lines 1–8 contain the four-badge hero row (PyPI `verity-redteam-core`,
      Python `3.12+`, License `Apache-2.0`, CI `ci.yml`) beneath the H1 and above the tagline.
- [ ] Every badge target resolves (PyPI project URL, relative `LICENSE`, `ci.yml` workflow
      URL) and the hero block contains zero stale `verity-core` references.
- [ ] `test_readme_hero_badges_present_and_valid` passes and asserts all four badges, their
      targets, ordering, and the no-stale-link guard.
- [ ] Packaged wheel metadata (`Name`, `Requires-Python`, `License`) matches the advertised
      badge claims in the container E2E run.
- [ ] `uv run pytest tests/`, `uv run ruff check src tests`, and
      `INSTALL_SOURCE=wheel ./tests/e2e_containers/run_e2e.sh` pass cleanly.
