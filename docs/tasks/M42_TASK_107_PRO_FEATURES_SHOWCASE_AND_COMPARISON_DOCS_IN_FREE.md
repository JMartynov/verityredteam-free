---
task_id: M42
alias: TASK-107
title: "Pro Features Showcase & Comparison Docs in Free"
status: Done
priority: P0
size: S
estimate_days: 2
board:
  project_number: 5
  item_id: PVTI_lAHOD-xmQM4Br351zhLvmsE
target_repos: [verityredteam-free]
---


## Context & Objectives

A Free customer needs to understand exactly what the commercial edition adds, without
being misled and without the Free package shipping Pro implementations. This task
delivered a dedicated Pro showcase page inside the Free documentation, with a
one-to-one Free-vs-Pro matrix, usage-only examples, and an explicit graceful
degradation contract.

## Scope

| File | Change |
| --- | --- |
| `docs/pro/enterprise_features.md` | Dedicated Pro showcase page |
| `docs/index.md` | Single link to the Pro showcase, after Tier 2 |
| `mkdocs.yml` | `Verity Pro:` nav entry |
| `tests/unit/test_docs_pro_features_showcase.py` | Structure, matrix, snippet, and no-vendoring tests |

## Contract

### Page structure

The page has exactly one H1, `Verity Pro Enterprise Features`, followed by these eight
H2 sections in this order:

1. `Overview`
2. `Free vs. Pro Feature Comparison`
3. `Database Guards`
4. `Compliance & SARIF Reporting`
5. `Agent-Native MCP Server Actions`
6. `Remediation`
7. `Adversarial Verification & Red-Teaming`
8. `Graceful Degradation (PRO_FEATURE_REQUIRED)`

### Comparison matrix

A four-domain matrix with the header
`| Capability Domain | Verity RedTeam Free (Apache-2.0) | Verity RedTeam Pro (Commercial) |`
covers: Database AST Guarding, Reporting & CI/CD Formats, Agent-Native MCP Server
(verity serve), and Adversarial Verification & Red-Teaming. Every Pro cell carries the
`[Pro]` badge, and the section states `PRO_FEATURE_REQUIRED` and exit code `2`.

### Feature subsections

Six H3 subsections exist: `SnowflakeSecurityGuard`, `FilterSecurityGuard`,
`VolumePolicyGuard`, `OASIS SARIF v2.1.0 & Compliance Bundles`,
`Pro verity_remediation_ops`, and `Multi-Turn Socratic Red-Teaming`. Each contains a
Python usage-only snippet (no Pro class definition), a CLI or JSON snippet, and a
Mermaid diagram.

### Graceful degradation

The final section documents the single structured error shape, exit code `2`, the
no-partial-write guarantee, the no-unhandled-traceback guarantee, live MCP behaviour,
and that installing `verity-pro` is the only unlock.

### Integration

`docs/index.md` links to `pro/enterprise_features.md` exactly once, after the Tier 2
section, and `mkdocs.yml` registers the page under `Verity Pro:`.

## ATDD Traceability Matrix

| Acceptance Criterion | Test Level | Target File / Function | Description | Status |
| --- | --- | --- | --- | --- |
| AC-42.1 | unit | `tests/unit/test_docs_pro_features_showcase.py::test_page_structure_and_nav` | Exact H1, ordered H2s, single homepage link, `Verity Pro:` nav entry. | Done |
| AC-42.2 | unit | `tests/unit/test_docs_pro_features_showcase.py::test_free_vs_pro_matrix` | Four-domain matrix with `[Pro]` badges and exit code `2` note. | Done |
| AC-42.3 | unit | `tests/unit/test_docs_pro_features_showcase.py::test_pro_feature_sections` | Each of six H3s has Python, CLI/JSON, and Mermaid blocks. | Done |
| AC-42.4 | unit | `tests/unit/test_docs_pro_features_showcase.py::test_graceful_degradation_documented` | Structured error, exit code `2`, no partial write, no traceback, `verity-pro` unlock. | Done |
| AC-42.5 | unit | `tests/unit/test_docs_pro_features_showcase.py::test_no_vendored_pro_implementations` | Python snippets parse and never define Pro guard classes. | Done |
| AC-42.6 | static | `uv run ruff check src tests` | Zero lint findings. | Done |

## Verification Evidence

~~~bash
uv run pytest tests/unit/test_docs_pro_features_showcase.py -q
uv run ruff check src tests
~~~

Both commands passed on the delivered branch.

## Delivery Checklist

- [x] `docs/pro/enterprise_features.md` created with the exact H1.
- [x] Eight H2 sections present and correctly ordered.
- [x] Four-domain Free-vs-Pro matrix with `[Pro]` badges.
- [x] Six H3 feature subsections with Python, CLI/JSON, and Mermaid blocks.
- [x] Python snippets are usage-only; no Pro class definitions.
- [x] Graceful degradation contract documented.
- [x] Single homepage link plus `Verity Pro:` nav entry.
- [x] Paired controls committed; lint clean.
