---
task_id: M40
alias: TASK-103-FREE
title: "Free CLI SARIF Pro Gate & Line Precision"
status: Done
priority: P0
size: XS
estimate_days: 1
board:
  project_number: 5
  item_id: PVTI_lAHOD-xmQM4Br351zhLvmAQ
target_repos: [verityredteam-free]
---


## Context & Objectives

`--format sarif` is a Verity Pro capability, but the Free CLI must describe that
boundary honestly and deterministically. Two properties matter to a CI customer:

1. A Free installation asked for SARIF never writes a partial or empty artifact; it
   returns the structured `PRO_FEATURE_REQUIRED` error and exit code `2`.
2. When `verity-pro` is installed, the exported SARIF preserves the real source line
   and the real file path instead of collapsing every result to `startLine: 1`.

This task hardens the Free CLI gate and the line-number propagation only.

## Scope

| File | Change |
| --- | --- |
| `src/verity/cli.py` | Pro-plugin gate for `--format sarif` and real line/path propagation |
| `tests/unit/cli/test_sarif_pro_gate.py` | Gate and paired Pro-present control |
| `tests/unit/cli/test_sarif_line_precision.py` | Line propagation and `startLine == 1` fallback |

Out of scope: any reporting engine internals outside the Free CLI surface.

## Contract

### Pro-only gate

- `_pro_plugin_available()` remains the single source of truth for edition detection.
- When the `verity-pro` plugin is absent and `--format sarif` is requested, the CLI
  must emit the structured `PRO_FEATURE_REQUIRED` payload and return exit code `2`.
- No output file is created or truncated when the gate fires, even if `--output` was
  supplied.
- No unhandled traceback escapes; the failure is the structured error only.

### Line and path precision

When the plugin is present, every SARIF result must carry:

- `physicalLocation.artifactLocation.uri` set to the real `file_path` from the finding.
- `physicalLocation.region.startLine` set to
  `finding.get('line_number') or finding.get('line') or 1`.

A finding without a usable location must degrade to `startLine == 1` rather than
omitting the region or crashing.

## ATDD Traceability Matrix

| Acceptance Criterion | Test Level | Target File / Function | Description | Status |
| --- | --- | --- | --- | --- |
| AC-40.1 | unit | `tests/unit/cli/test_sarif_pro_gate.py::test_sarif_requires_pro_plugin` | Free emits `PRO_FEATURE_REQUIRED`, exit code `2`, and writes no artifact; paired Pro-present control exports successfully. | Done |
| AC-40.2 | unit | `tests/unit/cli/test_sarif_line_precision.py::test_sarif_preserves_line` | Real source line survives export; missing location falls back to `startLine == 1`. | Done |
| AC-40.3 | static | `uv run ruff check src tests` | Zero lint findings. | Done |

## Validation Commands

~~~bash
uv run pytest tests/unit/cli/test_sarif_pro_gate.py tests/unit/cli/test_sarif_line_precision.py -q
uv run ruff check src tests
~~~

## Delivery Checklist

- [x] `--format sarif` returns `PRO_FEATURE_REQUIRED` with exit code `2` when the plugin is absent.
- [x] Gate writes no output file, including when `--output` is supplied.
- [x] SARIF `region.startLine` uses the real finding line.
- [x] SARIF `artifactLocation.uri` uses the real finding file path.
- [x] Missing-location fallback yields `startLine == 1`.
- [x] Paired test files committed and `uv run ruff check src tests` clean.
