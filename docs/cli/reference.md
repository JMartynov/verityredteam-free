# CLI Reference

Complete reference for the `verity` command line: options, exit codes, environment variables, output formats, and CI integration.

## Command tree

~~~text
verity
├── scan    static audit of MCP/LLM configs and source trees
├── test    isolated payload tests for CWE-89/639/943/94
└── serve   expose the scanner over a transport
~~~

## Global conventions

- Long options only. Both `--flag=value` and `--flag value` are accepted.
- `--format` accepts `terminal`, `json`, `markdown`, `html`, or `sarif`.
- `terminal` is the default when stdout is a TTY; `json` is the default when piped.
- Color is enabled only when stderr is a TTY and `NO_COLOR` is unset.
- Reports go to stdout (or `--output`); diagnostics and progress go to stderr.
- Every command supports `--help`; `--version` prints `verity <semver>`.
- Repeated scans and tests are deterministic: the same input produces the same fingerprints.

### Global options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `--help` | flag | — | Print help for the command and exit 0 |
| `--version` | flag | — | Print version and exit 0 |
| `--no-color` | flag | off | Disable ANSI styling regardless of TTY |
| `--log-level` | enum | `warn` | One of `error`, `warn`, `info`, `debug`; writes to stderr |

### Exit codes

| Code | Name | Meaning |
| --- | --- | --- |
| `0` | success | Completed; no blocking findings |
| `1` | findings | Findings present with `--fail-on-findings`, or `verity test` reported a vulnerable case |
| `2` | usage | Invalid flag, unknown command, mutually exclusive options |
| `3` | config | Unreadable/invalid config, schema, dialect, or baseline file |
| `4` | target | Target unreachable, refused, or timed out (`--url`, `--live-probe`) |
| `5` | internal | Unhandled internal error; a stack trace is printed at `--log-level debug` |
| `6` | baseline | Baseline file incompatible with the current rule set or schema version |

Exit codes are stable across minor releases. Scripts may rely on them.

### Environment variables

| Variable | Commands | Default | Description |
| --- | --- | --- | --- |
| `VERITY_CONFIG_FILE` | scan | — | Default for `--config-file` |
| `VERITY_SCHEMA_FILE` | scan | — | Default for `--schema-file` |
| `VERITY_FORMAT` | scan, test | auto | Default for `--format` |
| `VERITY_OUTPUT` | scan, test | stdout | Default for `--output` |
| `VERITY_OFFLINE` | scan | `1` | When `0`, behaves like `--live-probe` |
| `VERITY_FAIL_ON_FINDINGS` | scan, test | `0` | When `1`, behaves like `--fail-on-findings` |
| `VERITY_BASELINE` | scan, test | — | Default for `--baseline` |
| `VERITY_TEST_AUTHORIZATION` | test | — | `Authorization` header supplied to `--url` requests |
| `VERITY_NO_COLOR` | all | — | Any non-empty value disables color |
| `VERITY_LOG_LEVEL` | all | `warn` | Default for `--log-level` |
| `VERITY_TRANSPORT` | serve | — | Default for `--transport` |

Precedence, highest first: command-line flag → environment variable → built-in default. `NO_COLOR` (standard) is honored alongside `VERITY_NO_COLOR`.

---

## verity scan

~~~text
verity scan [--config-file PATH] [--schema-file PATH] [--path PATH]
            [--format terminal|json|markdown|html|sarif] [--output PATH]
            [--fail-on-findings] [--offline | --live-probe]
~~~

Statically audits discovered MCP/LLM configuration files and Python source trees. Target code is parsed, never executed.

### Option table

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `--config-file` | path | auto-discover | Explicit MCP/LLM config. When omitted, `.mcp.json`, `mcp.json`, and `claude_desktop_config.json` are located by walking upward from `--path` |
| `--schema-file` | path | — | JSON Schema for declared tool arguments. Enables `VERITY-MCP-014` (argument allowlisting) |
| `--path` | path | `.` | Root of the source tree to scan |
| `--format` | enum | tty: `table`, pipe: `json` | `terminal`, `json`, `markdown`, `html`, or `sarif` |
| `--output` | path | stdout | Write the report to a file. When `--format` is omitted, inferred from `.json`/`.sarif` |
| `--fail-on-findings` | flag | off | Exit `1` when at least one finding is present |
| `--offline` | flag | on | Disable all outbound network calls |
| `--live-probe` | flag | off | Permit outbound probes of endpoints referenced by discovered configs |

### Constraints

- `--offline` and `--live-probe` are mutually exclusive (exit `2`).
- `--live-probe` prints a notice to stderr and implies egress from the host.
- `--schema-file` requires `--config-file` (exit `3` if the pair is incomplete).
- Unreadable config or schema files exit `3`.
- Scan never imports, executes, or evaluates project code.

### Examples

~~~bash
# Default posture scan of the current directory
verity scan

# Explicit config and source root
verity scan --config-file .mcp.json --path server

# Machine-readable report to a file
verity scan --path . --format json --output findings.json

# CI gate
verity scan --path . --offline --fail-on-findings

# Code-scanning upload
verity scan --path . --format sarif --output verity.sarif

# Live probing of referenced endpoints
verity scan --path . --config-file .mcp.json --live-probe
~~~

### Terminal output

~~~text
verity 1.4.2 — scan
root: /Users/ivan/app
mode: offline (no live probes)

SEVERITY  COUNT
critical  1
high      2
medium    3
low       0
info      1
total     7

CRITICAL  CWE-78   .mcp.json:12     shell: true with interpolated env var
HIGH      CWE-798  .mcp.json:8      hard-coded API token
MEDIUM    CWE-89   app/db.py:58     f-string used in cursor.execute

duration: 1.2s   files: 812   configs: 4
~~~

### JSON output

Envelope fields:

| Field | Type | Description |
| --- | --- | --- |
| `schema_version` | string | Report schema version, currently `1.0` |
| `tool.name` | string | Always `verity` |
| `tool.version` | string | Scanner version |
| `scan.path` | string | Resolved scan root |
| `scan.offline` | boolean | Whether egress was disabled |
| `scan.live_probe` | boolean | Whether live probing was enabled |
| `scan.duration_ms` | integer | Wall-clock duration |
| `summary` | object | Counts per severity plus `total` |
| `findings` | array | Finding objects (see below) |
| `baseline` | object or null | Present when `--baseline` was used |

Finding object fields:

| Field | Type | Description |
| --- | --- | --- |
| `id` | string | Rule identifier, e.g. `CWE-78` or `VERITY-MCP-014` |
| `severity` | enum | `critical`, `high`, `medium`, `low`, `info` |
| `title` | string | Short human description |
| `location` | object | `file`, `line`, `column` |
| `evidence` | string | Snippet explaining the match |
| `remediation` | string | Suggested fix |
| `fingerprint` | string | `sha256:` hash of rule, location, evidence |

~~~json
{
  "schema_version": "1.0",
  "tool": { "name": "verity", "version": "1.4.2" },
  "scan": {
    "path": "/Users/ivan/app",
    "offline": true,
    "live_probe": false,
    "duration_ms": 1240
  },
  "summary": { "critical": 1, "high": 2, "medium": 3, "low": 0, "info": 1, "total": 7 },
  "findings": [
    {
      "id": "CWE-78",
      "severity": "critical",
      "title": "Shell execution with interpolated input",
      "location": { "file": ".mcp.json", "line": 12, "column": 5 },
      "evidence": "\"command\": \"npx ... --token $TOKEN\"",
      "remediation": "Pass arguments as an array and avoid shell interpretation.",
      "fingerprint": "sha256:6f1c...e9"
    }
  ],
  "baseline": null
}
~~~

### SARIF output

SARIF 2.1.0. One `run` per invocation, one `rule` per finding identifier, one `result` per finding.

| Field | Value |
| --- | --- |
| `version` | `2.1.0` |
| `runs[0].tool.driver.name` | `verity` |
| `runs[0].tool.driver.version` | scanner version |
| `runs[0].results[].ruleId` | finding `id` |
| `runs[0].results[].level` | `critical`/`high` → `error`, `medium` → `warning`, `low`/`info` → `note` |
| `runs[0].results[].partialFingerprints.verityFingerprint` | finding `fingerprint` |

~~~json
{
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "verity", "version": "1.4.2" } },
    "results": [{
      "ruleId": "CWE-78",
      "level": "error",
      "message": { "text": "Shell execution with interpolated input" },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": ".mcp.json" },
          "region": { "startLine": 12, "startColumn": 5 }
        }
      }],
      "partialFingerprints": { "verityFingerprint": "sha256:6f1c...e9" }
    }]
  }]
}
~~~

### Scan exit codes

| Code | Condition |
| --- | --- |
| `0` | Scan completed; no findings (or `--fail-on-findings` not set) |
| `1` | Findings present and `--fail-on-findings` was set |
| `2` | Usage error, including `--offline` with `--live-probe` |
| `3` | Invalid config, schema, or output path |
| `4` | `--live-probe` could not reach a referenced target |
| `5` | Internal error |
| `6` | Baseline incompatible with the current rule set |

---

## verity test

~~~text
verity test [--demo] [--target NAME]
            [--sql QUERY --dialect DIALECT]
            [--url URL --target FIELD]
            [--command TEMPLATE]
            [--format terminal|json|markdown|html|sarif] [--output PATH]
            [--save-baseline PATH] [--baseline PATH]
~~~

Runs isolated payload tests for CWE-89 (SQL injection), CWE-639 (insecure direct object reference), CWE-943 (NoSQL injection), and CWE-94 (code injection). Payloads are evaluated locally; `--url` is the only mode that performs network I/O.

### Option table

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `--demo` | flag | off | Run one canonical case per CWE. With `--target`, run only that case |
| `--target` | string | — | With `--demo`: `cwe-89`, `cwe-639`, `cwe-943`, or `cwe-94`. With `--url`: owner field name to compare |
| `--sql` | string | — | SQL statement under test |
| `--dialect` | enum | — | `postgresql`, `mysql`, `sqlite`, `mssql`, `oracle`, or `mongodb` |
| `--url` | URL | — | Live endpoint tested for CWE-639 |
| `--command` | string | — | Shell command template containing `{input}` |
| `--format` | enum | tty: `table`, pipe: `json` | `terminal`, `json`, `markdown`, `html`, or `sarif` |
| `--output` | path | stdout | Write results to a file |
| `--save-baseline` | path | — | Write a baseline of current case verdicts |
| `--baseline` | path | — | Compare verdicts against a saved baseline |

### Constraints

- `--sql` requires `--dialect` (exit `2` if missing).
- `--url` requires `--target` and uses `VERITY_TEST_AUTHORIZATION` if set.
- `--command` must contain the literal `{input}` placeholder (exit `2`).
- `--save-baseline` and `--baseline` may be combined to compare and refresh in one run.
- Invalid or missing baseline files exit `3`; incompatible baselines exit `6`.
- `--url` connection failures exit `4`; other modes never touch the network.

### Examples

~~~bash
# Every demo case
verity test --demo

# A single CWE
verity test --demo --target cwe-89
verity test --demo --target cwe-639
verity test --demo --target cwe-943
verity test --demo --target cwe-94

# SQL injection against a dialect
verity test --sql "SELECT * FROM users WHERE name = '%s'" --dialect postgresql

# NoSQL operator injection
verity test --sql '{"username": {"$ne": null}}' --dialect mongodb

# IDOR against a live endpoint
VERITY_TEST_AUTHORIZATION="Bearer $TOKEN" \
  verity test --url http://127.0.0.1:8000/api/orders/42 --target order

# Command injection template
verity test --command 'echo {input}'

# JSON and SARIF
verity test --demo --format json --output tests.json
verity test --demo --format sarif --output tests.sarif

# Baseline the current verdicts, then gate on regressions
verity test --demo --save-baseline .verity-test-baseline.json
verity test --demo --baseline .verity-test-baseline.json
~~~

### Terminal output

~~~text
verity 1.4.2 — test
mode: demo (4 cases)

CWE-89   SQL injection            vulnerable  payload: ' OR 1=1 --        result: bypass
CWE-639  Insecure direct object   vulnerable  id=1 -> id=2                 result: owner mismatch
CWE-943  NoSQL injection          vulnerable  {"$ne": null}               result: bypass
CWE-94   Code injection           vulnerable  __import__("os").system(..) result: executed

summary: 4 vulnerable, 0 patched, 0 errors
~~~

### JSON output

| Field | Type | Description |
| --- | --- | --- |
| `schema_version` | string | `1.0` |
| `tool` | object | `name`, `version` |
| `suite` | string | `demo`, `sql`, `idor`, `command`, or `nosql` |
| `cases[]` | array | One object per executed case |
| `cases[].cwe` | string | `CWE-89`, `CWE-639`, `CWE-943`, or `CWE-94` |
| `cases[].status` | enum | `vulnerable`, `patched`, `skipped`, `error` |
| `cases[].payload` | string | Payload that was evaluated |
| `cases[].evidence` | string | Why the verdict was reached |
| `cases[].duration_ms` | integer | Evaluation time |
| `summary` | object | Counts by status |
| `baseline` | object or null | Present when `--baseline`/`--save-baseline` used |

~~~json
{
  "schema_version": "1.0",
  "tool": { "name": "verity", "version": "1.4.2" },
  "suite": "demo",
  "cases": [
    {
      "cwe": "CWE-89",
      "status": "vulnerable",
      "payload": "' OR 1=1 --",
      "evidence": "tautology accepted by evaluator",
      "duration_ms": 3
    }
  ],
  "summary": { "vulnerable": 1, "patched": 0, "skipped": 0, "error": 0 },
  "baseline": null
}
~~~

### SARIF output

One rule per CWE (`CWE-89`, `CWE-639`, `CWE-943`, `CWE-94`). `vulnerable` maps to `error`, `error` to `warning`, `patched` and `skipped` produce no result.

### Test exit codes

| Code | Condition |
| --- | --- |
| `0` | Completed; no case reported `vulnerable` |
| `1` | At least one case reported `vulnerable` |
| `2` | Usage error (missing `--dialect`, malformed `{input}`, conflicting flags) |
| `3` | Invalid baseline or output path |
| `4` | `--url` target unreachable, refused, or timed out |
| `5` | Internal error |
| `6` | Baseline incompatible with the current case set |

---

## verity serve

~~~text
verity serve --transport stdio|http|unix
~~~

Exposes the scanner as a long-running process using a transport suitable for MCP clients and agent frameworks.

### Option table

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `--transport` | enum | `VERITY_TRANSPORT` unset → required | `stdio`, `http`, or `unix` |

### Transport behavior

| Transport | Endpoint | Notes |
| --- | --- | --- |
| `stdio` | stdin/stdout (JSON-RPC 2.0) | Logs go to stderr; stdout carries protocol frames only |
| `http` | `127.0.0.1:8765` | Loopback only; no authentication |
| `unix` | `/tmp/verity.sock` | Loopback-equivalent; socket permissions are `0600` |

### Examples

~~~bash
verity serve --transport stdio
verity serve --transport http
verity serve --transport unix
VERITY_TRANSPORT=stdio verity serve
~~~

### Exit codes

| Code | Condition |
| --- | --- |
| `0` | Shut down cleanly |
| `2` | Missing or unknown `--transport` |
| `4` | Requested endpoint could not be bound |
| `5` | Internal error |

The server is unauthenticated. Bind it to loopback only; do not proxy it to untrusted networks.

---

## Terminal output conventions

| Stream | Content |
| --- | --- |
| stdout | The report in `terminal`, `json`, `markdown`, `html`, or `sarif` |
| stderr | Progress, warnings, live-probe notices, and errors |

- Progress is suppressed when `--format` is `json`/`sarif`, when `--output` is set, or when stdout is not a TTY.
- Color is disabled when `NO_COLOR` or `VERITY_NO_COLOR` is set, or when stderr is not a TTY.
- Long evidence strings are truncated to 120 columns in `table` mode; `json` and `sarif` are never truncated.
- The footer always reports `duration`, `files`, and `configs` in `scan`, and a `summary` line in `test`.

---

## JSON output

- `schema_version` follows semver. Additive fields do not bump the major version; removals and type changes do.
- Field order is not significant; consumers must key by name.
- `fingerprint` is stable across runs for identical rule, location, and evidence; it changes when any of those change.
- Times are milliseconds since the run started; timestamps, when present, are RFC 3339 UTC.
- Errors reported in JSON also set a non-zero exit code; the envelope is still emitted when `--output` is set.

---

## SARIF output

- Emitted as SARIF 2.1.0, suitable for GitHub code scanning, Azure DevOps, and DefectDojo.
- `tool.driver.rules` is populated once per distinct finding identifier.
- `results[].partialFingerprints.verityFingerprint` enables deduplication across runs.
- Severity mapping is fixed: `critical`/`high` → `error`, `medium` → `warning`, `low`/`info` → `note`.

GitHub Actions upload:

~~~yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: verity.sarif
~~~

---

## CI/CD pipelines

### GitHub Actions

~~~yaml
name: verity
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pipx install verity
      - name: Restore baseline
        uses: actions/cache@v4
        with:
          path: .verity-baseline.json
          key: verity-baseline-${{ github.ref_name }}
      - name: Scan (gate on regressions)
        run: |
          verity scan --path . --offline \
            --baseline .verity-baseline.json \
            --format sarif --output verity.sarif \
            --fail-on-findings
      - name: Payload tests
        run: verity test --demo --format json --output tests.json
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: verity.sarif
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: verity-reports
          path: |
            verity.sarif
            tests.json
~~~

On the first run, seed the baseline without gating:

~~~bash
verity scan --path . --offline --save-baseline .verity-baseline.json
git add .verity-baseline.json && git commit -m "chore: seed verity baseline"
~~~

### GitLab CI

~~~yaml
verity:
  image: python:3.12
  before_script:
    - pip install verity
  script:
    - verity scan --path . --offline --format json --output scan.json
    - verity test --demo --format json --output tests.json
  artifacts:
    when: always
    paths:
      - scan.json
      - tests.json
    reports:
      sast: scan.sarif
  allow_failure: false
~~~

Emit `scan.sarif` alongside `scan.json` when GitLab's SAST report ingestion is required.

### pre-commit

~~~yaml
repos:
  - repo: local
    hooks:
      - id: verity-scan
        name: verity scan
        entry: verity scan --offline --fail-on-findings --format terminal
        language: system
        pass_filenames: false
      - id: verity-test
        name: verity test --demo
        entry: verity test --demo
        language: system
        pass_filenames: false
~~~

### Jenkins

~~~groovy
stage('verity') {
    steps {
        sh 'pipx install verity'
        sh 'verity scan --path . --offline --format sarif --output verity.sarif --fail-on-findings'
        sh 'verity test --demo --format json --output tests.json'
        archiveArtifacts artifacts: 'verity.sarif, tests.json', allowEmptyArchive: true
    }
}
~~~

### Gating guidance

- Use `--baseline` on long-lived branches to block only regressions.
- Use `--fail-on-findings` without a baseline only on greenfield repositories.
- Always pair `--output` with an artifact upload; exit codes alone discard evidence.
- Keep `--offline` in CI unless the job is explicitly authorized to probe live endpoints.

---

## Troubleshooting

| Symptom | Exit | Cause | Fix |
| --- | --- | --- | --- |
| `no findings, nothing scanned` | `0` | `--path` points at a directory with no configs or Python files | Pass `--config-file` explicitly or correct `--path` |
| `baseline incompatible` | `6` | Rule set or schema version changed | Re-run with `--save-baseline` to refresh |
| `offline and live-probe conflict` | `2` | Both flags supplied | Keep only one |
| `dialect is required` | `2` | `--sql` used without `--dialect` | Add `--dialect <name>` |
| `command template missing {input}` | `2` | `--command` lacks the placeholder | Add the literal `{input}` |
| `target refused connection` | `4` | `--url` endpoint down or unreachable | Start the service or fix the URL |
| `cannot bind transport` | `4` | Address or socket already in use | Stop the other process (e.g. remove `/tmp/verity.sock`) |
| `schema requires config-file` | `3` | `--schema-file` without `--config-file` | Supply both or omit the schema |
