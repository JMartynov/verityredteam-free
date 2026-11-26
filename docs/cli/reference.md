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
- `--format` accepts `terminal`, `json`, `markdown`, `html`, or `sarif` for `scan` (`sarif` is `[Pro]`); `test` accepts `terminal`, `json`, `markdown`, or `html`.
- `terminal` is the default for both `scan` and `test`.
- Color is enabled only when stderr is a TTY and `NO_COLOR` is unset.
- Reports go to stdout (or `--output`); diagnostics and progress go to stderr.
- Every command supports `--help`. To print the version, run `python -c "import verity; print(verity.__version__)"` (`--version` is planned for M30).
- Repeated scans and tests are deterministic: the same input produces the same fingerprints.

### Global options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `--help` | flag | — | Print help for the command and exit 0 |

### Exit codes

| Code | Name | Meaning |
| --- | --- | --- |
| `0` | success | Completed; no blocking findings |
| `1` | findings | Findings present with `--fail-on-findings`, or `verity test` reported a vulnerable case |
| `2` | usage / Pro gate | Invalid flag, unknown command, or gated `[Pro]` feature (`PRO_FEATURE_REQUIRED`) |
| `3` | config | Unreadable or invalid config, schema, or dialect file |
| `4` | target | Target unreachable, refused, or timed out (`--url`, `--live-probe`) |
| `5` | internal | Unhandled internal error |

Exit codes are stable across minor releases. Scripts may rely on them.

### Environment variables

| Variable | Commands | Default | Description |
| --- | --- | --- | --- |
| `VERITY_CONFIG_FILE` | scan | — | Default for `--config-file` |
| `VERITY_SCHEMA_FILE` | scan | — | Default for `--schema-file` |
| `VERITY_FORMAT` | scan, test | auto | Default for `--format` |
| `VERITY_OUTPUT` | scan, test | stdout | Default for `--output` |
| `VERITY_OFFLINE` | scan | unset | Set to `1` to enable air-gapped offline mode using bundled snapshots; `--offline` sets it to `1` for the run |
| `VERITY_FAIL_ON_FINDINGS` | scan | `0` | When `1`, behaves like `--fail-on-findings` |
| `VERITY_BASELINE` | test | — | Default for `--baseline` |
| `VERITY_TEST_AUTHORIZATION` | test | — | `Authorization` header supplied to `--url` requests |
| `VERITY_NO_COLOR` | all | — | Any non-empty value disables color |
| `VERITY_LOG_LEVEL` | all | `warn` | Logging verbosity for diagnostics (`error`, `warn`, `info`, `debug`) |
| `VERITY_TRANSPORT` | serve | — | Default for `--transport` |

Precedence, highest first: command-line flag → environment variable → built-in default. `NO_COLOR` (standard) is honored alongside `VERITY_NO_COLOR`.

---

## verity scan

~~~text
verity scan [--config-file PATH] [--schema-file PATH] [--path PATH]
            [--format terminal|json|markdown|html|sarif] [--output PATH]
            [--fail-on-findings] [--offline] [--live-probe]
~~~

Statically audits discovered MCP/LLM configuration files and Python source trees. Target code is parsed, never executed.

### Option table

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `--config-file` | path | auto-discover | Explicit MCP/LLM config. When omitted, `.mcp.json`, `mcp.json`, and `claude_desktop_config.json` are located by walking upward from `--path` |
| `--schema-file` | path | — | JSON Schema for declared tool arguments. Enables static checks such as `VERITY-STATIC-TOOL-POISONING` on tool schemas |
| `--path` | path | — | Python source file or directory to scan |
| `--format` | enum | `terminal` | `terminal`, `json`, `markdown`, `html`, or `sarif` (`[Pro]`) |
| `--output` | path | stdout | Write the report to a file |
| `--fail-on-findings` | flag | off | Exit `1` when at least one finding is present |
| `--offline` | flag | off | Enable air-gapped offline mode using bundled snapshots. Sets `VERITY_OFFLINE=1` for the run |
| `--live-probe` | flag | off | Permit outbound probes of endpoints referenced by discovered configs |

### Constraints

- `--live-probe` implies egress from the host.
- `--offline` sets `VERITY_OFFLINE=1` for the run.
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

# Code-scanning upload [Pro]
verity scan --path . --format sarif --output verity.sarif

# Live probing of referenced endpoints
verity scan --path . --config-file .mcp.json --live-probe
~~~

### Terminal output

~~~text
verity 0.2.1 — scan
root: /Users/ivan/app
mode: offline (no live probes)

SEVERITY  COUNT
critical  1
high      2
medium    3
low       0
info      1
total     7

CRITICAL  VERITY-STATIC-SHELL-DROPPER  .mcp.json:12     shell: true with interpolated env var
HIGH      SEC-STATIC-SECRET-IN-CONFIG   .mcp.json:8      hard-coded API token
MEDIUM    VERITY-AST-CWE-89-SQLI        app/db.py:58     f-string used in cursor.execute

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

Finding object fields:

| Field | Type | Description |
| --- | --- | --- |
| `id` | string | Rule identifier, e.g. `VERITY-STATIC-SHELL-DROPPER` or `VERITY-STATIC-TOOL-POISONING` |
| `severity` | enum | `critical`, `high`, `medium`, `low`, `info` |
| `title` | string | Short human description |
| `location` | object | `file`, `line`, `column` |
| `evidence` | string | Snippet explaining the match |
| `remediation` | string | Suggested fix |
| `fingerprint` | string | `sha256:` hash of rule, location, evidence |

~~~json
{
  "schema_version": "1.0",
  "tool": { "name": "verity", "version": "0.2.1" },
  "scan": {
    "path": "/Users/ivan/app",
    "offline": true,
    "live_probe": false,
    "duration_ms": 1240
  },
  "summary": { "critical": 1, "high": 2, "medium": 3, "low": 0, "info": 1, "total": 7 },
  "findings": [
    {
      "id": "VERITY-STATIC-SHELL-DROPPER",
      "severity": "critical",
      "title": "Shell execution with interpolated input",
      "location": { "file": ".mcp.json", "line": 12, "column": 5 },
      "evidence": "\"command\": \"npx ... --token $TOKEN\"",
      "remediation": "Pass arguments as an array and avoid shell interpretation.",
      "fingerprint": "sha256:6f1c...e9"
    }
  ]
}
~~~

### SARIF output (`[Pro]`)

SARIF 2.1.0 export (`--format sarif`) is a `[Pro]` feature requiring `verity-pro`. When `verity-pro` is absent, Free emits the deterministic `PRO_FEATURE_REQUIRED` JSON payload (`"ok": false`, `"verdict": "PRO_REQUIRED"`, `"error": "PRO_FEATURE_REQUIRED"`), exits with code `2`, and writes zero partial files even when `--output` is supplied. When `verity-pro` is installed, `--format sarif` and `ComplianceReportEngine.generate_bundle()` emit one `run` per invocation, one `rule` per finding identifier, and one `result` per finding with exact `physicalLocation.region.startLine` (falling back to `1` when line info is absent) and `artifactLocation.uri`, alongside OSV v1.6.0 records storing `AIVSS` under `database_specific.aivss`.

| Field | Value |
| --- | --- |
| `version` | `2.1.0` |
| `runs[0].tool.driver.name` | `verity` |
| `runs[0].tool.driver.version` | scanner version |
| `runs[0].results[].ruleId` | finding `id` |
| `runs[0].results[].level` | `critical`/`high` → `error`, `medium` → `warning`, `low`/`info` → `note` |
| `runs[0].results[].locations[0].physicalLocation.artifactLocation.uri` | finding `file_path` / `uri` |
| `runs[0].results[].locations[0].physicalLocation.region.startLine` | finding `line_number` / `line` (fallback `1`) |
| `runs[0].results[].partialFingerprints.verityFingerprint` | finding `fingerprint` |

~~~json
{
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "verity", "version": "0.2.1" } },
    "results": [{
      "ruleId": "VERITY-STATIC-SHELL-DROPPER",
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
| `2` | Usage error (unknown or invalid flag) or gated `[Pro]` feature such as `--format sarif` (`PRO_FEATURE_REQUIRED`, zero partial file writes) |
| `3` | Invalid config, schema, or output path |
| `4` | `--live-probe` could not reach a referenced target |
| `5` | Internal error |

---

## verity test

~~~text
verity test [--demo] [--target NAME]
            [--sql QUERY --dialect DIALECT]
            [--url URL --target FIELD]
            [--command TEMPLATE]
            [--format terminal|json|markdown|html] [--output PATH]
            [--save-baseline PATH] [--baseline PATH]
~~~

Runs isolated payload tests for CWE-89 (SQL injection), CWE-639 (insecure direct object reference), CWE-943 (NoSQL injection), and CWE-94 (code injection). Payloads are evaluated locally; `--url` is the only mode that performs network I/O.

### Option table

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `--demo` | flag | off | Run one canonical case per CWE. With `--target`, run only that case |
| `--target` | string | — | With `--demo`: `sqlite-basic`, `postgres-basic`, `mongo-basic`, or `code-exec-basic` |
| `--sql` | string | — | SQL statement under test |
| `--dialect` | enum | `postgres` | `postgres`, `mysql`, `sqlite`, `duckdb`, `tsql`, `bigquery`, or `snowflake` |
| `--url` | URL | — | Live MCP SSE endpoint to probe |
| `--command` | string | — | Stdio MCP command to probe |
| `--format` | enum | `terminal` | `terminal`, `json`, `markdown`, or `html` |
| `--output` | path | stdout | Write results to a file |
| `--save-baseline` | path | — | Write a baseline of current case verdicts |
| `--baseline` | path | — | Compare verdicts against a saved baseline |

### Constraints

- `--dialect` defaults to `postgres`.
- `--url` uses `VERITY_TEST_AUTHORIZATION` if set.
- `--save-baseline` and `--baseline` require `--command` or `--url` and are mutually exclusive; each violation is reported as a `FAIL` result and exits `1`.
- Invalid or missing baseline files exit `1` with a `FAIL` result.
- `--url` connection failures are reported as a `FAIL` result and exit `1`.

### Examples

~~~bash
# Every demo case
verity test --demo

# A single demo target
verity test --demo --target sqlite-basic
verity test --demo --target postgres-basic
verity test --demo --target mongo-basic
verity test --demo --target code-exec-basic

# SQL injection against a dialect
verity test --sql "SELECT * FROM users WHERE name = '%s'" --dialect postgres
verity test --sql "SELECT * FROM users WHERE name = '%s'" --dialect sqlite

# Probe a live MCP SSE endpoint
VERITY_TEST_AUTHORIZATION="Bearer $TOKEN" \
  verity test --url http://127.0.0.1:8000/sse

# Command probe
verity test --command 'python3 server.py'

# JSON output
verity test --demo --format json --output tests.json

# Baseline MCP tool hashes, then gate on drift
verity test --command 'python3 server.py' --save-baseline .verity-test-baseline.json
verity test --command 'python3 server.py' --baseline .verity-test-baseline.json
~~~

### Terminal output

~~~text
verity 0.2.1 — test
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
  "tool": { "name": "verity", "version": "0.2.1" },
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

### Test exit codes

| Code | Condition |
| --- | --- |
| `0` | Completed; no case reported `vulnerable` or `FAIL` |
| `1` | At least one case reported `vulnerable` or `FAIL`, including baseline/rug-pull and probe failures |
| `2` | Usage error (unknown flag or unknown subcommand) |
| `5` | Internal error |

---

## verity serve

~~~text
verity serve [--transport stdio|sse|http] [--host HOST] [--port PORT]
~~~

Exposes the scanner as a long-running process using a transport suitable for MCP clients and agent frameworks.

### Option table

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `--transport` | enum | `stdio` | `stdio`, `sse`, or `http` |
| `--host` | string | `127.0.0.1` | Bind host for network transports |
| `--port` | integer | `8765` | Bind port for network transports |

### Transport behavior

| Transport | Endpoint | Notes |
| --- | --- | --- |
| `stdio` | stdin/stdout (JSON-RPC 2.0) | Logs go to stderr; stdout carries protocol frames only |
| `sse` | `127.0.0.1:8765` | HTTP/SSE JSON-RPC; loopback only; no authentication |
| `http` | `127.0.0.1:8765` | HTTP JSON-RPC; loopback only; no authentication |

### Examples

~~~bash
verity serve --transport stdio
verity serve --transport sse
verity serve --transport http --host 127.0.0.1 --port 8765
VERITY_TRANSPORT=stdio verity serve
~~~

### Exit codes

| Code | Condition |
| --- | --- |
| `0` | Shut down cleanly |
| `2` | Missing or unknown `--transport` |
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

## SARIF output (`[Pro]`)

- Requires `verity-pro`; in Free, `--format sarif` emits `"ok": false`, `"verdict": "PRO_REQUIRED"`, `"error": "PRO_FEATURE_REQUIRED"`, exits with code `2`, and writes no partial file even when `--output` is supplied.
- When `verity-pro` is installed, emitted as OASIS SARIF 2.1.0 with exact `physicalLocation.region.startLine` (falling back to `1` when line info is absent) and `artifactLocation.uri`, suitable for GitHub code scanning, Azure DevOps, and DefectDojo.
- `ComplianceReportEngine.generate_bundle()` additionally pairs SARIF 2.1.0 with OSV v1.6.0 records that store `AIVSS` under `database_specific.aivss`.
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
      - run: pipx install verity-redteam-core
      - name: Scan (Pro SARIF export)
        # `--format sarif` requires verity-pro; Free exits 2 and writes no file.
        run: |
          verity scan --path . --offline \
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

Install `verity-pro` in the job to enable `--format sarif`. Without it, use `--format json` and upload the JSON report.

### GitLab CI

~~~yaml
verity:
  image: python:3.12
  before_script:
    - pip install verity-redteam-core
  script:
    - verity scan --path . --offline --format json --output scan.json
    - verity test --demo --format json --output tests.json
  artifacts:
    when: always
    paths:
      - scan.json
      - tests.json
  allow_failure: false
~~~

Emit `scan.sarif` with `[Pro]` (`verity-pro` installed) when GitLab's SAST report ingestion is required.

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
        sh 'pipx install verity-redteam-core'
        sh 'verity scan --path . --offline --format json --output scan.json --fail-on-findings'
        sh 'verity test --demo --format json --output tests.json'
        archiveArtifacts artifacts: 'scan.json, tests.json', allowEmptyArchive: true
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
| `target refused connection` | `1` | `--url` endpoint down or unreachable | Start the service or fix the URL |
| `cannot bind transport` | `4` | Address or port already in use | Stop the other process or choose another `--port` |
