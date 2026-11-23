# Quickstart

Get a first verified finding in under a minute.

`verity` audits three surfaces:

| Surface | Command | Audits |
| --- | --- | --- |
| Posture scan | `verity scan` | MCP/LLM tool configs and Python source trees |
| Payload test | `verity test` | SQL, NoSQL, IDOR, and code-injection payloads |
| Control plane | `verity serve` | Exposes the scanner over a transport |

The four tutorials are independent. Tutorial 1 needs no project files.

## Requirements

- Python 3.10+
- `verity` 1.0+
- No network access for Tutorials 1, 3, and 4

## Install

~~~bash
pipx install verity
verity --version
# verity 1.4.2
~~~

Alternative:

~~~bash
python -m pip install --user verity
~~~

Confirm the binary resolves and the subcommands load:

~~~bash
which verity
verity scan --help
verity test --help
~~~

---

## Tutorial 1 — Audit your workstation in 10 seconds

`verity scan` walks a directory tree, loads any discovered MCP configuration, and reports findings. It never executes target code and is offline by default.

### Step 1. Run the scan

~~~bash
verity scan --path . --format terminal
~~~

### Step 2. Read the summary

~~~text
verity 1.4.2 — scan
root: /Users/ivan
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
HIGH      CWE-94   tools/run.py:31  exec() on remote input
MEDIUM    CWE-22   tools/files.py:19 path join without normalization
MEDIUM    CWE-639  tools/api.py:44  object fetched by id without owner check
MEDIUM    CWE-89   app/db.py:58     f-string used in cursor.execute
INFO      VERITY-HINT-002          3 MCP servers use server-to-server auth

duration: 1.2s   files: 812   configs: 4
~~~

### Step 3. Re-run as JSON

~~~bash
verity scan --path . --format json --output findings.json
jq '.summary' findings.json
~~~

### Step 4. Fail CI on findings

~~~bash
verity scan --path . --offline --fail-on-findings
echo $?
# 1
~~~

`--fail-on-findings` returns exit code 1 when any finding is present; it does not alter the report.

### What happened

- `.mcp.json` was auto-discovered by walking upward from `--path`.
- Sources were parsed, not executed. Nothing in your project ran.
- `--offline` is the default; `--live-probe` is the opt-in.

---

## Tutorial 2 — Vulnerable MCP config and Python server

Scan a deliberately unsafe MCP setup, read the findings, and apply the fix.

### Step 1. Create the project

~~~bash
mkdir -p quickstart-mcp/server
cd quickstart-mcp
~~~

`.mcp.json`:

~~~json
{
  "mcpServers": {
    "shell-runner": {
      "command": "npx",
      "args": ["-y", "@acme/runner", "--token", "sk-live-9f3a2b7c4d5e6f"],
      "env": {
        "DEBUG": "1",
        "SHELL_WRAPPER": "true"
      }
    },
    "py-tools": {
      "command": "python",
      "args": ["server/main.py"],
      "env": {
        "PATH": "/usr/local/bin:/usr/bin"
      }
    }
  }
}
~~~

`server/main.py`:

~~~python
import os
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer

TOOL_TOKEN = "sk-live-1a2b3c4d5e6f"


def run_command(payload: dict) -> str:
    cmd = payload.get("command", "echo")
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        print(subprocess.check_output(body.decode(), shell=True))


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 7070), Handler).serve_forever()
~~~

### Step 2. Scan config and server together

~~~bash
verity scan \
  --config-file .mcp.json \
  --schema-file server/schema.json \
  --path server \
  --format terminal
~~~

Sample output:

~~~text
CRITICAL  CWE-78         .mcp.json:5       server "shell-runner" wraps command in shell
CRITICAL  CWE-78         server/main.py:9  subprocess.run(..., shell=True) on request data
CRITICAL  CWE-78         server/main.py:17 subprocess.check_output on request body
HIGH      CWE-798        .mcp.json:6       live token committed to config
HIGH      CWE-798        server/main.py:7  hard-coded TOOL_TOKEN
MEDIUM    VERITY-MCP-014 .mcp.json:1       no allowlist for tool arguments
~~~

`--schema-file` is optional. It validates the declared tool schema and raises findings when argument types allow raw strings into `command`.

### Step 3. Save a machine-readable report

~~~bash
verity scan --config-file .mcp.json --path server \
  --format json --output report.json
~~~

### Step 4. Fix the server

Replace shell execution with an allowlisted subprocess:

~~~python
import shlex
import subprocess

ALLOWED = {"echo", "uptime", "date"}


def run_command(payload: dict) -> str:
    argv = shlex.split(payload.get("command", "echo"))
    if not argv or argv[0] not in ALLOWED:
        raise ValueError("command not allowed")
    return subprocess.run(argv, shell=False, capture_output=True, text=True).stdout
~~~

Load the token from the environment instead of committing it:

~~~python
TOOL_TOKEN = os.environ["TOOL_TOKEN"]
~~~

### Step 5. Re-scan to confirm

~~~bash
verity scan --config-file .mcp.json --path server --format terminal
# total 2 (VERITY-MCP-014, VERITY-HINT-002)
~~~

Only informational items remain, so `--fail-on-findings` exits 0.

### Emit SARIF for code scanning

~~~bash
verity scan --config-file .mcp.json --path server \
  --offline --fail-on-findings --format sarif --output report.sarif
~~~

---

## Tutorial 3 — Native payload tests

`verity test` executes isolated, self-contained checks for the four classes most common in AI toolchains. `--demo` runs one canonical case per class.

### Run every demo

~~~bash
verity test --demo --format terminal
~~~

~~~text
CWE-89   SQL injection            vulnerable  payload: ' OR 1=1 --        result: bypass
CWE-639  Insecure direct object   vulnerable  id=1 -> id=2                 result: owner mismatch
CWE-943  NoSQL injection          vulnerable  {"$ne": null}               result: bypass
CWE-94   Code injection           vulnerable  __import__("os").system(..) result: executed
summary: 4 vulnerable, 0 patched, 0 errors
~~~

Exit code is 1 when any case reports `vulnerable`. Use `--format json` for automation.

### CWE-89 — SQL injection

~~~bash
verity test --demo --target cwe-89
~~~

Test a concrete statement against your own dialect:

~~~bash
verity test \
  --sql "SELECT * FROM users WHERE name = '%s'" \
  --dialect postgresql \
  --format json
~~~

`--dialect` accepts `postgresql`, `mysql`, `sqlite`, `mssql`, `oracle`. The payload corpus covers tautologies, union select, stacked queries, comment truncation, and time-based probes.

### CWE-639 — Insecure direct object reference

`--url` targets a live endpoint; `--target` names the expected owner field.

~~~bash
verity test \
  --url http://127.0.0.1:8000/api/orders/42 \
  --target order \
  --format terminal
~~~

Pass credentials through the environment, never on the command line:

~~~bash
export VERITY_TEST_AUTHORIZATION="Bearer $TOKEN"
verity test --url http://127.0.0.1:8000/api/orders/42 --target order
~~~

The check compares the authenticated principal with the requested object. A mismatch reports CWE-639.

### CWE-943 — NoSQL injection

~~~bash
verity test --demo --target cwe-943
verity test --sql '{"username": {"$ne": null}}' --dialect mongodb
~~~

Detects operator injection (`$ne`, `$gt`, `$where`, `$regex`) and type confusion where a string field receives an object.

### CWE-94 — Code injection

`--command` is the template under test; `verity` never executes your shell.

~~~bash
verity test --command 'python3 -m my_mcp_server' --format terminal
~~~

~~~text
CWE-94  Code injection  vulnerable  payload: ; id  result: shell metachar accepted
~~~

For Python sinks, `--demo --target cwe-94` probes `eval`, `exec`, `compile`, and `__import__` patterns.

### Persist results

~~~bash
verity test --demo --format json --output tests.json
verity test --command 'echo {input}' --format sarif --output tests.sarif
~~~

---

## Tutorial 4 — Adopting a baseline

A baseline freezes the current finding set so new code is judged only against regressions.

### Step 1. Capture today's findings

~~~bash
verity scan --path . --format json --save-baseline .verity-baseline.json
~~~

Each baseline entry stores a fingerprint — a hash of rule, location, and evidence — not a line number. Refactors that move code do not invalidate it.

### Step 2. Fail only on new findings

~~~bash
verity scan --path . --baseline .verity-baseline.json --fail-on-findings
echo $?
# 0 — no regressions
~~~

### Step 3. Introduce a regression

~~~python
# app/db.py
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
~~~

~~~bash
verity scan --path . --baseline .verity-baseline.json --fail-on-findings
echo $?
# 1 — 1 new finding: CWE-89 at app/db.py
~~~

### Step 4. Preview the delta without blocking

~~~bash
verity test --command 'python3 -m my_mcp_server' --baseline .verity-baseline.json --format terminal
~~~

~~~text
BASELINE  .verity-baseline.json (created 2026-11-20)
suppressed 41   new 1   resolved 0

NEW  CRITICAL  CWE-89  app/db.py:58  f-string used in cursor.execute
~~~

### Step 5. Refresh intentionally

Baselines rot. Re-capture on a schedule or after a remediation sprint:

~~~bash
verity scan --path . --format json --save-baseline .verity-baseline.json
git add .verity-baseline.json && git commit -m "chore: refresh verity baseline"
~~~

Keep the file in version control so every branch compares against the same baseline.

---

## Next steps

- Full flag reference: [CLI reference](../cli/reference.md).
- CI wiring: see the CI/CD pipelines section of the CLI reference.
- Machine output: `--format json` or `--format sarif`.
- Keep probes offline unless you are explicitly testing a live target.
