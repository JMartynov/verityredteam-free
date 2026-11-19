#!/usr/bin/env bash
set -euo pipefail

export HOME="${HOME:-/root}"

OUT_DIR="/tmp/out"
WORK_DIR="/tmp/workspace"
SNAP_DIR="/snapshots"

mkdir -p "$OUT_DIR" "$WORK_DIR"
printf '{"mcpServers": {}}\n' > "$OUT_DIR/empty_mcp.json"

SERVE_PID=""
cleanup() {
  if [ -n "${SERVE_PID}" ]; then
    kill "${SERVE_PID}" 2>/dev/null || true
    wait "${SERVE_PID}" 2>/dev/null || true
    SERVE_PID=""
  fi
}
trap cleanup EXIT

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

strip_ansi() { sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g'; }

expect_exit() {
  local expected="$1"; shift
  local label="$1"; shift
  local outf="$1"; shift
  set +e
  "$@" > "$outf" 2>&1
  local rc=$?
  set -e
  if [ "$rc" -ne "$expected" ]; then
    echo "----- output for: $label -----" >&2
    cat "$outf" >&2 || true
    fail "$label expected exit $expected but got $rc"
  fi
  pass "$label exited $expected"
}

SECRETS=(
  "sk-live-verity-e2e-secret-9999999999"
  "SuperSecretDbPassword123"
  "ghp_VerityE2eSecretToken1234567890abcdef"
  "sk-continue-yaml-secret-8888888888"
  "sk-exported-host-env-should-not-flag"
)

scan_for_leaks() {
  local dir="$1" f secret
  for f in "$dir"/*; do
    [ -f "$f" ] || continue
    for secret in "${SECRETS[@]}"; do
      if grep -Fq -- "$secret" "$f"; then
        fail "raw secret leaked into $f"
      fi
    done
  done
}

# ---------------- Generate realistic workstation configs ----------------
mkdir -p "$HOME/.cursor" "$HOME/.config/Claude" "$HOME/.continue"

cat > "$HOME/.cursor/mcp.json" <<'JSON'
{
  "mcpServers": {
    "analytics-db": {
      "command": "bash",
      "args": ["-c", "npx -y @org/analytics-mcp"],
      "env": {
        "OPENAI_API_KEY": "sk-live-verity-e2e-secret-9999999999",
        "DATABASE_PASSWORD": "SuperSecretDbPassword123"
      }
    },
    "mcp-remote-client": {
      "command": "npx",
      "args": ["-y", "mcp-remote@0.1.15", "https://remote.example.com/sse"]
    },
    "safe-env-server": {
      "command": "uvx",
      "args": ["mcp-server-fetch"],
      "env": {
        "OPENAI_API_KEY": "${OPENAI_API_KEY}"
      }
    }
  }
}
JSON

cat > "$HOME/.config/Claude/claude_desktop_config.json" <<'JSON'
{
  "mcpServers": {
    "gh-helper": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "ghp_VerityE2eSecretToken1234567890abcdef"
      }
    }
  }
}
JSON

cat > "$HOME/.continue/config.yaml" <<'YAML'
mcpServers:
  - name: continue-shell
    command: sh
    args:
      - -c
      - echo hi
    env:
      API_KEY: sk-continue-yaml-secret-8888888888
YAML

cat > "$WORK_DIR/.mcp.json" <<'JSON'
{
  "mcpServers": {
    "workspace-fetch": {
      "command": "uvx",
      "args": ["mcp-server-fetch"]
    }
  }
}
JSON

export OPENAI_API_KEY=sk-exported-host-env-should-not-flag

# ---------------- Scenario 1: workstation scan ----------------
cd "$WORK_DIR"
verity scan --format json --output "$OUT_DIR/workstation_all.json" \
  > "$OUT_DIR/workstation_scan.txt" 2>&1 || true
verity scan > "$OUT_DIR/workstation_terminal.txt" 2>&1 || true
verity scan --format markdown --output "$OUT_DIR/scan.md" > "$OUT_DIR/s1_md.txt" 2>&1 || true
verity scan --format html --output "$OUT_DIR/scan.html" > "$OUT_DIR/s1_html.txt" 2>&1 || true

expect_exit 1 "scan cursor --fail-on-findings" "$OUT_DIR/s1_cursor.txt" \
  verity scan --config-file "$HOME/.cursor/mcp.json" --fail-on-findings
expect_exit 1 "scan continue --fail-on-findings" "$OUT_DIR/s1_continue.txt" \
  verity scan --config-file "$HOME/.continue/config.yaml" --fail-on-findings

[ -s "$OUT_DIR/workstation_all.json" ] || fail "workstation_all.json empty"
[ -s "$OUT_DIR/scan.md" ] || fail "scan.md empty"
[ -s "$OUT_DIR/scan.html" ] || fail "scan.html empty"
python3 -m json.tool "$OUT_DIR/workstation_all.json" > /dev/null || fail "invalid JSON report"

python3 - "$OUT_DIR/workstation_all.json" <<'PY'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if isinstance(report, list):
    findings = report
elif isinstance(report, dict):
    findings = report.get("findings")
    if findings is None:
        findings = report.get("results")
    if findings is None:
        findings = report.get("issues")
    if findings is None:
        findings = []
else:
    findings = []
rule_ids = {str(f.get("rule_id", "")) for f in findings}
required = {
    "SEC-STATIC-SECRET-IN-CONFIG",
    "SEC-STATIC-UNSAFE-SHELL-WRAPPER",
    "VULN-CVE-2025-6514",
}
missing = required - rule_ids
assert not missing, f"missing rules: {missing}; got: {sorted(rule_ids)}"

secret_findings = [
    f for f in findings if f.get("rule_id") == "SEC-STATIC-SECRET-IN-CONFIG"
]
assert secret_findings, "no SEC-STATIC-SECRET-IN-CONFIG findings"
assert any("****" in str(f.get("message", "")) for f in secret_findings), (
    "no masked '****' in secret findings"
)
for finding in secret_findings:
    assert "safe-env-server" not in json.dumps(finding).lower(), (
        f"safe-env-server incorrectly flagged: {finding}"
    )
print("scenario 1 assertions passed")
PY

scan_for_leaks "$OUT_DIR"
pass "scenario 1 complete"

# ---------------- Scenario 2: live vulnerable probes ----------------
expect_exit 1 "stdio vuln probe" "$OUT_DIR/s2_stdio.txt" \
  verity test --command "python3 /opt/fixtures/vuln_stdio_mcp.py"
grep -q "FAIL" "$OUT_DIR/s2_stdio.txt" || fail "stdio probe missing FAIL"
tr -s '[:space:]' ' ' < "$OUT_DIR/s2_stdio.txt" | grep -q "static finding(s)" \
  || fail "stdio probe missing 'static finding(s)'"

expect_exit 1 "stdio vuln probe json" "$OUT_DIR/s2_stdio.json" \
  verity test --command "python3 /opt/fixtures/vuln_stdio_mcp.py" --format json

expect_exit 0 "stdio clean probe" "$OUT_DIR/s2_clean.txt" \
  verity test --command "python3 /opt/fixtures/clean_stdio_mcp.py"
grep -q "PASS" "$OUT_DIR/s2_clean.txt" || fail "clean probe missing PASS"

expect_exit 1 "sse vuln probe" "$OUT_DIR/s2_sse.txt" \
  verity test --url "http://target-sse-lab:8000/sse"
grep -q "FAIL" "$OUT_DIR/s2_sse.txt" || fail "sse probe missing FAIL"
tr -s '[:space:]' ' ' < "$OUT_DIR/s2_sse.txt" | grep -q "static finding(s)" \
  || fail "sse probe missing 'static finding(s)'"

expect_exit 1 "sse vuln probe json" "$OUT_DIR/s2_sse.json" \
  verity test --url "http://target-sse-lab:8000/sse" --format json

python3 - "$OUT_DIR/s2_stdio.json" "$OUT_DIR/s2_sse.json" <<'PY'
import json
import sys
from pathlib import Path

EXPECTED = {
    "VERITY-STATIC-INJECTION-OVERRIDE",
    "VERITY-STATIC-TOOL-POISONING",
    "VERITY-STATIC-EXFIL-WEBHOOK",
    "VERITY-STATIC-METADATA-SSRF",
}

for path in sys.argv[1:]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    results = data if isinstance(data, list) else data.get("results", [])
    failed = [r for r in results if str(r.get("status", "")).upper() == "FAIL"]
    assert failed, f"{path}: no FAIL results"
    for result in failed:
        details = str(result.get("details") or "")
        message = str(result.get("message") or "")
        for rule in EXPECTED:
            assert rule in details, f"{path}: details missing {rule}: {details}"
            assert rule in message, f"{path}: message missing {rule}: {message}"
print("scenario 2 json assertions passed")
PY

expect_exit 1 "schema scan" "$OUT_DIR/s2_schema.txt" \
  verity scan --schema-file /opt/fixtures/vendor_tools.json \
  --config-file "$OUT_DIR/empty_mcp.json" --offline --fail-on-findings
pass "scenario 2 complete"

# ---------------- Scenario 3: SQL AST guard ----------------
expect_exit 1 "sql stacked" "$OUT_DIR/s3_stacked.txt" \
  verity test --sql "SELECT id FROM users; DROP TABLE users;--"
expect_exit 1 "sql comment split" "$OUT_DIR/s3_comment.txt" \
  verity test --sql "DE/**/LETE FROM users"
expect_exit 1 "sql pg_shadow" "$OUT_DIR/s3_pgshadow.txt" \
  verity test --sql "SELECT usename, passwd FROM pg_shadow"
expect_exit 0 "sql safe" "$OUT_DIR/s3_safe.txt" \
  verity test --sql "SELECT id, email FROM orders WHERE tenant_id = :tenant_id"
grep -q "PASS" "$OUT_DIR/s3_safe.txt" || fail "safe sql missing PASS"

python3 - <<'PY'
from verity.mcp_library.sql_guard import SqlSecurityGuard

try:
    SqlSecurityGuard.validate_single_select_statement(
        "SELECT id FROM users; DROP TABLE users;--"
    )
except Exception:
    pass
else:
    raise SystemExit("stacked SQL injection was not rejected")

SqlSecurityGuard.validate_single_select_statement(
    "SELECT id, email FROM orders WHERE tenant_id = :tenant_id"
)

assert callable(getattr(SqlSecurityGuard, "enforce_tenant_filter", None)), (
    "SqlSecurityGuard.enforce_tenant_filter missing"
)
assert callable(getattr(SqlSecurityGuard, "apply_projection", None)), (
    "SqlSecurityGuard.apply_projection missing"
)
print("SqlSecurityGuard runtime checks passed")
PY

cat "$OUT_DIR"/s3_*.txt > "$OUT_DIR/scenario3_combined.txt"
pass "scenario 3 complete"

# ---------------- Scenario 4: Python AST source scanner ----------------
expect_exit 1 "ast fixture scan" "$OUT_DIR/s4_ast.txt" \
  verity scan --path /opt/fixtures/ast_vuln_server.py \
  --config-file "$OUT_DIR/empty_mcp.json" --offline --fail-on-findings \
  --format markdown --output "$OUT_DIR/ast.md"
for rule in VERITY-AST-CWE-94-EVAL VERITY-AST-CWE-78-SHELL VERITY-AST-CWE-502-YAML; do
  grep -q "$rule" "$OUT_DIR/ast.md" || fail "ast.md missing $rule"
done

expect_exit 1 "dvmcp ast scan" "$OUT_DIR/s4_dvmcp.txt" \
  verity scan --path /opt/dvmcp \
  --config-file "$OUT_DIR/empty_mcp.json" --offline --fail-on-findings \
  --format json --output "$OUT_DIR/dvmcp_ast.json"
python3 - "$OUT_DIR/dvmcp_ast.json" "$OUT_DIR/dvmcp_summary.json" <<'PY'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
total = 0
if isinstance(report, dict):
    total = report.get("total_findings", 0) or 0
    summary = report.get("summary")
    if not total and isinstance(summary, dict):
        total = summary.get("total_findings", 0) or 0
    if not total and isinstance(report.get("findings"), list):
        total = len(report["findings"])
elif isinstance(report, list):
    total = len(report)
assert total >= 1, f"DVMCP AST scan produced no findings: {report}"
Path(sys.argv[2]).write_text(
    json.dumps({"total_findings": total}, indent=2), encoding="utf-8"
)
print(f"dvmcp total_findings={total}")
PY

expect_exit 0 "clean ast scan" "$OUT_DIR/s4_clean.txt" \
  verity scan --path /opt/fixtures/clean_stdio_mcp.py \
  --config-file "$OUT_DIR/empty_mcp.json" --offline --fail-on-findings
pass "scenario 4 complete"

# ---------------- Scenario 5: 4-target zero-Docker demo ----------------
expect_exit 0 "demo" "$OUT_DIR/demo.txt" verity test --demo
grep -q "Passed: 4" "$OUT_DIR/demo.txt" || fail "demo missing 'Passed: 4'"
grep -q "Failed: 0" "$OUT_DIR/demo.txt" || fail "demo missing 'Failed: 0'"

expect_exit 0 "demo html" "$OUT_DIR/demo_html.txt" \
  verity test --demo --format html --output "$OUT_DIR/demo.html"
grep -q "<!DOCTYPE html>" "$OUT_DIR/demo.html" || fail "demo.html missing doctype"

expect_exit 0 "demo json" "$OUT_DIR/demo_json.txt" \
  verity test --demo --format json --output "$OUT_DIR/demo.json"
python3 - "$OUT_DIR/demo.json" <<'PY'
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if isinstance(data, dict):
    for key in ("results", "items", "tests"):
        if isinstance(data.get(key), list):
            data = data[key]
            break
assert isinstance(data, list), data
assert len(data) == 4, f"expected 4 demo results, got {len(data)}"
for item in data:
    assert str(item.get("status", "")).upper() == "PASS", item
print("demo json assertions passed")
PY
pass "scenario 5 complete"

# ---------------- Scenario 6: IDE MCP server mode ----------------
verity serve --transport http --host 127.0.0.1 --port 8765 \
  > "$OUT_DIR/serve_http.log" 2>&1 &
SERVE_PID=$!

health_ok=0
for _ in $(seq 1 25); do
  if python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/health', timeout=1)" \
      > /dev/null 2>&1; then
    health_ok=1
    break
  fi
  sleep 0.2
done
[ "$health_ok" -eq 1 ] || fail "verity serve /health did not return 200"

kill "$SERVE_PID" 2>/dev/null || true
wait "$SERVE_PID" 2>/dev/null || true
SERVE_PID=""

python3 - "$OUT_DIR/serve_tools.json" <<'PY'
import json
import subprocess
import sys


def rpc(proc: subprocess.Popen, message: dict) -> dict:
    assert proc.stdin is not None and proc.stdout is not None
    proc.stdin.write(json.dumps(message) + "\n")
    proc.stdin.flush()
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError("no response from verity serve --transport stdio")
    return json.loads(line)


def main(out_path: str) -> None:
    proc = subprocess.Popen(
        ["verity", "serve", "--transport", "stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        init = rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        assert "result" in init, init

        tools_resp = rpc(
            proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        )
        tools = tools_resp["result"]["tools"]
        names = {t["name"] for t in tools}
        for required in ("verity_security_scan", "verity_database_guard"):
            assert required in names, f"missing tool {required}: {sorted(names)}"
        assert len(tools) >= 4, f"expected at least 4 unified tools: {sorted(names)}"
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(tools_resp, fh, indent=2)

        guard_tool = next(t for t in tools if t["name"] == "verity_database_guard")
        schema = (
            guard_tool.get("inputSchema")
            or guard_tool.get("input_schema")
            or guard_tool.get("parameters")
            or {}
        )
        props = schema.get("properties", {}) if isinstance(schema, dict) else {}
        sql_key = next(
            (k for k in ("sql", "query", "statement", "sql_query") if k in props),
            "sql",
        )

        stacked = rpc(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "verity_database_guard",
                    "arguments": {
                        "action": "validate_sql_query",
                        sql_key: "SELECT id FROM users; DROP TABLE users;--",
                    },
                },
            },
        )
        stacked_text = json.dumps(stacked).lower()
        assert any(
            token in stacked_text
            for token in ("reject", "error", "invalid", "fail", "denied")
        ), stacked

        safe = rpc(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "verity_database_guard",
                    "arguments": {
                        "action": "validate_sql_query",
                        sql_key: (
                            "SELECT id, email FROM orders "
                            "WHERE tenant_id = :tenant_id"
                        ),
                    },
                },
            },
        )
        safe_text = json.dumps(safe).lower()
        assert any(
            token in safe_text
            for token in ("valid", "pass", "allow", "safe", "ok", "true")
        ), safe
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    main(sys.argv[1])
PY

# Scenario 6b: rug-pull detection (CLI baseline + MCP JSON-RPC)
RUG_PULL_BASELINE="$OUT_DIR/rug_pull_baseline.json"

expect_exit 0 "rug-pull baseline save" "$OUT_DIR/s6_rug_save.txt" \
  env RUG_PULL_MODE=0 verity test \
  --command "python3 /opt/fixtures/rug_pull_mcp.py" \
  --save-baseline "$RUG_PULL_BASELINE"
[ -s "$RUG_PULL_BASELINE" ] || fail "rug-pull baseline file empty"
python3 -m json.tool "$RUG_PULL_BASELINE" > /dev/null || fail "invalid rug-pull baseline JSON"

expect_exit 0 "rug-pull baseline pass" "$OUT_DIR/s6_rug_pass.txt" \
  env RUG_PULL_MODE=0 verity test \
  --command "python3 /opt/fixtures/rug_pull_mcp.py" \
  --baseline "$RUG_PULL_BASELINE"
grep -q "PASS" "$OUT_DIR/s6_rug_pass.txt" || fail "rug-pull baseline re-verify missing PASS"

expect_exit 1 "rug-pull baseline mutated" "$OUT_DIR/s6_rug_fail.json" \
  verity test \
  --command "env RUG_PULL_MODE=1 python3 /opt/fixtures/rug_pull_mcp.py" \
  --baseline "$RUG_PULL_BASELINE" --format json
grep -q "RUG_PULL_DETECTED" "$OUT_DIR/s6_rug_fail.json" \
  || fail "rug-pull mutated missing RUG_PULL_DETECTED"
grep -q "query_docs" "$OUT_DIR/s6_rug_fail.json" \
  || fail "rug-pull mutated missing query_docs"

python3 - "$RUG_PULL_BASELINE" <<'PY'
import json
import os
import subprocess
import sys

BASELINE_PATH = sys.argv[1]


def rpc(proc, message):
    assert proc.stdin is not None and proc.stdout is not None
    proc.stdin.write(json.dumps(message) + "\n")
    proc.stdin.flush()
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError("no response from verity serve --transport stdio")
    return json.loads(line)


def extract_payload(response):
    result = response.get("result") or {}
    content = result.get("content") if isinstance(result, dict) else None
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                try:
                    return json.loads(item["text"])
                except Exception:
                    continue
    if isinstance(result, dict) and "rug_pull_detected" in result:
        return result
    return {}


env = dict(os.environ)
env["RUG_PULL_MODE"] = "1"

proc = subprocess.Popen(
    ["verity", "serve", "--transport", "stdio"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    env=env,
)
try:
    rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    with open(BASELINE_PATH, "r", encoding="utf-8") as fh:
        authorized = json.load(fh)
    response = rpc(
        proc,
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "verity_security_scan",
                "arguments": {
                    "action": "detect_rug_pull",
                    "options": {
                        "command": "env",
                        "args": [
                            "RUG_PULL_MODE=1",
                            "python3",
                            "/opt/fixtures/rug_pull_mcp.py",
                        ],
                        "authorized_hashes": authorized,
                    },
                },
            },
        },
    )
    payload = extract_payload(response)
    assert payload.get("ok") is True, payload
    assert payload.get("rug_pull_detected") is True, payload
    names = {finding.get("tool_name") for finding in payload.get("drift_findings", [])}
    assert "query_docs" in names, payload
finally:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
PY

pass "scenario 6 complete"

# ---------------- Scenario 7: unpinned MCP package detection (M15) ----------------
UNPINNED_CFG="$OUT_DIR/unpinned_mcp.json"
cat > "$UNPINNED_CFG" <<'JSON'
{
  "mcpServers": {
    "mcp-remote-pinned": {
      "command": "npx",
      "args": ["-y", "mcp-remote@0.1.15", "https://remote.example.com/sse"]
    },
    "mcp-remote-unpinned": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://remote.example.com/sse"]
    },
    "local-clean-server": {
      "command": "python3",
      "args": ["/opt/fixtures/clean_stdio_mcp.py"]
    }
  }
}
JSON

expect_exit 1 "unpinned package detection" "$OUT_DIR/s7_unpinned.txt" \
  verity scan --config-file "$UNPINNED_CFG" --format json \
  --output "$OUT_DIR/unpinned_check.json" --fail-on-findings

python3 - "$OUT_DIR/unpinned_check.json" <<'PY'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
findings = report.get("findings", []) if isinstance(report, dict) else report
assert isinstance(findings, list), findings

unpinned = [
    f for f in findings if f.get("rule_id") == "SEC-STATIC-UNPINNED-PACKAGE"
]
assert len(unpinned) == 1, f"expected one unpinned finding: {unpinned}"
finding = unpinned[0]
assert finding.get("severity") == "MEDIUM", finding
assert finding.get("remediation"), finding
assert "0.1.15" not in json.dumps(finding), finding

vuln = [f for f in findings if f.get("rule_id") == "VULN-CVE-2025-6514"]
assert vuln, f"mcp-remote-pinned missing VULN-CVE-2025-6514: {findings}"
assert "0.1.15" in json.dumps(vuln[0]), vuln[0]

for item in findings:
    blob = json.dumps(item)
    assert "npx mcp-remote" in blob or "0.1.15" in blob, item
print("scenario 7 assertions passed")
PY

LOCAL_ONLY_CFG="$OUT_DIR/local_only_mcp.json"
cat > "$LOCAL_ONLY_CFG" <<'JSON'
{
  "mcpServers": {
    "local-clean-server": {
      "command": "python3",
      "args": ["/opt/fixtures/clean_stdio_mcp.py"]
    }
  }
}
JSON

expect_exit 0 "local clean server no findings" "$OUT_DIR/s7_local.txt" \
  verity scan --config-file "$LOCAL_ONLY_CFG" --format json \
  --output "$OUT_DIR/local_only_check.json" --fail-on-findings

python3 - "$OUT_DIR/local_only_check.json" <<'PY'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
findings = report.get("findings", []) if isinstance(report, dict) else report
assert findings == [], f"local-clean-server produced findings: {findings}"
print("scenario 7 local clean assertion passed")
PY
pass "scenario 7 complete"

# ---------------- Final leak scan + snapshot export ----------------
scan_for_leaks "$OUT_DIR"

if [ -d "$SNAP_DIR" ] && [ -w "$SNAP_DIR" ]; then
  copy_snap() {
    local src="$1" dst="$2"
    [ -s "$src" ] || fail "missing or empty snapshot source $src"
    strip_ansi < "$src" > "$SNAP_DIR/$dst" || true
    [ -s "$SNAP_DIR/$dst" ] || fail "empty snapshot $dst"
  }
  copy_snap "$OUT_DIR/workstation_terminal.txt" "01_workstation_scan.txt"
  copy_snap "$OUT_DIR/workstation_all.json" "01_workstation_scan.json"
  copy_snap "$OUT_DIR/s2_stdio.txt" "02_live_stdio_probe.txt"
  copy_snap "$OUT_DIR/s2_sse.txt" "02_live_sse_probe.txt"
  copy_snap "$OUT_DIR/s2_schema.txt" "02_schema_scan.txt"
  copy_snap "$OUT_DIR/scenario3_combined.txt" "03_sql_guard.txt"
  copy_snap "$OUT_DIR/ast.md" "04_ast_scan.txt"
  copy_snap "$OUT_DIR/dvmcp_summary.json" "04_dvmcp_ast_summary.json"
  copy_snap "$OUT_DIR/demo.txt" "05_demo_targets.txt"
  copy_snap "$OUT_DIR/serve_tools.json" "06_mcp_serve_tools.json"

  for f in "$SNAP_DIR"/*; do
    [ -f "$f" ] || continue
    for secret in "${SECRETS[@]}"; do
      if grep -Fq -- "$secret" "$f"; then
        fail "raw secret leaked into snapshot $f"
      fi
    done
  done
  pass "snapshots exported"
fi

echo "ALL SCENARIOS PASSED"
