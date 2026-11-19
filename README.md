# Verity RedTeam Free (`verity-redteam-core`)

[![PyPI](https://img.shields.io/pypi/v/verity-redteam-core.svg)](https://pypi.org/project/verity-redteam-core/)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://pypi.org/project/verity-redteam-core/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/JMartynov/verityredteam-free/actions/workflows/ci.yml/badge.svg)](https://github.com/JMartynov/verityredteam-free/actions/workflows/ci.yml)

Catch poisoned MCP servers, leaked workstation secrets, prompt-injected SQL, and remote code execution hidden inside AI agent tools — before your IDE agent runs them.
Offline, deterministic, zero Docker, zero API keys, Apache-2.0.

![Verity RedTeam Free Terminal Demo](docs/assets/demo.gif)

## Install & 5-Second Quickstart

End users install straight from PyPI:

```bash
pip install verity-redteam-core
uvx --from verity-redteam-core verity scan
```

If the package is not yet on PyPI, install from source or from a built wheel:

```bash
git clone https://github.com/JMartynov/verityredteam-free.git
cd verityredteam-free
uv build
pip install dist/*.whl
```

Run your first three checks in five seconds:

```bash
verity scan
verity test --demo
verity test --sql "SELECT id FROM users; DROP TABLE users;--"
```

- `verity scan` — discovers and statically scans local AI client configs, MCP tool schemas, and Python MCP source, with credential scrubbing.
- `verity test` — deterministically probes `stdio` or `HTTP/SSE` MCP servers, validates SQL, and runs in-memory demo targets.
- `verity serve` — a zero-framework JSON-RPC 2.0 MCP server that lets your IDE agent audit itself.

## 6 Real Customer Pain Points & Verified Solutions

Every scenario below shows the exact command you run, a verbatim output captured from an
empty container (see [`tests/e2e_containers/README.md`](tests/e2e_containers/README.md)),
and how that output removes risk from your workflow.

### 1. Shadow MCP Servers, Plaintext Secrets & Known CVEs on Developer Laptops

**The Problem:** Developers silently install shadow MCP servers. Plaintext API keys sit in
`~/.cursor/mcp.json`, the Claude Desktop config, and Continue YAML, and vulnerable packages
such as `mcp-remote@0.1.15` are exposed to OS command injection (CVE-2025-6514).

**What You Run:**

```bash
verity scan
verity scan --config-file ~/.cursor/mcp.json --fail-on-findings
verity scan --config-file ~/.cursor/mcp.json --format json --output scan.json
```

**Verified Result:** `verity scan` on a clean workstation with three discovered configs:

```text
Verity Scan Report
         Summary          
┏━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Metric         ┃ Value ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ Scanned files  │     3 │
│ Total findings │     8 │
│ Duration (ms)  │   0.0 │
│ CRITICAL       │     0 │
│ HIGH           │     6 │
│ MEDIUM         │     2 │
│ LOW            │     0 │
│ INFO           │     0 │
└────────────────┴───────┘
                                              Findings                                              
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity ┃ Rule                            ┃ Title                    ┃ Location                 ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│  HIGH    │ SEC-STATIC-SECRET-IN-CONFIG     │ Plaintext Secret in      │ /root/.config/Claude/cl… │
│          │                                 │ Configuration:           │                          │
│          │                                 │ GITHUB_TOKEN             │                          │
│  HIGH    │ SEC-STATIC-SECRET-IN-CONFIG     │ Plaintext Secret in      │ /root/.cursor/mcp.json:- │
│          │                                 │ Configuration:           │                          │
│          │                                 │ OPENAI_API_KEY           │                          │
│  HIGH    │ SEC-STATIC-SECRET-IN-CONFIG     │ Plaintext Secret in      │ /root/.cursor/mcp.json:- │
│          │                                 │ Configuration:           │                          │
│          │                                 │ DATABASE_PASSWORD        │                          │
│  MEDIUM  │ SEC-STATIC-UNSAFE-SHELL-WRAPPER │ Direct Shell Execution   │ /root/.cursor/mcp.json:- │
│          │                                 │ Wrapper                  │                          │
│  HIGH    │ VULN-CVE-2025-6514              │ Known Vulnerability:     │ /root/.cursor/mcp.json:- │
│          │                                 │ mcp-remote exposed to OS │                          │
│          │                                 │ command injection via    │                          │
│          │                                 │ untrusted MCP server     │                          │
│          │                                 │ connections              │                          │
│  HIGH    │ VULN-GHSA-6xpm-ggf7-wc3p        │ Known Vulnerability:     │ /root/.cursor/mcp.json:- │
│          │                                 │ mcp-remote exposed to OS │                          │
│          │                                 │ command injection via    │                          │
│          │                                 │ untrusted MCP server     │                          │
│          │                                 │ connections              │                          │
│  HIGH    │ SEC-STATIC-SECRET-IN-CONFIG     │ Plaintext Secret in      │ /root/.continue/config.… │
│          │                                 │ Configuration: API_KEY   │                          │
│  MEDIUM  │ SEC-STATIC-UNSAFE-SHELL-WRAPPER │ Direct Shell Execution   │ /root/.continue/config.… │
│          │                                 │ Wrapper                  │                          │
└──────────┴─────────────────────────────────┴──────────────────────────┴──────────────────────────┘
Upgrade to Verity Pro for Snowflake RBAC guards, live DB canary oracles, and SARIF CI/CD exports.
```

<details>
<summary>Machine-readable JSON findings (secrets redacted as <code>****</code>)</summary>

```json
{
  "summary": {
    "scanned_files_count": 3,
    "total_findings": 8,
    "scan_duration_ms": 0.0,
    "error_count": 0,
    "severity_counts": { "CRITICAL": 0, "HIGH": 6, "MEDIUM": 2, "LOW": 0, "INFO": 0 }
  },
  "findings": [
    {
      "rule_id": "SEC-STATIC-SECRET-IN-CONFIG",
      "cwe_id": "",
      "severity": "HIGH",
      "title": "Plaintext Secret in Configuration: GITHUB_TOKEN",
      "message": "Env variable 'GITHUB_TOKEN' contains unredacted credential. (GITHUB_TOKEN=****)",
      "file_path": "/root/.config/Claude/claude_desktop_config.json",
      "line_number": "-",
      "remediation": "Replace hardcoded value with reference '${GITHUB_TOKEN}'."
    },
    {
      "rule_id": "VULN-CVE-2025-6514",
      "cwe_id": "CVE-2025-6514",
      "severity": "HIGH",
      "title": "Known Vulnerability: mcp-remote exposed to OS command injection via untrusted MCP server connections",
      "message": "mcp-remote is exposed to OS command injection when connecting to untrusted MCP servers due to crafted input from the authorization_endpoint response URL (Matched version 0.1.15 in advisory CVE-2025-6514)",
      "file_path": "/root/.cursor/mcp.json",
      "line_number": "-",
      "remediation": "Upgrade to fixed version or apply sandbox."
    }
  ],
  "scanned_files": [
    "/root/.config/Claude/claude_desktop_config.json",
    "/root/.continue/config.yaml",
    "/root/.cursor/mcp.json"
  ]
}
```

</details>

**How It Solves Your Pain Point:** One offline command audits every supported client
config, masks plaintext secrets as `****`, flags raw shell wrappers such as `bash`/`sh`,
and matches installed MCP package versions against known CVEs and advisories. Add
`--fail-on-findings` to make a leaked key or a vulnerable package fail CI. Choose any
output with `--format terminal|json|markdown|html` and persist it with `--output`.

### 2. Tool Poisoning, Indirect Prompt Injection & Exfiltration in Third-Party MCP Servers

**The Problem:** A third-party MCP server can hide instruction overrides, webhook
exfiltration, and cloud metadata SSRF inside tool descriptions that your agent reads.

**What You Run:**

```bash
verity test --command "python3 vuln_stdio_mcp.py"
verity test --url http://localhost:8000/sse
verity scan --schema-file vendor_tools.json --fail-on-findings
```

**Verified Result:** live `stdio` probe of a poisoned server:

```text
                                        Verity Test Results                                         
┏━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Status ┃ Check                 ┃ Severity ┃ Message                                              ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│  FAIL  │ stdio_transport_probe │ CRITICAL │ 4 static finding(s) on exposed capabilities:         │
│        │                       │          │ VERITY-STATIC-EXFIL-WEBHOOK;                         │
│        │                       │          │ VERITY-STATIC-INJECTION-OVERRIDE;                    │
│        │                       │          │ VERITY-STATIC-METADATA-SSRF;                         │
│        │                       │          │ VERITY-STATIC-TOOL-POISONING                         │
└────────┴───────────────────────┴──────────┴──────────────────────────────────────────────────────┘
Passed: 0  Failed: 1
Upgrade to Verity Pro for Snowflake RBAC guards, live DB canary oracles, and SARIF CI/CD exports.
```

<details>
<summary>Offline schema screen output (<code>vendor_tools.json</code>)</summary>

```text
Verity Scan Report
         Summary          
┏━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Metric         ┃ Value ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ Scanned files  │     2 │
│ Total findings │     4 │
│ Duration (ms)  │   0.0 │
│ CRITICAL       │     1 │
│ HIGH           │     3 │
│ MEDIUM         │     0 │
│ LOW            │     0 │
│ INFO           │     0 │
└────────────────┴───────┘
                                              Findings                                              
┏━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity   ┃ Rule                             ┃ Title                  ┃ Location                ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━┩
│  CRITICAL  │ VERITY-STATIC-INJECTION-OVERRIDE │ Prompt Injection       │ query_customer_records… │
│            │                                  │ Instruction Override   │                         │
│  HIGH      │ VERITY-STATIC-TOOL-POISONING     │ Tool Poisoning /       │ query_customer_records… │
│            │                                  │ Secondary Shadow       │                         │
│            │                                  │ Functionality          │                         │
│  HIGH      │ VERITY-STATIC-EXFIL-WEBHOOK      │ Out-of-Band Data       │ query_customer_records… │
│            │                                  │ Exfiltration Endpoint  │                         │
│  HIGH      │ VERITY-STATIC-METADATA-SSRF      │ Cloud Instance         │ fetch_docs:-            │
│            │                                  │ Metadata Service SSRF  │                         │
└────────────┴──────────────────────────────────┴────────────────────────┴─────────────────────────┘
Upgrade to Verity Pro for Snowflake RBAC guards, live DB canary oracles, and SARIF CI/CD exports.
```

</details>

**How It Solves Your Pain Point:** Point `verity test` at a live `stdio` command or an
`HTTP/SSE` URL and it inspects every exposed tool, prompt, and resource. For air-gapped
review, `verity scan --schema-file` screens a saved tool manifest offline. The
`INJECTION-OVERRIDE`, `TOOL-POISONING`, `EXFIL-WEBHOOK`, and `METADATA-SSRF` findings tell
you exactly which description must be removed before the server is trusted.

### 3. LLM-Generated SQL Injection, Comment-Splitting & Cross-Tenant Data Leaks

**The Problem:** An agent turns natural language into SQL. A crafted prompt can inject a
stacked query, split keywords with comments (`DE/**/LETE`), read `pg_shadow`, or cross
tenant boundaries.

**What You Run:**

```bash
verity test --sql "DE/**/LETE FROM users"
verity test --sql "SELECT usename, passwd FROM pg_shadow"
verity test --sql "SELECT id, email FROM orders WHERE tenant_id = :tenant_id"
verity test --sql "SELECT id FROM users; DROP TABLE users;--"
```

**Verified Result:** stacked queries, catalog access, and comment-splitting are rejected;
a parameterized read passes:

```text
                                        Verity Test Results                                         
┏━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Status ┃ Check              ┃ Severity ┃ Message                                                 ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│  FAIL  │ sql_security_guard │ HIGH     │ Prohibited SQL keyword detected in read query:          │
│        │                    │          │ 'DELETE'.                                               │
└────────┴────────────────────┴──────────┴─────────────────────────────────────────────────────────┘
Passed: 0  Failed: 1
Upgrade to Verity Pro for Snowflake RBAC guards, live DB canary oracles, and SARIF CI/CD exports.
                                        Verity Test Results                                         
┏━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Status ┃ Check              ┃ Severity ┃ Message                                                 ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│  FAIL  │ sql_security_guard │ HIGH     │ Access to internal database catalog 'PG_SHADOW' is      │
│        │                    │          │ prohibited.                                             │
└────────┴────────────────────┴──────────┴─────────────────────────────────────────────────────────┘
Passed: 0  Failed: 1
Upgrade to Verity Pro for Snowflake RBAC guards, live DB canary oracles, and SARIF CI/CD exports.
                                        Verity Test Results                                         
┏━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Status ┃ Check              ┃ Severity ┃ Message                                                 ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│  PASS  │ sql_security_guard │ -        │ Query passed read-only and parameterization validation. │
└────────┴────────────────────┴──────────┴─────────────────────────────────────────────────────────┘
Passed: 1  Failed: 0
Upgrade to Verity Pro for Snowflake RBAC guards, live DB canary oracles, and SARIF CI/CD exports.
                                        Verity Test Results                                         
┏━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Status ┃ Check              ┃ Severity ┃ Message                                                 ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│  FAIL  │ sql_security_guard │ HIGH     │ Stacked queries with semicolons are strictly            │
│        │                    │          │ prohibited.                                             │
└────────┴────────────────────┴──────────┴─────────────────────────────────────────────────────────┘
Passed: 0  Failed: 1
Upgrade to Verity Pro for Snowflake RBAC guards, live DB canary oracles, and SARIF CI/CD exports.
```

Embed the same guard inside your Python MCP server:

```python
from verity.mcp_library.sql_guard import SqlSecurityGuard

SqlSecurityGuard.validate_single_select_statement(query)
params = SqlSecurityGuard.enforce_tenant_filter(params, session_tenant="tenant-a")
rows = [SqlSecurityGuard.apply_projection(row, allowlist={"id", "amount"}) for row in rows]
```

**How It Solves Your Pain Point:** The `SqlSecurityGuard` parses SQL with `sqlglot`,
rejects stacked statements, comment-split keywords, DDL/DML, and internal catalogs
(`pg_shadow`, `pg_authid`, `information_schema`), while `enforce_tenant_filter` and
`apply_projection` bind tenant scope and mask non-allowlisted columns.

### 4. RCE & Dangerous Patterns in Custom Python MCP Servers (CI/CD Gate)

**The Problem:** Your own MCP servers can ship `eval()`, `shell=True` subprocesses, unsafe
YAML, and path traversal into production. You need a deterministic gate, not a vibe check.

**What You Run:**

```bash
verity scan --path ./src/my_mcp_server --fail-on-findings --format markdown --output audit.md
verity scan --path ./src/my_mcp_server --format json --output audit.json
```

**Verified Result:** AST scan of a vulnerable fixture:

```text
# Verity Scan Report

## Summary

| Metric | Value |
| --- | --- |
| Scanned files | 2 |
| Total findings | 3 |
| Duration (ms) | 0.33 |
| CRITICAL | 2 |
| HIGH | 1 |
| MEDIUM | 0 |
| LOW | 0 |
| INFO | 0 |

## Findings

| Severity | Rule | CWE | Title | Location | Remediation |
| --- | --- | --- | --- | --- | --- |
| CRITICAL | VERITY-AST-CWE-94-EVAL | CWE-94 | Unsafe Dynamic Code Evaluation (eval/exec) | /opt/fixtures/ast_vuln_server.py:13 | Replace dynamic eval/exec with a strict AST whitelist parser (e.g. SafeMathEvaluator) or isolated non-evaluating expression evaluator. |
| CRITICAL | VERITY-AST-CWE-78-SHELL | CWE-78 | Command Injection via shell=True Subprocess | /opt/fixtures/ast_vuln_server.py:18 | Set 'shell=False' and pass arguments as a validated list of tokens: ['executable', 'arg1', 'arg2']. |
| HIGH | VERITY-AST-CWE-502-YAML | CWE-502 | Insecure YAML Deserialization (yaml.load without SafeLoader) | /opt/fixtures/ast_vuln_server.py:24 | Always use yaml.safe_load() or specify Loader=yaml.SafeLoader. |

---

_Upgrade to Verity Pro for Snowflake RBAC guards, live DB canary oracles, and SARIF CI/CD exports._
```

Scanning the real DVMCP benchmark source produced **6** findings
(`04_dvmcp_ast_summary.json` reports `{"total_findings": 6}`), confirming the gate fires on
real-world MCP code, not only on synthetic fixtures.

**How It Solves Your Pain Point:** `verity scan --path` parses Python into an AST and flags
`eval`/`exec`, `compile`, `shell=True`, `os.system`, unsafe `pickle`/`yaml.load`, path
traversal, unescaped HTML, and BOLA tenant gaps. Combine with `--fail-on-findings` to block
a pull request before RCE reaches your agent.

### 5. Proving Agent Vulnerability vs. Defense in 5 Seconds (Zero Docker, Zero API Keys)

**The Problem:** You need to show a skeptical stakeholder that an agent class is exploitable
and that the secure variant resists it — without Docker, databases, or cloud credentials.

**What You Run:**

```bash
verity test --demo
verity test --demo --format html --output verity-demo.html
```

**Verified Result:** four in-memory targets pass, each proving the vulnerable server is
breached while the secure twin defends:

| Target | CWE | Outcome |
| :--- | :---: | :--- |
| `sqlite-basic` | CWE-89 | Vulnerable breached, secure defended |
| `postgres-basic` | CWE-639 | Vulnerable breached, secure defended |
| `mongo-basic` | CWE-943 | Vulnerable breached, secure defended |
| `code-exec-basic` | CWE-94 | Vulnerable breached, secure defended |

<details>
<summary>Verbatim <code>verity test --demo</code> output</summary>

```text
                                        Verity Test Results                                         
┏━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Status ┃ Check                          ┃ Severity ┃ Message                                     ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│  PASS  │ SQLite Basic Target            │ CWE-89   │ Vulnerable breached=True, Secure            │
│        │                                │          │ defended=True — {'payload': "' OR '1'='1",  │
│        │                                │          │ 'vulnerable_result': {'rows': [{'id': 1,    │
│        │                                │          │ 'username': 'alice', 'role': 'user'},       │
│        │                                │          │ {'id': 2, 'username': 'bob', 'role':        │
│        │                                │          │ 'user'}, {'id': 3, 'username': 'admin',     │
│        │                                │          │ 'role': 'admin'}], 'count': 3},             │
│        │                                │          │ 'secure_result': {'rows': [], 'count': 0}}  │
│  PASS  │ PostgreSQL Multi-Tenant Target │ CWE-639  │ Vulnerable breached=True, Secure            │
│        │                                │          │ defended=True — {'session_tenant':          │
│        │                                │          │ 'tenant-a', 'requested_invoice':            │
│        │                                │          │ 'inv_b_cyber', 'vulnerable_result':         │
│        │                                │          │ {'invoice': {'invoice_id': 'inv_b_cyber',   │
│        │                                │          │ 'tenant_id': 'tenant-b', 'amount': 1337.0,  │
│        │                                │          │ 'status': 'overdue', 'password_hash':       │
│        │                                │          │ 'FAKE-PW-HASH-B-CYBER'}}, 'secure_result':  │
│        │                                │          │ {'invoice': None}}                          │
│  PASS  │ MongoDB NoSQL Target           │ CWE-943  │ Vulnerable breached=True, Secure            │
│        │                                │          │ defended=True — {'payload': {'username':    │
│        │                                │          │ {'$ne': None}}, 'vulnerable_result':        │
│        │                                │          │ {'matches': [{'username': 'alice', 'role':  │
│        │                                │          │ 'user', 'email': 'alice@example.com',       │
│        │                                │          │ 'secret': 'alice-secret'}, {'username':     │
│        │                                │          │ 'bob', 'role': 'user', 'email':             │
│        │                                │          │ 'bob@example.com', 'secret': 'bob-secret'}, │
│        │                                │          │ {'username': 'admin', 'role': 'admin',      │
│        │                                │          │ 'email': 'admin@example.com', 'secret':     │
│        │                                │          │ 'FLAG{mongo_admin_secret}'}]},              │
│        │                                │          │ 'secure_result': {'error': 'operator        │
│        │                                │          │ payloads are not permitted', 'matches':     │
│        │                                │          │ []}}                                        │
│  PASS  │ MCP Code Execution Target      │ CWE-94   │ Vulnerable breached=True, Secure            │
│        │                                │          │ defended=True — {'payload':                 │
│        │                                │          │ "__import__('math').sqrt(16)",              │
│        │                                │          │ 'vulnerable_result': {'expression':         │
│        │                                │          │ "__import__('math').sqrt(16)", 'result':    │
│        │                                │          │ 4.0}, 'secure_result': {'error':            │
│        │                                │          │ 'expression must be a numeric literal',     │
│        │                                │          │ 'expression':                               │
│        │                                │          │ "__import__('math').sqrt(16)", 'result':    │
│        │                                │          │ None}}                                      │
└────────┴────────────────────────────────┴──────────┴─────────────────────────────────────────────┘
Passed: 4  Failed: 0
Upgrade to Verity Pro for Snowflake RBAC guards, live DB canary oracles, and SARIF CI/CD exports.
```

</details>

**How It Solves Your Pain Point:** Two commands give you an executive HTML report
(`verity-demo.html`) proving that the vulnerable variant leaks data and the secure variant
defends, with no infrastructure to provision.

### 6. In-IDE Self-Auditing & Rug-Pull Detection (`verity serve`)

**The Problem:** You want your IDE agent (Cursor, Claude Desktop, Antigravity) to audit its
own MCP environment and detect a server changing behaviour after trust (a rug pull).

**What You Run:** add Verity as an MCP server in your client config:

```json
{
  "mcpServers": {
    "verity": {
      "command": "uvx",
      "args": ["--from", "verity-redteam-core", "verity", "serve", "--transport", "stdio"]
    }
  }
}
```

Or run the server over the network:

```bash
verity serve --transport stdio
verity serve --transport http --host 127.0.0.1 --port 8765
```

`--transport` accepts `stdio`, `sse`, or `http`; network transports expose a `/health`
endpoint and accept `--host` / `--port`.

**Verified Result:** `tools/list` returns four unified MCP tools:

- `verity_security_scan` — discovery, config scanning, fingerprinting, OSV lookup, full audit, AST scan.
- `verity_database_guard` — SQL validation, warehouse policy checks, projection masking, input sanitization.
- `verity_database_oracle` — attack proposals, response verification, canary proofs.
- `verity_remediation_ops` — remediation explanations, guard patches, wrapper configs.

The Unknown Capability Profiler (`src/verity/ucp/engine.py`) provides `detect_rug_pull`
drift detection: it compares a previously trusted capability profile against the current
one and reports added, removed, or mutated tools.

**How It Solves Your Pain Point:** Your IDE agent can call Verity directly to scan its own
MCP environment, and `python -m verity.mcp_server.manage` operates the server side. Rug-pull
detection catches a server that changes its tools after you approved it.

## Full Free Capabilities Reference

### Supported AI clients (9)

`Claude Desktop`, `Cursor`, `VS Code Cline`, `VS Code Roo`, `Continue`, `Windsurf`, `Zed`,
`LibreChat`, and workspace `.mcp.json` auto-detection.

### Static rule screening (`VERITY-STATIC-*`, 13 rules)

| Rule ID | CWE | Severity | What It Catches |
| :--- | :---: | :---: | :--- |
| `VERITY-STATIC-INJECTION-OVERRIDE` | CWE-74 | CRITICAL | Prompt injection instruction overrides |
| `VERITY-STATIC-INJECTION-DELIMITER` | CWE-74 | HIGH | Spoofed system delimiters / hidden evasion blocks |
| `VERITY-STATIC-TOOL-POISONING` | CWE-358 | HIGH | Covert secondary shadow functionality |
| `VERITY-STATIC-EXFIL-WEBHOOK` | CWE-200 | HIGH | Out-of-band webhook exfiltration endpoints |
| `VERITY-STATIC-EXFIL-COVERT` | CWE-200 | HIGH | Covert background streaming of data |
| `VERITY-STATIC-METADATA-SSRF` | CWE-918 | HIGH | Cloud metadata SSRF (169.254.169.254) |
| `VERITY-STATIC-CREDENTIAL-HARVESTING` | CWE-200 | HIGH | Embedded keys and sensitive path references |
| `VERITY-STATIC-SHELL-DROPPER` | CWE-78 | CRITICAL | Remote download piped into a shell |
| `VERITY-STATIC-SHELL-REVERSE-PIPE` | CWE-78 | CRITICAL | Reverse shell network payloads |
| `VERITY-STATIC-CODE-EXECUTION` | CWE-94 | HIGH | Obfuscated / dynamic execution wrappers |
| `VERITY-STATIC-SHELL-DESTRUCTIVE` | CWE-78 | HIGH | Destructive host commands |
| `VERITY-STATIC-SQL-INJECTION-SCHEMA` | CWE-89 | HIGH | SQL injection sequences in schema defaults |
| `VERITY-STATIC-SCRIPT-INJECTION-XSS` | CWE-79 | MEDIUM | Script injection / stored XSS in metadata |

### Python AST scanning (`VERITY-AST-*`, 9 rules)

| Rule ID | CWE | Severity | What It Catches |
| :--- | :---: | :---: | :--- |
| `VERITY-AST-CWE-94-EVAL` | CWE-94 | CRITICAL | Unsafe `eval`/`exec` |
| `VERITY-AST-CWE-94-COMPILE` | CWE-94 | HIGH | Dynamic `compile()` |
| `VERITY-AST-CWE-78-SHELL` | CWE-78 | CRITICAL | `subprocess(..., shell=True)` |
| `VERITY-AST-CWE-78-SYSTEM` | CWE-78 | CRITICAL | `os.system` / `os.popen` |
| `VERITY-AST-CWE-22-TRAVERSAL` | CWE-22 | HIGH | Unvalidated path traversal |
| `VERITY-AST-CWE-502-PICKLE` | CWE-502 | CRITICAL | Insecure `pickle`/`marshal` deserialization |
| `VERITY-AST-CWE-502-YAML` | CWE-502 | HIGH | `yaml.load` without SafeLoader |
| `VERITY-AST-CWE-79-XSS` | CWE-79 | HIGH | Unescaped HTML/script injection in output |
| `VERITY-AST-CWE-862-BOLA` | CWE-862 | HIGH | Missing tenant verification in multi-tenant tools |

### Output, offline mode & exit codes

- `--format` supports `terminal`, `json`, `markdown`, and `html`; `--output` writes to a file.
- `--offline` disables remote snapshot fetching and uses local caches only.
- Exit codes: `0` success, `1` findings with `--fail-on-findings` (or a failing probe), `2` gated Pro-only feature such as SARIF export.

The SQL guard (`SqlSecurityGuard`) is also importable as a library from `verity.mcp_library.sql_guard`.

## CI/CD Integration & Reproducible Empty-Container Verification

Drop this workflow into `.github/workflows/` to gate every pull request:

```yaml
name: verity-security
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install verity-redteam-core
      - name: Scan MCP agents
        run: |
          verity scan --path ./src/my_mcp_server --schema-file vendor_tools.json --fail-on-findings
```

Every command in this README was captured from empty containers. See
[`tests/e2e_containers/README.md`](tests/e2e_containers/README.md) for the ground-zero
suite (`customer-pip`, `customer-uvx`, `customer-full-workstation`, `target-sse-lab`).
Regenerate the animated demo with [`scripts/record_demo_gif.sh`](scripts/record_demo_gif.sh).

## Free vs. Enterprise (`verity-pro`)

| Capability | `verity-redteam-core` (Free) | `verity-pro` (Enterprise) |
| :--- | :---: | :---: |
| Workstation discovery (9 clients) | ✅ | ✅ |
| 13 static rule screening | ✅ | ✅ |
| 9-rule Python AST scanning | ✅ | ✅ |
| Deterministic SQL AST guard | ✅ | ✅ |
| Zero-Docker demo targets | ✅ | ✅ |
| Terminal / JSON / Markdown / HTML reports | ✅ | ✅ |
| IDE MCP server & rug-pull detection | ✅ | ✅ |
| Snowflake RBAC & time-travel guard | — | ✅ |
| Live database verification oracles | — | ✅ |
| SARIF v2.1.0 export | — | ✅ |
| Penetration automation & canary lab | — | ✅ |

Enterprise features are discovered via plugins; see [`docs/extensibility.md`](docs/extensibility.md).

## Development

```bash
uv sync --extra dev
uv run pytest tests/ -q
uv run ruff check src tests
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
