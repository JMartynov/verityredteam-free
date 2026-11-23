# Verity in Your IDE: MCP Security Co-Pilot

Verity can run as a local Model Context Protocol (MCP) server and act as a security co-pilot inside your IDE or desktop AI client. The IDE assistant can ask Verity to scan MCP configurations, fingerprint MCP servers, validate SQL, verify database claims, and prepare remediation guidance without leaving the editor.

`verity serve` is a **stdio MCP server**. It speaks standard **JSON-RPC 2.0** over stdin/stdout, advertises tools through `tools/list`, and executes them through `tools/call`. There is no HTTP listener, no browser dependency, and no telemetry in the default serve path.

This guide covers:

- Installing and invoking Verity.
- Ready-to-copy MCP configurations for popular IDE clients.
- JSON-RPC handshake and tool examples.
- How an IDE assistant uses Verity results.
- Troubleshooting the stdio handshake, virtual environments, and offline operation.
- The zero-telemetry and offline guarantee.

---

## 1. What `verity serve` Provides

When your IDE starts `verity serve`, the client and server perform a standard MCP stdio handshake:

1. The client starts the process and writes JSON-RPC messages to stdin.
2. The server writes JSON-RPC responses to stdout.
3. Diagnostic logging goes to stderr, never stdout.
4. The client discovers tools with `tools/list`.
5. The assistant calls tools with `tools/call`.
6. The server wraps the tool result in MCP `content` blocks.

The supported unified tools are:

| Tool | Purpose |
| --- | --- |
| `verity_security_scan` | Run MCP/security scans such as server fingerprinting and environment audits. |
| `verity_database_guard` | Validate SQL and block dangerous database operations. |
| `verity_database_oracle` | Verify database claims and query results against a trusted oracle. |
| `verity_remediation_ops` | Produce and apply remediation guidance for findings. |

The authoritative input schema for every tool is returned by `tools/list`. IDE assistants should always read that schema before constructing tool arguments. Examples in this document are illustrative and use the argument shapes supported by the dispatcher.

---

## 2. Prerequisites

- Python 3.11 or newer.
- `uv` for the recommended zero-install `uvx` flow.
- A Verity installation if you want to use the `verity` command directly.
- Local Verity data snapshots if you are operating offline. The usual directories are `data/fingerprints` and `data/vulnerabilities`.

Verify `uvx`:

~~~bash
uvx --version
~~~

Verify the installed command:

~~~bash
verity --help
~~~

Verify the serve entry point:

~~~bash
verity serve --help
~~~

If your client cannot see shell-installed commands, use the absolute path to the executable in the MCP configuration. On macOS or Linux:

~~~bash
which uvx
which verity
~~~

On Windows, use the full `.exe` path, for example `C:\Users\you\.local\bin\verity.exe`.

---

## 3. Two Supported Invocation Styles

Every configuration in this guide is shown in two variants.

### Variant A: zero-install with `uvx`

~~~json
{
  "command": "uvx",
  "args": ["verity-redteam-core", "serve"]
}
~~~

This is the easiest starting point. `uvx` resolves and runs the package without a permanent global install.

### Variant B: installed `verity` command

~~~json
{
  "command": "verity",
  "args": ["serve"]
}
~~~

Use this when Verity is already installed in a controlled environment or when your organization pins tool versions internally.

Both variants communicate over stdio. Do not configure an HTTP or SSE URL for IDE use.

---

## 4. Ready-to-Copy IDE Configurations

### 4.1 Google Antigravity

Paste this into Antigravity's MCP server settings. This is the client-level MCP configuration, not the directory that Verity scans for server schemas.

Variant A:

~~~json
{
  "mcpServers": {
    "verity": {
      "command": "uvx",
      "args": ["verity-redteam-core", "serve"]
    }
  }
}
~~~

Variant B:

~~~json
{
  "mcpServers": {
    "verity": {
      "command": "verity",
      "args": ["serve"]
    }
  }
}
~~~

After saving, reload the MCP servers in Antigravity and confirm that `verity_security_scan`, `verity_database_guard`, `verity_database_oracle`, and `verity_remediation_ops` appear in the tool list.

### 4.2 Claude Desktop

Configuration file locations:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

Variant A:

~~~json
{
  "mcpServers": {
    "verity": {
      "command": "uvx",
      "args": ["verity-redteam-core", "serve"]
    }
  }
}
~~~

Variant B:

~~~json
{
  "mcpServers": {
    "verity": {
      "command": "verity",
      "args": ["serve"]
    }
  }
}
~~~

Restart Claude Desktop after editing the file. If the tools do not appear, check the Claude Desktop logs and run `verity serve` manually in a terminal to confirm that the process starts and waits on stdin.

### 4.3 Cursor

Use Cursor's MCP configuration, either global or project-local.

Variant A:

~~~json
{
  "mcpServers": {
    "verity": {
      "command": "uvx",
      "args": ["verity-redteam-core", "serve"]
    }
  }
}
~~~

Variant B:

~~~json
{
  "mcpServers": {
    "verity": {
      "command": "verity",
      "args": ["serve"]
    }
  }
}
~~~

Reload the Cursor window or use the MCP panel to restart the server. Cursor should show four tools after the handshake completes.

### 4.4 Windsurf

Use Windsurf's MCP server configuration file.

Variant A:

~~~json
{
  "mcpServers": {
    "verity": {
      "command": "uvx",
      "args": ["verity-redteam-core", "serve"]
    }
  }
}
~~~

Variant B:

~~~json
{
  "mcpServers": {
    "verity": {
      "command": "verity",
      "args": ["serve"]
    }
  }
}
~~~

After saving, refresh the MCP servers in Windsurf. If the server appears but tools do not, inspect the server stderr output and verify that `uvx` or `verity` is on the GUI application's `PATH`.

### 4.5 VS Code with GitHub Copilot

VS Code MCP configuration uses a `servers` object and an explicit stdio type. Place this in `.vscode/mcp.json` or the equivalent user-level MCP configuration.

Variant A:

~~~json
{
  "servers": {
    "verity": {
      "type": "stdio",
      "command": "uvx",
      "args": ["verity-redteam-core", "serve"]
    }
  }
}
~~~

Variant B:

~~~json
{
  "servers": {
    "verity": {
      "type": "stdio",
      "command": "verity",
      "args": ["serve"]
    }
  }
}
~~~

Start or restart the MCP server from the VS Code command palette. GitHub Copilot can then use the Verity tools in agent mode.

### 4.6 Cline

Cline stores MCP server definitions in its `cline_mcp_settings.json` file. Add the Verity entry under `mcpServers`.

Variant A:

~~~json
{
  "mcpServers": {
    "verity": {
      "command": "uvx",
      "args": ["verity-redteam-core", "serve"]
    }
  }
}
~~~

Variant B:

~~~json
{
  "mcpServers": {
    "verity": {
      "command": "verity",
      "args": ["serve"]
    }
  }
}
~~~

Save the file and reload Cline. Cline should list the Verity tools in its MCP tools panel.

### 4.7 Zed

Zed uses `context_servers`. The command is an object with a `path` and `args`.

Variant A:

~~~json
{
  "context_servers": {
    "verity": {
      "command": {
        "path": "uvx",
        "args": ["verity-redteam-core", "serve"]
      }
    }
  }
}
~~~

Variant B:

~~~json
{
  "context_servers": {
    "verity": {
      "command": {
        "path": "verity",
        "args": ["serve"]
      }
    }
  }
}
~~~

Restart Zed or reload the settings. Zed will launch the server over stdio and expose the Verity tools to the assistant.

---

## 5. JSON-RPC Handshake

The client sends `initialize` first.

Request:

~~~json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {
      "name": "example-ide",
      "version": "1.0.0"
    }
  }
}
~~~

Response:

~~~json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2024-11-05",
    "capabilities": {
      "tools": {
        "listChanged": false
      }
    },
    "serverInfo": {
      "name": "verity-discovery-security-mcp-server",
      "version": "1.0.0"
    }
  }
}
~~~

The client then sends a notification. Notifications have no `id` and do not receive a response.

~~~json
{
  "jsonrpc": "2.0",
  "method": "notifications/initialized"
}
~~~

---

## 6. Tool Discovery

Request:

~~~json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/list",
  "params": {}
}
~~~

The response contains the authoritative tool definitions. It is abbreviated here; use the response from your running server for exact `inputSchema` fields.

~~~json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "tools": [
      {
        "name": "verity_security_scan",
        "description": "Run MCP and application security scans.",
        "inputSchema": {
          "type": "object"
        }
      },
      {
        "name": "verity_database_guard",
        "description": "Validate SQL and guard database operations.",
        "inputSchema": {
          "type": "object"
        }
      },
      {
        "name": "verity_database_oracle",
        "description": "Verify database claims and query results.",
        "inputSchema": {
          "type": "object"
        }
      },
      {
        "name": "verity_remediation_ops",
        "description": "Produce remediation guidance for findings.",
        "inputSchema": {
          "type": "object"
        }
      }
    ]
  }
}
~~~

The IDE assistant should use the `inputSchema` from this response, not a hard-coded schema, before calling a tool.

---

## 7. Tool-by-Tool Reference and Examples

The MCP response envelope is always the same:

~~~json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "<tool JSON result>"
      }
    ],
    "isError": false
  }
}
~~~

The `text` field contains the tool's JSON result. The IDE assistant should parse it and use the structured fields in its answer. If `isError` is `true`, the assistant should report the failure and the error content instead of pretending the scan succeeded.

### 7.1 `verity_security_scan`

Use this tool for fingerprinting an MCP server, scanning client environments, and auditing tool contracts.

Example developer prompt:

> Fingerprint the FastMCP server in this workspace and tell me whether its exposed tools match a known package.

Example tool call:

~~~json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "verity_security_scan",
    "arguments": {
      "action": "fingerprint_server",
      "options": {
        "name_hint": "fastmcp"
      }
    }
  }
}
~~~

Example response envelope:

~~~json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "<JSON audit and fingerprint report>"
      }
    ],
    "isError": false
  }
}
~~~

How the IDE assistant uses the result:

1. Parse the JSON in `content[0].text`.
2. Summarize matched package, confidence, findings, and severity.
3. Quote the relevant tool-contract evidence.
4. Offer a next step such as `verity_remediation_ops` or a configuration change.
5. If `isError` is `true`, show the error and suggest a diagnostic command.

### 7.2 `verity_database_guard`

Use this tool before executing generated or user-supplied SQL. It is a guardrail for database operations.

Example developer prompt:

> Is this SQL safe to run? `SELECT * FROM users`

Example tool call:

~~~json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "verity_database_guard",
    "arguments": {
      "action": "validate_sql_query",
      "options": {
        "sql_query": "SELECT * FROM users"
      }
    }
  }
}
~~~

Example response envelope:

~~~json
{
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "<JSON SQL validation result>"
      }
    ],
    "isError": false
  }
}
~~~

How the IDE assistant uses the result:

- If the query is allowed, explain why and optionally continue with the database workflow.
- If the query is blocked, do not execute it. Explain the violated rule, quote the risky SQL fragment, and propose a parameterized or scoped alternative.
- If the tool returns an error because the query could not be parsed, ask the developer to provide a complete statement.

### 7.3 `verity_database_oracle`

Use this tool when the assistant needs to verify a database claim, compare an expected result with an oracle result, or validate that a generated query returns trustworthy data.

Example developer prompt:

> Verify that the reporting query returns the same row count as the trusted oracle.

The exact required arguments depend on the `inputSchema` returned by `tools/list`. The following call demonstrates the JSON-RPC envelope; replace `{}` with the schema-valid fields for your version.

~~~json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "tools/call",
  "params": {
    "name": "verity_database_oracle",
    "arguments": {}
  }
}
~~~

Example response envelope:

~~~json
{
  "jsonrpc": "2.0",
  "id": 5,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "<JSON oracle verification result>"
      }
    ],
    "isError": false
  }
}
~~~

How the IDE assistant uses the result:

- Treat a negative verification as a hard stop for data-changing actions.
- Explain which value was expected, which value was observed, and why they differ.
- Do not claim the database is correct unless the oracle result explicitly supports that conclusion.

### 7.4 `verity_remediation_ops`

Use this tool after a security scan or database guard finding to turn evidence into a concrete fix plan.

Example developer prompt:

> Turn the findings from the last scan into a patch plan for this repository.

The exact required arguments depend on `tools/list`. This example shows the transport envelope.

~~~json
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "tools/call",
  "params": {
    "name": "verity_remediation_ops",
    "arguments": {}
  }
}
~~~

Example response envelope:

~~~json
{
  "jsonrpc": "2.0",
  "id": 6,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "<JSON remediation plan and guidance>"
      }
    ],
    "isError": false
  }
}
~~~

How the IDE assistant uses the result:

- Present remediation steps in priority order.
- Distinguish automatic, guided, and manual fixes.
- Never apply a code change that the remediation result marks as unsafe or requiring approval.
- Re-run the relevant scan or guard after applying a fix.

---

## 8. End-to-End IDE Flow

A typical IDE interaction looks like this:

1. Developer asks: “Audit the MCP servers configured in this workspace.”
2. The assistant calls `verity_security_scan` with the appropriate scan action.
3. Verity reads local configuration and fingerprint data.
4. Verity returns a JSON report in `content[0].text`.
5. The assistant summarizes findings and links them to files or tools.
6. Developer asks: “Fix the highest-severity issue.”
7. The assistant calls `verity_remediation_ops`.
8. The assistant applies only approved edits and re-runs the scan.

The assistant should keep tool output structured. It should not paste raw JSON at the developer unless the developer asks for it; it should translate the JSON into a concise security narrative with evidence.

---

## 9. Troubleshooting Playbook

### 9.1 The IDE shows the server but no tools

1. Open a terminal.
2. Run the exact command from your configuration.
3. Send a valid `initialize` request and confirm that a response appears.

Manual handshake test on macOS or Linux:

~~~bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"manual","version":"1.0.0"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | uvx verity-redteam-core serve
~~~

If this prints a JSON response containing `tools`, the server is healthy and the IDE configuration is the problem. If it prints nothing, check stderr and the executable path.

### 9.2 `uvx` works in Terminal but not in the IDE

GUI applications often have a different `PATH` than your shell. Use an absolute path.

~~~bash
which uvx
~~~

Put that full path into the IDE configuration:

~~~json
{
  "command": "/Users/you/.local/bin/uvx",
  "args": ["verity-redteam-core", "serve"]
}
~~~

For the installed command:

~~~bash
which verity
~~~

~~~json
{
  "command": "/Users/you/.local/bin/verity",
  "args": ["serve"]
}
~~~

### 9.3 The process exits immediately

Run the server manually and inspect stderr:

~~~bash
verity serve
~~~

Common causes:

- Python version too old. Use Python 3.11 or newer.
- The package is not installed in the active environment.
- The virtual environment was created under a different user or architecture.
- A project-level `.env` or wrapper script is sending output to stdout.

Only JSON-RPC may be written to stdout. Logs and prompts must go to stderr.

### 9.4 Virtual environment problems

Create and activate a clean environment:

~~~bash
uv venv
source .venv/bin/activate
uv pip install -e .
~~~

On Windows:

~~~bash
uv venv
.venv\Scripts\activate
uv pip install -e .
~~~

Then confirm:

~~~bash
python --version
which verity
verity serve --help
~~~

If the IDE uses `uvx`, the virtual environment is managed by `uvx` and does not need to be activated. If the IDE uses `verity`, make sure the IDE's command path points to the environment where Verity is installed.

### 9.5 The server starts but the handshake times out

- Confirm that the client is configured for stdio, not SSE or HTTP.
- Confirm that no wrapper script prints a banner to stdout.
- Confirm that the client sends `initialize` before `tools/list`.
- Confirm that the client sends `notifications/initialized` after the initialize response.
- Check whether a proxy or corporate endpoint security tool is intercepting child processes.

### 9.6 Tool calls fail with schema errors

Call `tools/list` and inspect the `inputSchema` for the target tool. The dispatcher validates arguments against the schemas returned by the server. Do not copy arguments from a different Verity version.

### 9.7 Fingerprints or vulnerability data are missing

Local scans depend on local snapshots. Confirm that the data directories exist relative to the process working directory, or configure the scan to use the packaged snapshots.

~~~bash
ls -la data/fingerprints
ls -la data/vulnerabilities
~~~

If the IDE starts the server from a different working directory, run Verity from the repository root or install a build that bundles the expected data paths.

### 9.8 Windows path and quoting issues

Use escaped backslashes in JSON or use forward slashes.

~~~json
{
  "command": "C:\\Users\\you\\.local\\bin\\verity.exe",
  "args": ["serve"]
}
~~~

Do not wrap the command in extra shell quotes. The MCP client starts the executable directly.

---

## 10. Zero-Telemetry and Offline Guarantee

Verity is designed to run as a local security tool.

- `verity serve` does not require a Verity account.
- The MCP server does not send analytics, usage events, prompts, source code, or scan results to a Verity telemetry endpoint.
- Default fingerprinting and vulnerability lookup operate on local data snapshots.
- Tool results are returned to the calling MCP client over stdio.
- The server does not open an inbound network port in stdio mode.

For air-gapped environments:

1. Install Verity and its data snapshots in advance.
2. Configure the IDE to launch `verity serve` with an absolute executable path.
3. Disable or avoid actions that explicitly require live network probing.
4. Keep `data/fingerprints` and `data/vulnerabilities` under change control.
5. Review the MCP client's own telemetry settings separately; the IDE may have its own data policies.

Network egress can occur only when you explicitly request an operation that needs it, such as live probing a remote MCP endpoint. Local scan, fingerprint, SQL guard, and local vulnerability lookup paths do not need outbound connectivity.

---

## 11. Security Checklist for IDE Rollout

- Pin the Verity version used by the organization.
- Prefer absolute executable paths in managed IDE configurations.
- Review each IDE's MCP server configuration before enabling it for developers.
- Restrict database guard and oracle credentials to least-privilege accounts.
- Keep local fingerprint and vulnerability snapshots updated.
- Treat `isError: true` as a failure, not as a clean result.
- Require human approval for remediation actions that modify code or data.
- Log tool calls at the IDE or gateway layer if your compliance model requires an audit trail.
- Verify that stdout contains only JSON-RPC messages.
- Run the manual handshake test after upgrading Verity or changing Python environments.

---

## 12. Quick Reference

Start the server manually:

~~~bash
verity serve
~~~

Zero-install invocation:

~~~bash
uvx verity-redteam-core serve
~~~

Manual MCP tools/list smoke test:

~~~bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"1.0.0"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | verity serve
~~~

Supported unified tools:

- `verity_security_scan`
- `verity_database_guard`
- `verity_database_oracle`
- `verity_remediation_ops`
