# Installation

Verity runs on macOS, Linux, and Windows, with first-class support for developer laptops, CI runners, air-gapped environments, and security research workstations. Choose the path that matches your environment, then wire the IDE client of your choice to the shared MCP server.

---

## Customer Environment Selector Guide

| Environment | Recommended install | Why | Key flags |
|---|---|---|---|
| Developer workstation | `uvx` or `brew` | Fast updates, no global pollution | `verity scan --path .` |
| CI/CD pipeline | `pip` or container | Pinned versions, deterministic cache | `--fail-on-findings --format json` |
| Air-gapped / regulated | Source or offline wheel | Full artifact control | `--offline` |
| Security researcher | `uv tool` or source | Isolated env, editable checkout | `--target ... --demo` |

### Prerequisites

- Python 3.12 or newer (<3.15) for pip, uvx, uv tool, and source installs.
- A supported IDE client for MCP integration.
- Optional: Docker 24+ only if you choose the container path.

~~~bash
$ python --version
Python 3.12.4
~~~

---

## Install with `uvx`

`uvx` runs Verity in an ephemeral environment, which is ideal for one-off scans and trying the CLI without modifying global state.

~~~bash
$ curl -LsSf https://astral.sh/uv/install.sh | sh
$ uvx --from verity-redteam-core verity scan --offline
$ uvx --from verity-redteam-core verity scan --path . --format terminal
~~~

Pin a version in automation:

~~~bash
$ uvx --from verity-redteam-core==0.2.1 verity scan --path . --fail-on-findings
~~~

## Install with `pip`

Use a virtual environment or the CI runner's managed environment.

~~~bash
$ python -m venv .venv
$ source .venv/bin/activate
$ python -m pip install --upgrade pip
$ python -m pip install "verity-redteam-core==0.2.1"
$ verity scan --help
~~~

~~~bash
$ python -m pip install --upgrade verity-redteam-core
~~~

## Install with `uv tool`

`uv tool` installs an isolated CLI binary while keeping it on `PATH`.

~~~bash
$ uv tool install verity-redteam-core
$ uv tool list
verity-redteam-core v0.2.1

$ verity scan --help
~~~

Upgrade or uninstall:

~~~bash
$ uv tool upgrade verity-redteam-core
$ uv tool uninstall verity-redteam-core
~~~

## Install with Homebrew

> The Homebrew formula is upcoming in M30. Use `uvx` or `pip` until then.

~~~bash
$ brew tap JMartynov/tap
$ brew install verity
$ verity scan --help
~~~

Upgrade:

~~~bash
$ brew upgrade verity
~~~

## Install with Docker

Run Verity from the official Python 3.12 image and mount the working directory for scanning.

~~~bash
$ docker run --rm \
    -v "$PWD:/work" \
    -w /work \
    python:3.12-slim \
    sh -c "pip install verity-redteam-core==0.2.1 && verity scan --path . --format json"
~~~

For CI, pin the image digest instead of the tag.

## Install from source

Use this path for air-gapped builds, contribution, or deep inspection.

~~~bash
$ git clone https://github.com/JMartynov/verityredteam-free.git
$ cd verityredteam-free
$ uv sync
$ uv run verity scan --help
~~~

Build an offline wheel for transfer:

~~~bash
$ uv build
$ ls dist
verity_redteam_core-0.2.1-py3-none-any.whl
~~~

## Verify the installation

~~~bash
$ verity scan --offline
$ verity test --demo
$ python -c "import verity; print(verity.__version__)"
0.2.1
~~~

---

## MCP client discovery paths

| Client | macOS | Linux | Windows |
|---|---|---|---|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` | `~/.config/Claude/claude_desktop_config.json` | `%APPDATA%\Claude\claude_desktop_config.json` |
| Cursor | `~/Library/Application Support/Cursor/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` | `~/.config/Cursor/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` | `%APPDATA%\Cursor\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | `~/.codeium/windsurf/mcp_config.json` | `%USERPROFILE%\.codeium\windsurf\mcp_config.json` |
| VS Code | `~/Library/Application Support/Code/User/mcp.json` | `~/.config/Code/User/mcp.json` | `%APPDATA%\Code\User\mcp.json` |
| Cline | `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` | `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` | `%APPDATA%\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json` |
| Continue | `~/.continue/config.json` | `~/.continue/config.json` | `%USERPROFILE%\.continue\config.json` |
| Zed | `~/.zed/settings.json` | `~/.config/zed/settings.json` | `%APPDATA%\Zed\settings.json` |

### Shared MCP server entry

Most clients accept the same command block. Adapt the key name where required (`mcpServers`, `context_servers`, or IDE-specific schema).

~~~json
{
  "mcpServers": {
    "verity": {
      "command": "verity",
      "args": ["serve", "--transport", "stdio"]
    }
  }
}
~~~

For Continue:

~~~json
{
  "mcpServers": [
    {
      "name": "verity",
      "command": "verity",
      "args": ["serve", "--transport", "stdio"]
    }
  ]
}
~~~

For Zed:

~~~json
{
  "context_servers": {
    "verity": {
      "command": {
        "path": "verity",
        "args": ["serve", "--transport", "stdio"]
      }
    }
  }
}
~~~

---

## Troubleshooting FAQ

### 1. `uvx: command not found`

~~~bash
$ uvx --from verity-redteam-core verity scan --offline
zsh: command not found: uvx
~~~

Install uv and reopen the shell so `~/.local/bin` is on `PATH`.

~~~bash
$ curl -LsSf https://astral.sh/uv/install.sh | sh
$ exec "$SHELL"
$ uvx --from verity-redteam-core verity scan --offline
~~~

### 2. Permission denied writing an MCP config

Add the `verity` server entry directly to the client JSON config. If the file or directory is not writable:

~~~bash
$ verity scan --config-file "$HOME/Library/Application Support/Claude/claude_desktop_config.json"
error: permission denied: /Users/dev/Library/Application Support/Claude/claude_desktop_config.json
~~~

Fix ownership or run the client once so it creates the directory, then retry.

~~~bash
$ mkdir -p "$HOME/Library/Application Support/Claude"
$ chmod u+rw "$HOME/Library/Application Support/Claude"
$ verity scan --config-file "$HOME/Library/Application Support/Claude/claude_desktop_config.json"
~~~

### 3. Python version mismatch

~~~bash
$ python -m pip install verity-redteam-core
ERROR: Package 'verity-redteam-core' requires a different Python: 3.9.6 not in '>=3.12,<3.15'
~~~

Use a supported interpreter explicitly.

~~~bash
$ uv python install 3.12
$ uv venv --python 3.12
$ uv pip install verity-redteam-core
$ verity scan --help
~~~

### 4. Homebrew tap not found

~~~bash
$ brew install verity
Error: No available formula with the name "verity".
~~~

Tap the repository first.

~~~bash
$ brew tap JMartynov/tap
$ brew install verity
$ verity scan --help
~~~

### 5. Docker daemon unavailable

~~~bash
$ docker run --rm python:3.12-slim verity scan --offline
Cannot connect to the Docker daemon at unix:///var/run/docker.sock.
~~~

Start Docker and retry.

~~~bash
$ docker run --rm \
    -v "$PWD:/work" \
    -w /work \
    python:3.12-slim \
    sh -c "pip install verity-redteam-core==0.2.1 && verity scan --path . --format json"
~~~

### 6. IDE does not list `verity` as an MCP server

~~~bash
$ verity serve --transport stdio
error: command not found in client PATH
~~~

Use an absolute path in the client config, or install Verity where the IDE can see it.

~~~bash
$ which verity
/Users/dev/.local/bin/verity
~~~

~~~json
{
  "mcpServers": {
    "verity": {
      "command": "/Users/dev/.local/bin/verity",
      "args": ["serve", "--transport", "stdio"]
    }
  }
}
~~~

Restart the IDE, then confirm discovery with a manual stdio handshake:

~~~bash
$ printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"manual","version":"1.0.0"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | verity serve --transport stdio
~~~

The response lists the four unified tools: `verity_security_scan`, `verity_database_guard`, `verity_database_oracle`, and `verity_remediation_ops`.

---

## Uninstall

~~~bash
$ uv tool uninstall verity-redteam-core
$ brew uninstall verity
$ python -m pip uninstall -y verity-redteam-core
~~~

Remove any `verity` entry from the MCP config paths listed above, then restart the IDE client.
