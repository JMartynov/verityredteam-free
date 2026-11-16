"""Automated Antigravity Lifecycle Management CLI for Verity MCP Auditor."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from verity.mcp_server.tools import TOOL_DEFINITIONS

WORKSPACE_ROOT = (
    Path.cwd()
    if (Path.cwd() / ".agents").exists()
    else Path(__file__).resolve().parent.parent.parent.parent
)
DEFAULT_ANTIGRAVITY_MCP_DIR = Path.home() / ".gemini" / "antigravity" / "mcp"
DEFAULT_CLI_MCP_DIR = Path.home() / ".gemini" / "antigravity-cli" / "mcp"
DEFAULT_ANTIGRAVITY_SKILLS_DIR = Path.home() / ".gemini" / "antigravity" / "builtin" / "skills"
WORKSPACE_SKILLS_DIR = WORKSPACE_ROOT / ".agents" / "skills"
DEFAULT_ANTIGRAVITY_MCP_CONFIG = Path.home() / ".gemini" / "antigravity" / "mcp_config.json"
DEFAULT_CLI_MCP_CONFIG = Path.home() / ".gemini" / "antigravity-cli" / "mcp_config.json"
DEFAULT_CLAUDE_MCP_CONFIG = (
    Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
)
DEFAULT_CURSOR_MCP_CONFIG = Path.home() / ".cursor" / "mcp.json"
DEFAULT_GLOBAL_PLUGIN_DIR = Path.home() / ".gemini" / "config" / "plugins" / "verity-plugin"

TOOL_SCHEMAS = {
    "verity_scan_environment": {
        "name": "verity_scan_environment",
        "description": (
            "Scan and audit all configured MCP servers across client environment "
            "directories or custom schemas."
        ),

        "parameters": {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {
                "custom_schemas": {
                    "type": "object",
                    "description": "Optional mapping of server names to lists of tool schemas.",
                },
                "scan_dirs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional list of directories to scan for MCP servers.",
                },
            },
            "additionalProperties": False,
        },
    },
    "verity_audit_target": {
        "name": "verity_audit_target",
        "description": (
            "Audit an MCP server (by URL, command, or package) to fingerprint its contract "
            "and detect known CVEs."
        ),
        "parameters": {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": (
                        "Target MCP URL (e.g. 'http://localhost:3000/sse') or command/package "
                        "(e.g. 'mcp-remote@0.0.8')."
                    ),
                },
                "transport_type": {
                    "type": "string",
                    "description": "Transport type: 'stdio', 'sse', or 'http'.",
                    "default": "stdio",
                },
                "live_probe": {
                    "type": "boolean",
                    "description": "Whether to dynamically query live tools and capabilities.",
                    "default": True,
                },
            },
            "required": ["target"],
            "additionalProperties": False,
        },
    },
    "verity_fingerprint_target": {
        "name": "verity_fingerprint_target",
        "description": "Match exposed MCP tools and schemas against 3,903+ passport signatures.",
        "parameters": {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {
                "tools": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "List of discovered MCP tool schemas.",
                },
                "prompts": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "Optional list of prompt templates.",
                },
                "resources": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "Optional list of resource templates.",
                },
                "name_hint": {
                    "type": "string",
                    "description": "Optional name hint for target server.",
                },
            },
            "required": ["tools"],
            "additionalProperties": False,
        },
    },
    "verity_lookup_vulnerabilities": {
        "name": "verity_lookup_vulnerabilities",
        "description": "Lookup known OSV security advisories for an MCP package name and version.",
        "parameters": {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {
                "package_name": {
                    "type": "string",
                    "description": "MCP package name (e.g. 'mcp-remote' or 'server-postgres').",
                },
                "version": {
                    "type": "string",
                    "description": (
                        "Optional package version to evaluate SemVer vulnerability ranges."
                    ),
                },
            },
            "required": ["package_name"],
            "additionalProperties": False,
        },
    },
    "verity_health_check": {
        "name": "verity_health_check",
        "description": (
            "Check the health, dataset status, and readiness of the Verity MCP Auditor server."
        ),
        "parameters": {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
}

# Merge all unified and standard tool definitions from tools.py
for _t in TOOL_DEFINITIONS:
    TOOL_SCHEMAS[_t["name"]] = {
        "name": _t["name"],
        "description": _t["description"],
        "parameters": _t.get("inputSchema", {}),
    }


def is_docker_running() -> bool:
    """Check if Docker daemon is responsive."""
    try:
        res = subprocess.run(
            ["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return res.returncode == 0
    except Exception:
        return False


def is_mcp_server_running(port: int = 8765) -> bool:
    """Check if the Verity MCP server is responsive on given port."""
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect(("127.0.0.1", port))
        s.close()
        return True
    except Exception:
        return False


def _get_mcp_config_paths() -> list[Path]:
    paths: list[Path] = []
    candidates = [
        DEFAULT_ANTIGRAVITY_MCP_CONFIG,
        Path.home() / ".gemini" / "config" / "mcp_config.json",
        DEFAULT_CLI_MCP_CONFIG,
        DEFAULT_CLAUDE_MCP_CONFIG,
        DEFAULT_CURSOR_MCP_CONFIG,
    ]
    for p in candidates:
        if (p.is_file() or p.parent.is_dir()) and p not in paths:
            paths.append(p)
    return paths


def _get_mcp_config_path() -> Path | None:
    for p in (
        DEFAULT_ANTIGRAVITY_MCP_CONFIG,
        Path.home() / ".gemini" / "config" / "mcp_config.json",
        DEFAULT_CLI_MCP_CONFIG,
        DEFAULT_CLAUDE_MCP_CONFIG,
    ):
        if p.exists():
            return p.resolve()
    return None


def register_mcp_config(transport: str = "auto") -> bool:
    config_paths = _get_mcp_config_paths()
    if not config_paths:
        return False
    success = False
    venv_py = WORKSPACE_ROOT / ".venv" / "bin" / "python"
    py_cmd = str(venv_py) if venv_py.is_file() else sys.executable

    stdio_entry = {
        "command": py_cmd,
        "args": ["-m", "verity.mcp_server.server", "--transport", "stdio"],
        "env": {
            "PYTHONPATH": str(WORKSPACE_ROOT / "src"),
            "VERITY_STREAM_LOG_PATH": str(WORKSPACE_ROOT / "artifacts" / "mcp_stream.log"),
        },
    }

    sse_entry = {
        "serverUrl": "http://localhost:8765/sse",
    }

    t_clean = transport.lower()
    # Auto-detect: prefer SSE for Antigravity when the container is responsive on 8765
    use_sse = t_clean == "sse" or (t_clean == "auto" and is_mcp_server_running(8765))

    for cfg_path in config_paths:
        try:
            cfg_path.parent.mkdir(parents=True, exist_ok=True)
            content = json.loads(cfg_path.read_text(encoding="utf-8")) if cfg_path.is_file() else {}
            servers = content.setdefault("mcpServers", {})
            # Antigravity supports serverUrl (SSE); Claude Desktop and Cursor require stdio
            if use_sse and cfg_path in (
                DEFAULT_ANTIGRAVITY_MCP_CONFIG,
                Path.home() / ".gemini" / "config" / "mcp_config.json",
                DEFAULT_CLI_MCP_CONFIG,
            ):
                servers["verity-mcp-auditor"] = sse_entry
            else:
                servers["verity-mcp-auditor"] = stdio_entry
            cfg_path.write_text(json.dumps(content, indent=2) + "\n", encoding="utf-8")
            success = True
        except Exception:
            continue

    primary = _get_mcp_config_path()
    if (
        primary
        and DEFAULT_CLI_MCP_CONFIG.parent.is_dir()
        and not DEFAULT_CLI_MCP_CONFIG.exists()
    ):
        import contextlib

        with contextlib.suppress(Exception):
            DEFAULT_CLI_MCP_CONFIG.symlink_to(primary)
    return success


def unregister_mcp_config() -> bool:
    config_paths = _get_mcp_config_paths()
    if not config_paths:
        return False
    success = False
    for cfg_path in config_paths:
        if not cfg_path.is_file():
            continue
        try:
            content = json.loads(cfg_path.read_text(encoding="utf-8"))
            servers = content.get("mcpServers", {})
            if "verity-mcp-auditor" in servers:
                del servers["verity-mcp-auditor"]
                cfg_path.write_text(json.dumps(content, indent=2) + "\n", encoding="utf-8")
            success = True
        except Exception:
            continue
    return success


def is_mcp_config_registered() -> bool:
    for cfg_path in _get_mcp_config_paths():
        if cfg_path.is_file():
            try:
                content = json.loads(cfg_path.read_text(encoding="utf-8"))
                if "verity-mcp-auditor" in content.get("mcpServers", {}):
                    return True
            except Exception:
                continue
    return False


def install(
    target_mcp_dir: Path | None = None,
    target_skills_dir: Path | None = None,
    build_container: bool = True,
    transport: str = "auto",
) -> bool:
    """Onboard Verity MCP Auditor and Skill into Antigravity."""
    mcp_dirs = [target_mcp_dir or DEFAULT_ANTIGRAVITY_MCP_DIR]
    if not target_mcp_dir and DEFAULT_CLI_MCP_DIR.parent.is_dir():
        mcp_dirs.append(DEFAULT_CLI_MCP_DIR)

    for mcp_dir in mcp_dirs:
        server_mcp_dir = mcp_dir / "verity-mcp-auditor"
        server_mcp_dir.mkdir(parents=True, exist_ok=True)

        # 1. Write MCP Tool Schemas
        for tool_name, schema in TOOL_SCHEMAS.items():
            tool_file = server_mcp_dir / f"{tool_name}.json"
            tool_file.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")

        # 2. Write instructions.md
        instructions_file = server_mcp_dir / "instructions.md"
        instructions_file.write_text(
            "# Verity MCP Security Auditor\n\n"
            "This MCP server provides unified security reconnaissance, in-line query guarding, "
            "empirical database verification oracles, and auto-remediation patches against "
            "3,903+ MCP passports and 508+ OSV security advisories.\n",
            encoding="utf-8",
        )

    # Automatically register into mcp_config.json
    register_mcp_config(transport=transport)

    # 3. Deploy Antigravity Skill
    skill_src_dir = WORKSPACE_ROOT / "skills" / "mcp-security-audit"
    if not skill_src_dir.is_dir():
        skill_src_dir = WORKSPACE_ROOT / ".agents" / "skills" / "mcp-security-audit"

    if skill_src_dir.is_dir():
        # Install into workspace project skills
        ws_skill_dest = WORKSPACE_SKILLS_DIR / "mcp-security-audit"
        shutil.copytree(skill_src_dir, ws_skill_dest, dirs_exist_ok=True)

        # Install into global Antigravity skills if directory exists
        if target_skills_dir or DEFAULT_ANTIGRAVITY_SKILLS_DIR.is_dir():
            dest_global = (
                target_skills_dir or DEFAULT_ANTIGRAVITY_SKILLS_DIR
            ) / "mcp-security-audit"
            shutil.copytree(skill_src_dir, dest_global, dirs_exist_ok=True)

        # Install into machine-global Antigravity plugin (active across ALL workspaces)
        global_plugins_parent = DEFAULT_GLOBAL_PLUGIN_DIR.parent
        if global_plugins_parent.is_dir():
            plugin_dir = DEFAULT_GLOBAL_PLUGIN_DIR
            plugin_skills_dir = plugin_dir / "skills" / "mcp-security-audit"
            plugin_dir.mkdir(parents=True, exist_ok=True)
            plugin_json = plugin_dir / "plugin.json"
            plugin_json.write_text(
                json.dumps(
                    {
                        "name": "verity-plugin",
                        "version": "1.0.0",
                        "description": (
                            "Unified MCP Security Reconnaissance, OSV Vulnerability Intelligence, "
                            "and AST Database Guards"
                        ),
                        "author": {"name": "Verity Red Team"},
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            shutil.copytree(skill_src_dir, plugin_skills_dir, dirs_exist_ok=True)


    # 4. Start Docker container if requested and docker is active
    if build_container and is_docker_running():
        compose_file = WORKSPACE_ROOT / "docker-compose.mcp.yml"
        if compose_file.is_file():
            subprocess.run(
                [
                    "docker",
                    "compose",
                    "-f",
                    str(compose_file),
                    "up",
                    "-d",
                    "--build",
                ],
                cwd=WORKSPACE_ROOT,
                check=False,
            )

    # 5. Register in Antigravity mcp_config.json if present
    register_mcp_config(transport=transport)

    return True


def remove(
    target_mcp_dir: Path | None = None,
    target_skills_dir: Path | None = None,
    stop_container: bool = True,
) -> bool:
    """Cleanly uninstall Verity MCP Auditor schemas and skill from Antigravity."""
    mcp_dir = target_mcp_dir or DEFAULT_ANTIGRAVITY_MCP_DIR
    server_mcp_dir = mcp_dir / "verity-mcp-auditor"

    # 1. Remove MCP Schemas
    if server_mcp_dir.is_dir():
        shutil.rmtree(server_mcp_dir, ignore_errors=True)

    # 2. Remove Skills
    ws_skill = WORKSPACE_SKILLS_DIR / "mcp-security-audit"
    if ws_skill.is_dir():
        shutil.rmtree(ws_skill, ignore_errors=True)

    global_skill = (target_skills_dir or DEFAULT_ANTIGRAVITY_SKILLS_DIR) / "mcp-security-audit"
    if global_skill.is_dir():
        shutil.rmtree(global_skill, ignore_errors=True)

    if DEFAULT_GLOBAL_PLUGIN_DIR.is_dir():
        shutil.rmtree(DEFAULT_GLOBAL_PLUGIN_DIR, ignore_errors=True)

    # 3. Stop Docker Container
    if stop_container and is_docker_running():
        compose_file = WORKSPACE_ROOT / "docker-compose.mcp.yml"
        if compose_file.is_file():
            subprocess.run(
                ["docker", "compose", "-f", str(compose_file), "down"],
                cwd=WORKSPACE_ROOT,
                check=False,
            )

    # 4. Unregister from Antigravity mcp_config.json if present
    unregister_mcp_config()

    return True


update = install


def status(
    target_mcp_dir: Path | None = None,
    target_skills_dir: Path | None = None,
) -> dict[str, Any]:
    """Check onboarding and installation status in Antigravity."""
    mcp_dir = target_mcp_dir or DEFAULT_ANTIGRAVITY_MCP_DIR
    server_mcp_dir = mcp_dir / "verity-mcp-auditor"
    ws_skill = WORKSPACE_SKILLS_DIR / "mcp-security-audit" / "SKILL.md"
    global_skill = (
        target_skills_dir or DEFAULT_ANTIGRAVITY_SKILLS_DIR
    ) / "mcp-security-audit" / "SKILL.md"
    plugin_skill = DEFAULT_GLOBAL_PLUGIN_DIR / "skills" / "mcp-security-audit" / "SKILL.md"

    installed_schemas = (
        [p.name for p in server_mcp_dir.glob("*.json")] if server_mcp_dir.is_dir() else []
    )

    mcp_cfg_reg = is_mcp_config_registered()
    return {
        "mcp_server_directory": str(server_mcp_dir),
        "mcp_schemas_installed": len(installed_schemas) > 0,
        "mcp_server_registered": len(installed_schemas) > 0,
        "mcp_config_registered": mcp_cfg_reg,
        "installed_schemas": installed_schemas,
        "workspace_skill_installed": ws_skill.is_file(),
        "global_skill_installed": global_skill.is_file() or plugin_skill.is_file(),
        "global_plugin_installed": plugin_skill.is_file(),
        "docker_responsive": is_docker_running(),
        "mcp_server_running": is_mcp_server_running(8765),
    }


def audit_target(url: str = "http://localhost:8800/sse", transport: str = "http") -> dict[str, Any]:
    """Execute verity_security_scan full_audit on a target URL."""
    from verity.mcp_server.bootstrap import initialize_server_context
    from verity.mcp_server.tools import VerityToolDispatcher

    resolved_url = url
    if Path("/.dockerenv").is_file() and "localhost" in resolved_url:
        resolved_url = resolved_url.replace("localhost", "host.docker.internal")

    ctx = initialize_server_context()
    dispatcher = VerityToolDispatcher(ctx)
    return dispatcher.execute_tool(
        "verity_security_scan",
        {
            "action": "full_audit",
            "options": {
                "transport": transport,
                "url": resolved_url,
            },
        },
    )


def main() -> None:
    """CLI entrypoint for managing Verity MCP Auditor registration and audits."""
    parser = argparse.ArgumentParser(description="Manage Verity MCP Auditor in Antigravity")
    parser.add_argument(
        "action",
        choices=["install", "onboard", "update", "remove", "uninstall", "status", "audit"],
    )
    parser.add_argument(
        "target_url",
        nargs="?",
        default="http://localhost:8800/sse",
        help="Target MCP endpoint URL to audit (used with 'audit' action)",
    )
    parser.add_argument(
        "--transport",
        default="auto",
        choices=["http", "sse", "stdio", "auto"],
        help="Transport type for server registration or audit (default: auto, prefers SSE if port 8765 is responsive)",
    )
    parser.add_argument("--mcp-dir", type=Path, help="Override Antigravity MCP directory")
    parser.add_argument("--skills-dir", type=Path, help="Override Antigravity Skills directory")
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="Skip docker container build/start",
    )
    args = parser.parse_args()

    if args.action in ("install", "onboard", "update"):
        success = install(
            target_mcp_dir=args.mcp_dir,
            target_skills_dir=args.skills_dir,
            build_container=not args.no_build,
            transport=args.transport,
        )
        if success:
            print("✅ Verity MCP Auditor and Skill successfully installed in Antigravity.")
        else:
            print("❌ Failed to install Verity MCP Auditor.")
            sys.exit(1)

    elif args.action in ("remove", "uninstall"):
        success = remove(
            target_mcp_dir=args.mcp_dir,
            target_skills_dir=args.skills_dir,
        )
        if success:
            print("✅ Verity MCP Auditor and Skill removed from Antigravity.")
        else:
            print("❌ Failed to remove Verity MCP Auditor.")
            sys.exit(1)

    elif args.action == "status":
        stat = status(
            target_mcp_dir=args.mcp_dir,
            target_skills_dir=args.skills_dir,
        )
        print(json.dumps(stat, indent=2))

    elif args.action == "audit":
        audit_transport = args.transport if args.transport not in ("stdio", "auto") else "http"
        res = audit_target(url=args.target_url, transport=audit_transport)
        print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()

