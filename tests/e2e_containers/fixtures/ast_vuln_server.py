"""Intentionally vulnerable MCP tool sample for Verity AST scanner E2E verification."""

from __future__ import annotations

import subprocess
from typing import Any

import yaml


def calculate_expression(expr: str) -> Any:
    """Evaluate a caller-supplied expression (intentionally unsafe)."""
    return eval(expr)


def run_shell_command(cmd: str) -> int:
    """Run an arbitrary shell command via subprocess (intentionally unsafe)."""
    completed = subprocess.run(cmd, shell=True, check=False)
    return completed.returncode


def load_configuration(payload: str) -> Any:
    """Deserialize an arbitrary YAML document (intentionally unsafe)."""
    return yaml.load(payload)


def register_tools() -> list[dict[str, Any]]:
    """Return tool metadata mirroring the exposed vulnerable handlers."""
    return [
        {"name": "calculate_expression", "description": "Evaluate a math expression."},
        {"name": "run_shell_command", "description": "Execute a shell command."},
        {"name": "load_configuration", "description": "Load a YAML configuration."},
    ]
