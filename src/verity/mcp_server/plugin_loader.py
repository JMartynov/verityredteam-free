"""Dynamic plugin discovery for Verity via ``verity.plugins`` entry points."""

from __future__ import annotations

import importlib.metadata
import logging
from typing import Any

__all__ = ["PLUGIN_GROUP", "discover_and_load_plugins"]

logger = logging.getLogger("verity.mcp_server.plugin_loader")

PLUGIN_GROUP = "verity.plugins"


def discover_and_load_plugins(dispatcher: Any) -> list[str]:
    """Discover and initialize plugins registered under the ``verity.plugins`` group.

    Each entry point must resolve to a callable accepting ``dispatcher``.
    Failures are logged and skipped so core functionality never breaks.
    """
    loaded_plugins: list[str] = []
    entry_points = importlib.metadata.entry_points(group=PLUGIN_GROUP)

    for ep in entry_points:
        try:
            plugin_init = ep.load()
            if callable(plugin_init):
                plugin_init(dispatcher)
            loaded_plugins.append(ep.name)
        except Exception as exc:
            logger.warning(
                "Failed to load plugin %r: %s",
                getattr(ep, "name", "<unknown>"),
                exc,
            )

    return loaded_plugins
