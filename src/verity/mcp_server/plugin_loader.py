"""Dynamic plugin discovery for Verity via ``verity.plugins`` entry points."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import logging
from typing import Any

__all__ = ["PLUGIN_GROUP", "discover_and_load_plugins", "register_in_tree_pro_defaults"]

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


def register_in_tree_pro_defaults(dispatcher: Any) -> None:
    """Register in-tree verity-pro plugin defaults when the Pro package is installed.

    Pure open-core helper: does nothing unless ``verity_pro.plugin`` is importable.
    Never imports ``verity_lite`` or ``snowflake_guard``.
    """
    if "pro" in getattr(dispatcher, "loaded_plugins", []):
        return
    try:
        if importlib.util.find_spec("verity_pro") is None:
            return
        if importlib.util.find_spec("verity_pro.plugin") is None:
            return
    except (ModuleNotFoundError, ValueError):
        return
    try:
        from verity_pro.plugin import (  # type: ignore[import-not-found]
            register_pro_extensions,
        )

        register_pro_extensions(dispatcher)
    except Exception as exc:
        logger.warning("Failed to register verity-pro defaults: %s", exc)
