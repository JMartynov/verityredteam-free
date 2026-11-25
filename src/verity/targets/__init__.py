"""Zero-Docker synthetic red-team targets for local demonstrations."""

from __future__ import annotations

from typing import Any

from verity.targets.code_exec_target import CodeExecSyntheticTarget
from verity.targets.mongo_target import MongoSyntheticTarget
from verity.targets.postgres_sqli_target import PostgresSqliSyntheticTarget
from verity.targets.sqlite_target import SqliteSyntheticTarget

__all__ = [
    "SYNTHETIC_TARGETS",
    "TARGET_SLUGS",
    "get_synthetic_target",
    "list_synthetic_targets",
    "run_all_demo_probes",
]

SYNTHETIC_TARGETS: dict[str, Any] = {
    target.target_id: target
    for target in (
        SqliteSyntheticTarget(),
        PostgresSqliSyntheticTarget(),
        MongoSyntheticTarget(),
        CodeExecSyntheticTarget(),
    )
}

TARGET_SLUGS: frozenset[str] = frozenset(SYNTHETIC_TARGETS.keys())


def get_synthetic_target(target_id: str) -> Any:
    """Return the synthetic target instance registered under ``target_id``."""
    try:
        return SYNTHETIC_TARGETS[target_id]
    except KeyError as exc:
        raise KeyError(f"Unknown synthetic target: {target_id}") from exc


def list_synthetic_targets() -> list[str]:
    """Return the identifiers of all registered synthetic targets."""
    return list(SYNTHETIC_TARGETS.keys())


def run_all_demo_probes(
    target_id: str | None = None,
    *,
    target: str | None = None,
) -> list[dict[str, Any]]:
    """Run demo probes for one target or for every registered target."""
    resolved_id = target_id if target_id is not None else target
    if resolved_id is not None:
        return [get_synthetic_target(resolved_id).run_demo_probe()]
    return [registered.run_demo_probe() for registered in SYNTHETIC_TARGETS.values()]
