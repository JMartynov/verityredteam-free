"""Central synchronizer for fetching, parsing, and caching MCP server passports."""

from __future__ import annotations

import argparse

from mcp_fingerprints.synchronizer import PassportSynchronizer


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Multi-Source MCP Passport Synchronizer & Update Engine"
    )
    parser.add_argument("--output", default="data/fingerprints", help="Passport storage directory")
    parser.add_argument(
        "--update-existing", action="store_true", help="Check and update existing MCP versions"
    )
    parser.add_argument(
        "--discover-new", action="store_true", help="Discover and pull new MCP servers"
    )
    parser.add_argument("--all", action="store_true", help="Run both update and discovery")
    args = parser.parse_args()

    syncer = PassportSynchronizer(output_dir=args.output)
    if args.all or args.update_existing:
        syncer.update_existing_passports()
    if args.all or args.discover_new:
        syncer.discover_new_mcps()


if __name__ == "__main__":
    main()

__all__ = ["PassportSynchronizer"]
