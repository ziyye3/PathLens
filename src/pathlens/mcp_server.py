"""MCP stdio interface; results have the same contract as CLI JSON output."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from .analysis import analyze
from .collectors import collect_live
from .models import Snapshot

server = FastMCP("PathLens")


@server.tool()
def analyze_snapshot(snapshot: dict[str, Any], max_assets: int = 100) -> dict[str, Any]:
    """Analyze an offline PathLens snapshot without making network requests."""
    return analyze(Snapshot.model_validate(snapshot), max_assets=max_assets).as_dict()


@server.tool()
def scan_domain(domain: str, authorized: bool = False, max_assets: int = 100) -> dict[str, Any]:
    """Query public sources for a domain only when the user explicitly confirms authorization."""
    snapshot = collect_live(domain, authorized=authorized, max_assets=max_assets)
    return analyze(snapshot, max_assets=max_assets, collection_mode="live").as_dict()


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
