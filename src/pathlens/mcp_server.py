"""MCP stdio interface; results have the same contract as CLI JSON output."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from .analysis import analyze
from .collectors import collect_live
from .models import Snapshot
from .threat_intel import ThreatFeed

server = FastMCP("PathLens")


@server.tool()
def analyze_snapshot(
    snapshot: dict[str, Any], max_assets: int = 100, threat_feed: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Analyze an offline PathLens snapshot without making network requests."""
    feed = ThreatFeed.model_validate(threat_feed) if threat_feed is not None else None
    return analyze(
        Snapshot.model_validate(snapshot), max_assets=max_assets, threat_feed=feed
    ).as_dict()


@server.tool()
def scan_domain(
    domain: str,
    authorized: bool = False,
    max_assets: int = 100,
    threat_feed: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Query public sources for a domain only when the user explicitly confirms authorization."""
    feed = ThreatFeed.model_validate(threat_feed) if threat_feed is not None else None
    snapshot = collect_live(domain, authorized=authorized, max_assets=max_assets)
    return analyze(
        snapshot, max_assets=max_assets, collection_mode="live", threat_feed=feed
    ).as_dict()


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
