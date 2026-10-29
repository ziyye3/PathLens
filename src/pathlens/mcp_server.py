"""MCP stdio interface; results have the same contract as CLI JSON output."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from .analysis import analyze
from .collectors import collect_live
from .exposures import ExposureObservations, correlate_exposures
from .kev import Catalog, Observations, ProductObservations, correlate, correlate_products
from .models import Snapshot
from .threat_intel import ThreatFeed

server = FastMCP("PathLens")


@server.tool()
def analyze_snapshot(
    snapshot: dict[str, Any],
    max_assets: int = 100,
    threat_feed: dict[str, Any] | None = None,
    cve_observations: dict[str, Any] | None = None,
    kev_catalog: dict[str, Any] | None = None,
    product_observations: dict[str, Any] | None = None,
    exposure_observations: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Analyze an offline PathLens snapshot without making network requests."""
    feed = ThreatFeed.model_validate(threat_feed) if threat_feed is not None else None
    if (cve_observations is None and product_observations is None) != (kev_catalog is None):
        raise ValueError("Provide CVE or product observations and kev_catalog")
    observations = (
        Observations.model_validate(cve_observations) if cve_observations is not None else None
    )
    catalog = Catalog.model_validate(kev_catalog) if kev_catalog is not None else None
    products = (
        ProductObservations.model_validate(product_observations)
        if product_observations is not None
        else None
    )
    exposures = (
        ExposureObservations.model_validate(exposure_observations)
        if exposure_observations is not None
        else None
    )
    report = analyze(Snapshot.model_validate(snapshot), max_assets=max_assets, threat_feed=feed)
    if observations is not None and catalog is not None:
        correlate(report, observations, catalog)
    if products is not None and catalog is not None:
        correlate_products(report, products, catalog)
    if exposures is not None:
        correlate_exposures(report, exposures)
    return report.as_dict()


@server.tool()
def scan_domain(
    domain: str,
    authorized: bool = False,
    max_assets: int = 100,
    threat_feed: dict[str, Any] | None = None,
    cve_observations: dict[str, Any] | None = None,
    kev_catalog: dict[str, Any] | None = None,
    product_observations: dict[str, Any] | None = None,
    exposure_observations: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Query public sources for a domain only when the user explicitly confirms authorization."""
    feed = ThreatFeed.model_validate(threat_feed) if threat_feed is not None else None
    if (cve_observations is None and product_observations is None) != (kev_catalog is None):
        raise ValueError("Provide CVE or product observations and kev_catalog")
    observations = (
        Observations.model_validate(cve_observations) if cve_observations is not None else None
    )
    catalog = Catalog.model_validate(kev_catalog) if kev_catalog is not None else None
    products = (
        ProductObservations.model_validate(product_observations)
        if product_observations is not None
        else None
    )
    exposures = (
        ExposureObservations.model_validate(exposure_observations)
        if exposure_observations is not None
        else None
    )
    snapshot = collect_live(domain, authorized=authorized, max_assets=max_assets)
    report = analyze(snapshot, max_assets=max_assets, collection_mode="live", threat_feed=feed)
    if observations is not None and catalog is not None:
        correlate(report, observations, catalog)
    if products is not None and catalog is not None:
        correlate_products(report, products, catalog)
    if exposures is not None:
        correlate_exposures(report, exposures)
    return report.as_dict()


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
