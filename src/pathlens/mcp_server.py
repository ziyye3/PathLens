"""MCP stdio interface; results have the same contract as CLI JSON output."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from .analysis import analyze
from .collectors import collect_live
from .exposures import ExposureObservations, correlate_exposures
from .kev import Catalog, Observations, ProductObservations, correlate, correlate_products
from .models import Snapshot
from .osv import OSVSnapshot, PackageObservations, correlate_osv
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
    osv_observations: dict[str, Any] | None = None,
    osv_results: dict[str, Any] | None = None,
    stix_bundle: dict[str, Any] | None = None,
    stix_indicator_ids: list[str] | None = None,
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
    if (osv_observations is None) != (osv_results is None):
        raise ValueError("Provide both osv_observations and osv_results")
    packages = (
        PackageObservations.model_validate(osv_observations)
        if osv_observations is not None
        else None
    )
    osv_snapshot = OSVSnapshot.model_validate(osv_results) if osv_results is not None else None
    if stix_indicator_ids and stix_bundle is None:
        raise ValueError("stix_indicator_ids requires stix_bundle")
    parsed_snapshot = Snapshot.model_validate(snapshot)
    report = analyze(parsed_snapshot, max_assets=max_assets, threat_feed=feed)
    if stix_bundle is not None:
        from .stix_patterns import correlate_stix

        correlate_stix(report, parsed_snapshot, stix_bundle, indicator_ids=stix_indicator_ids)
    if observations is not None and catalog is not None:
        correlate(report, observations, catalog)
    if products is not None and catalog is not None:
        correlate_products(report, products, catalog)
    if exposures is not None:
        correlate_exposures(report, exposures)
    if packages is not None and osv_snapshot is not None:
        correlate_osv(report, packages, osv_snapshot, provenance="supplied")
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
    osv_observations: dict[str, Any] | None = None,
    osv_results: dict[str, Any] | None = None,
    stix_bundle: dict[str, Any] | None = None,
    stix_indicator_ids: list[str] | None = None,
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
    if (osv_observations is None) != (osv_results is None):
        raise ValueError("Provide both osv_observations and osv_results")
    packages = (
        PackageObservations.model_validate(osv_observations)
        if osv_observations is not None
        else None
    )
    osv_snapshot = OSVSnapshot.model_validate(osv_results) if osv_results is not None else None
    if stix_indicator_ids and stix_bundle is None:
        raise ValueError("stix_indicator_ids requires stix_bundle")
    snapshot = collect_live(domain, authorized=authorized, max_assets=max_assets)
    report = analyze(snapshot, max_assets=max_assets, collection_mode="live", threat_feed=feed)
    if stix_bundle is not None:
        from .stix_patterns import correlate_stix

        correlate_stix(report, snapshot, stix_bundle, indicator_ids=stix_indicator_ids)
    if observations is not None and catalog is not None:
        correlate(report, observations, catalog)
    if products is not None and catalog is not None:
        correlate_products(report, products, catalog)
    if exposures is not None:
        correlate_exposures(report, exposures)
    if packages is not None and osv_snapshot is not None:
        correlate_osv(report, packages, osv_snapshot, provenance="supplied")
    return report.as_dict()


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
