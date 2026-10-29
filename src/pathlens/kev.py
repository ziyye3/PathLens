"""Match explicit asset-CVE observations against a supplied CISA KEV snapshot."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .collectors import _read_json
from .models import (
    CVECorrelationSummary,
    ProductCorrelationSummary,
    ProductKEVCandidate,
    Report,
    StrictModel,
    VulnerabilityMatch,
    in_scope,
    normalize_name,
)
from .threat_intel import MAX_FEED_BYTES, validate_https_url, validate_text

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_REFERENCE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
_CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,19}$")


class CVEObservation(StrictModel):
    asset: str
    cve_id: str
    source_url: str = Field(max_length=2048)
    evidence: str = Field(min_length=1, max_length=1000)

    _name = field_validator("asset")(normalize_name)
    _source = field_validator("source_url")(validate_https_url)
    _text = field_validator("evidence")(validate_text)

    @field_validator("cve_id")
    @classmethod
    def cve_format(cls, value: str) -> str:
        if not _CVE.fullmatch(value):
            raise ValueError("Invalid CVE identifier")
        return value


class Observations(StrictModel):
    schema_version: Literal["1.0"]
    observations: list[CVEObservation] = Field(max_length=20_000)


class ProductObservation(StrictModel):
    asset: str
    vendor: str = Field(min_length=1, max_length=200)
    product: str = Field(min_length=1, max_length=200)
    version: str | None = Field(default=None, min_length=1, max_length=200)
    source_url: str = Field(max_length=2048)
    evidence: str = Field(min_length=1, max_length=1000)

    _name = field_validator("asset")(normalize_name)
    _source = field_validator("source_url")(validate_https_url)
    _text = field_validator("vendor", "product", "evidence")(validate_text)

    @field_validator("version")
    @classmethod
    def valid_version(cls, value: str | None) -> str | None:
        return validate_text(value) if value is not None else None


class ProductObservations(StrictModel):
    schema_version: Literal["1.0"]
    observations: list[ProductObservation] = Field(max_length=20_000)


class KEVEntry(BaseModel):
    model_config = ConfigDict(extra="allow")
    cveID: str
    dateAdded: str
    shortDescription: str
    requiredAction: str
    vendorProject: str | None = None
    product: str | None = None

    @field_validator("cveID")
    @classmethod
    def cve_format(cls, value: str) -> str:
        if not _CVE.fullmatch(value):
            raise ValueError("Invalid catalog CVE identifier")
        return value


class Catalog(BaseModel):
    model_config = ConfigDict(extra="allow")
    catalogVersion: str = Field(min_length=1, max_length=100)
    dateReleased: str = Field(min_length=1, max_length=100)
    count: int = Field(ge=0, le=100_000)
    vulnerabilities: list[KEVEntry] = Field(max_length=100_000)

    @model_validator(mode="after")
    def check_catalog(self) -> Catalog:
        ids = [entry.cveID for entry in self.vulnerabilities]
        if self.count != len(ids) or len(set(ids)) != len(ids):
            raise ValueError("Catalog count mismatch or duplicate CVE")
        return self


def load_json(path: Path) -> Any:
    if path.stat().st_size > MAX_FEED_BYTES:
        raise ValueError("Input exceeds 25 MiB")
    return json.loads(path.read_text(encoding="utf-8"))


def fetch_catalog() -> Catalog:
    with httpx.Client(timeout=15.0, follow_redirects=False, trust_env=False) as client:
        data = _read_json(client, KEV_URL)
    return Catalog.model_validate(data)


def correlate(report: Report, observations: Observations, catalog: Catalog) -> None:
    assets = {asset.name: asset for asset in report.assets}
    entries = {entry.cveID: entry for entry in catalog.vulnerabilities}
    results: dict[str, list[VulnerabilityMatch]] = {name: [] for name in assets}
    missing = 0
    for observation in observations.observations:
        if not in_scope(observation.asset, report.domain):
            raise ValueError("CVE observation asset is outside the requested domain")
        asset = assets.get(observation.asset)
        if asset is None:
            missing += 1
            continue
        entry = entries.get(observation.cve_id)
        if entry:
            results[asset.name].append(
                VulnerabilityMatch(
                    cve_id=entry.cveID,
                    claimed_source=observation.source_url,
                    claimed_evidence=observation.evidence,
                    kev_catalog_version=catalog.catalogVersion,
                    kev_date_added=entry.dateAdded,
                    kev_description=entry.shortDescription,
                    kev_action=entry.requiredAction,
                    kev_reference=KEV_REFERENCE,
                )
            )
    for name, asset in assets.items():
        asset.vulnerability_matches = results[name]
    if missing:
        report.warnings.append(
            f"{missing} CVE observations refer to assets not discovered in this run."
        )
    report.cve_correlation = CVECorrelationSummary(
        status="loaded",
        catalog_version=catalog.catalogVersion,
        observation_count=len(observations.observations),
        match_count=sum(len(asset.vulnerability_matches) for asset in report.assets),
    )
    limitation = (
        "CVE-to-asset evidence and the catalog are supplied by the user; neither is independently "
        "verified. KEV inclusion does not prove this asset is affected or compromised."
    )
    if limitation not in report.limitations:
        report.limitations.append(limitation)


def _product_key(vendor: str, product: str) -> tuple[str, str]:
    return (" ".join(vendor.split()).casefold(), " ".join(product.split()).casefold())


def correlate_products(report: Report, observations: ProductObservations, catalog: Catalog) -> None:
    assets = {asset.name: asset for asset in report.assets}
    index: dict[tuple[str, str], list[KEVEntry]] = {}
    for entry in catalog.vulnerabilities:
        if entry.vendorProject and entry.product:
            index.setdefault(_product_key(entry.vendorProject, entry.product), []).append(entry)
    results: dict[str, list[ProductKEVCandidate]] = {name: [] for name in assets}
    missing = 0
    count = 0
    for item in observations.observations:
        if not in_scope(item.asset, report.domain):
            raise ValueError("Product observation asset is outside the requested domain")
        if item.asset not in assets:
            missing += 1
            continue
        for entry in index.get(_product_key(item.vendor, item.product), []):
            count += 1
            if count > 2_000:
                raise ValueError("Product-KEV candidate limit exceeded; narrow the inventory")
            results[item.asset].append(
                ProductKEVCandidate(
                    vendor=item.vendor,
                    product=item.product,
                    supplied_version=item.version,
                    claimed_source=item.source_url,
                    claimed_evidence=item.evidence,
                    cve_id=entry.cveID,
                    kev_catalog_version=catalog.catalogVersion,
                    kev_description=entry.shortDescription,
                    kev_reference=KEV_REFERENCE,
                )
            )
    for name, asset in assets.items():
        asset.product_kev_candidates = results[name]
    if missing:
        report.warnings.append(
            f"{missing} product observations refer to assets not discovered in this run."
        )
    report.product_correlation = ProductCorrelationSummary(
        status="loaded",
        catalog_version=catalog.catalogVersion,
        observation_count=len(observations.observations),
        candidate_count=count,
    )
    limitation = (
        "Product observations are user-supplied; exact vendor/product names are only candidate "
        "links. Versions, product deployment, vulnerability and compromise are not verified."
    )
    if limitation not in report.limitations:
        report.limitations.append(limitation)
