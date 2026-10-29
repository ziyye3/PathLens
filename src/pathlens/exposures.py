"""Correlate minimal user-supplied exposure claims without importing leaked content."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator

from .models import (
    ExposureClaim,
    ExposureSummary,
    Report,
    StrictModel,
    in_scope,
    normalize_name,
)
from .threat_intel import validate_https_url, validate_text


class ExposureObservation(StrictModel):
    asset: str
    category: Literal["credential_exposure", "data_leak_claim"]
    source_name: str = Field(min_length=1, max_length=200)
    source_url: str = Field(min_length=1, max_length=2048)
    observed_at: datetime

    _name = field_validator("asset")(normalize_name)
    _source_name = field_validator("source_name")(validate_text)

    @field_validator("source_url")
    @classmethod
    def safe_reference(cls, value: str) -> str:
        validate_https_url(value)
        parts = urlsplit(value)
        if parts.query or parts.fragment:
            raise ValueError("Exposure reference cannot contain a query or fragment")
        return value

    @field_validator("observed_at")
    @classmethod
    def timezone_required(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        return value


class ExposureObservations(StrictModel):
    schema_version: Literal["1.0"]
    observations: list[ExposureObservation] = Field(max_length=20_000)


def correlate_exposures(report: Report, observations: ExposureObservations) -> None:
    assets = {asset.name: asset for asset in report.assets}
    results: dict[str, list[ExposureClaim]] = {name: [] for name in assets}
    missing = 0
    for item in observations.observations:
        if not in_scope(item.asset, report.domain):
            raise ValueError("Exposure claim asset is outside the requested domain")
        if item.asset not in assets:
            missing += 1
            continue
        results[item.asset].append(ExposureClaim(**item.model_dump(exclude={"asset"})))
    for name, asset in assets.items():
        asset.exposure_claims = results[name]
    if missing:
        report.warnings.append(
            f"{missing} exposure claims refer to assets not discovered in this run."
        )
    report.exposure_correlation = ExposureSummary(
        status="loaded",
        observation_count=len(observations.observations),
        match_count=sum(len(asset.exposure_claims) for asset in report.assets),
    )
    limitation = (
        "Exposure claims are supplied by the user and not independently verified; "
        "PathLens does not collect leaked content or verify a compromise."
    )
    if limitation not in report.limitations:
        report.limitations.append(limitation)
