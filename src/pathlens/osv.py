"""Opt-in package/version advisory queries without transmitting target asset names."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any, Literal

import httpx
from pydantic import Field, field_validator, model_validator

from .collectors import MAX_HTTP_BYTES, CollectionError
from .models import OSVMatch, OSVSummary, Report, StrictModel, in_scope, normalize_name
from .threat_intel import validate_https_url, validate_text

OSV_URL = "https://api.osv.dev/v1/query"
_ADVISORY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")


class PackageQuery(StrictModel):
    ecosystem: Literal["PyPI", "npm"]
    name: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=200)

    _text = field_validator("name", "version")(validate_text)


class PackageObservation(PackageQuery):
    asset: str
    source_url: str = Field(max_length=2048)
    evidence: str = Field(min_length=1, max_length=1000)

    _asset = field_validator("asset")(normalize_name)
    _source = field_validator("source_url")(validate_https_url)
    _evidence = field_validator("evidence")(validate_text)

    def query(self) -> PackageQuery:
        return PackageQuery(ecosystem=self.ecosystem, name=self.name, version=self.version)


class PackageObservations(StrictModel):
    schema_version: Literal["1.0"]
    observations: list[PackageObservation] = Field(min_length=1, max_length=25)


class Advisory(StrictModel):
    id: str = Field(min_length=1, max_length=200)
    summary: str = Field(default="", max_length=1000)
    aliases: list[str] = Field(default_factory=list, max_length=100)
    withdrawn: bool = False

    @field_validator("summary")
    @classmethod
    def summary_is_safe(cls, value: str) -> str:
        return validate_text(value) if value else value

    @field_validator("id")
    @classmethod
    def id_is_safe(cls, value: str) -> str:
        if not _ADVISORY_ID.fullmatch(value):
            raise ValueError("Invalid OSV advisory id")
        return value

    @field_validator("aliases")
    @classmethod
    def aliases_are_safe(cls, values: list[str]) -> list[str]:
        if any(not _ADVISORY_ID.fullmatch(value) for value in values):
            raise ValueError("Invalid OSV advisory alias")
        return values


class QueryResult(StrictModel):
    query: PackageQuery
    advisories: list[Advisory] = Field(max_length=500)


class OSVSnapshot(StrictModel):
    schema_version: Literal["1.0"]
    queried_at: datetime
    results: list[QueryResult] = Field(min_length=1, max_length=25)

    @model_validator(mode="after")
    def valid_snapshot(self) -> OSVSnapshot:
        if self.queried_at.utcoffset() is None:
            raise ValueError("queried_at must include a timezone")
        keys = [(r.query.ecosystem, r.query.name, r.query.version) for r in self.results]
        if len(keys) != len(set(keys)):
            raise ValueError("Duplicate OSV query result")
        return self


def _read_page(client: httpx.Client, query: PackageQuery, token: str | None) -> dict:
    payload: dict[str, Any] = {
        "package": {"ecosystem": query.ecosystem, "name": query.name},
        "version": query.version,
    }
    if token:
        payload["page_token"] = token
    try:
        with client.stream("POST", OSV_URL, json=payload, follow_redirects=False) as response:
            response.raise_for_status()
            chunks = []
            size = 0
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > MAX_HTTP_BYTES:
                    raise CollectionError("OSV response exceeds the size limit")
                chunks.append(chunk)
        page = json.loads(b"".join(chunks))
    except (httpx.HTTPError, ValueError) as exc:
        raise CollectionError(f"OSV query failed: {type(exc).__name__}") from exc
    if not isinstance(page, dict) or not isinstance(page.get("vulns", []), list):
        raise CollectionError("Invalid OSV response")
    return page


def fetch_query(client: httpx.Client, query: PackageQuery) -> QueryResult:
    token = None
    seen: set[str] = set()
    advisories: list[Advisory] = []
    advisory_ids: dict[str, Advisory] = {}
    for _ in range(10):
        page = _read_page(client, query, token)
        for item in page.get("vulns", []):
            if not isinstance(item, dict):
                raise CollectionError("Invalid OSV advisory")
            raw_text = str(item.get("summary") or "")
            safe_text = "".join(
                " " if ord(char) < 32 or 127 <= ord(char) <= 159 else char for char in raw_text
            )
            text = " ".join(safe_text.split())[:1000]
            withdrawal = item.get("withdrawn")
            if withdrawal is not None and (not isinstance(withdrawal, str) or not withdrawal):
                raise CollectionError("Invalid OSV withdrawal status")
            advisory = Advisory(
                id=item.get("id"),
                summary=text,
                aliases=item.get("aliases", []),
                withdrawn=withdrawal is not None,
            )
            previous = advisory_ids.get(advisory.id)
            if previous is not None:
                if previous != advisory:
                    raise CollectionError("Conflicting OSV advisory versions; query incomplete")
                continue
            advisory_ids[advisory.id] = advisory
            advisories.append(advisory)
            if len(advisories) > 500:
                raise CollectionError("OSV advisory limit exceeded; query incomplete")
        token = page.get("next_page_token")
        if token is None:
            return QueryResult(query=query, advisories=advisories)
        if not isinstance(token, str) or not token or len(token) > 1000 or token in seen:
            raise CollectionError("Invalid OSV pagination token; query incomplete")
        seen.add(token)
    raise CollectionError("OSV page limit reached; query incomplete")


def fetch_observations(observations: PackageObservations) -> OSVSnapshot:
    queries = {(o.ecosystem, o.name, o.version): o.query() for o in observations.observations}
    with httpx.Client(timeout=15.0, follow_redirects=False, trust_env=False) as client:
        results = [fetch_query(client, query) for query in queries.values()]
    return OSVSnapshot(schema_version="1.0", queried_at=datetime.now(UTC), results=results)


def correlate_osv(
    report: Report,
    observations: PackageObservations,
    snapshot: OSVSnapshot,
    *,
    provenance: Literal["live", "supplied"],
) -> None:
    assets = {asset.name: asset for asset in report.assets}
    results = {(r.query.ecosystem, r.query.name, r.query.version): r for r in snapshot.results}
    matches: dict[str, list[OSVMatch]] = {name: [] for name in assets}
    missing_assets = 0
    for item in observations.observations:
        if not in_scope(item.asset, report.domain):
            raise ValueError("Package observation asset is outside the requested domain")
        result = results.get((item.ecosystem, item.name, item.version))
        if result is None:
            raise ValueError("OSV snapshot does not contain all requested package queries")
        if item.asset not in assets:
            missing_assets += 1
            continue
        for advisory in result.advisories:
            matches[item.asset].append(
                OSVMatch(
                    advisory_id=advisory.id,
                    aliases=advisory.aliases,
                    ecosystem=item.ecosystem,
                    package_name=item.name,
                    version=item.version,
                    claimed_source=item.source_url,
                    claimed_evidence=item.evidence,
                    summary=advisory.summary,
                    withdrawn=advisory.withdrawn,
                    reference=f"https://osv.dev/vulnerability/{advisory.id}",
                )
            )
    for name, asset in assets.items():
        asset.osv_matches = matches[name]
    if missing_assets:
        report.warnings.append(
            f"{missing_assets} package observations refer to undiscovered assets."
        )
    report.osv_correlation = OSVSummary(
        status=provenance,
        query_count=len(snapshot.results),
        match_count=sum(len(asset.osv_matches) for asset in report.assets),
        queried_at=snapshot.queried_at,
    )
    limitation = (
        "Package deployment and version are user-supplied, not verified. OSV version queries "
        "may use fuzzy matching; advisory results do not prove the asset is vulnerable "
        "or compromised. "
        "An empty result does not establish safety."
    )
    if limitation not in report.limitations:
        report.limitations.append(limitation)
    if provenance == "supplied":
        report.limitations.append(
            "OSV-format results were supplied by the user and not independently verified."
        )
