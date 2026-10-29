"""Validated threat context and opt-in indicator matching; never downloads a feed."""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import yaml
from pydantic import Field, field_validator, model_validator

from .models import (
    Evidence,
    IndicatorMatch,
    StrictModel,
    ThreatContext,
    ThreatFeedSummary,
    normalize_name,
)

MAX_FEED_BYTES = 25 * 1024 * 1024


def validate_https_url(value: str) -> str:
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("source_url cannot contain control characters")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("source_url must be an HTTPS URL without credentials")
    return value


def validate_text(value: str) -> str:
    if not value.strip() or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value):
        raise ValueError("text cannot be blank or contain control characters")
    return value


class Source(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    url: str = Field(min_length=1, max_length=2048)

    _url = field_validator("url")(validate_https_url)
    _name = field_validator("name")(validate_text)


class Indicator(StrictModel):
    id: str = Field(min_length=1, max_length=200)
    type: Literal["domain", "ip"]
    value: str = Field(min_length=1, max_length=253)
    description: str = Field(min_length=1, max_length=2000)
    valid_from: datetime
    valid_until: datetime

    _text = field_validator("id", "description")(validate_text)

    @model_validator(mode="after")
    def validate_indicator(self) -> Indicator:
        if self.valid_from.utcoffset() is None or self.valid_until.utcoffset() is None:
            raise ValueError("indicator timestamps must include a timezone")
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be later than valid_from")
        self.value = (
            normalize_name(self.value)
            if self.type == "domain"
            else str(ipaddress.ip_address(self.value))
        )
        return self


class ThreatFeed(StrictModel):
    schema_version: Literal["1.0"]
    source: Source
    generated_at: datetime
    indicators: list[Indicator] = Field(max_length=100_000)

    @model_validator(mode="after")
    def validate_feed(self) -> ThreatFeed:
        if self.generated_at.utcoffset() is None:
            raise ValueError("generated_at must include a timezone")
        if len({indicator.id for indicator in self.indicators}) != len(self.indicators):
            raise ValueError("indicator ids must be unique")
        return self


class ContextDefinition(StrictModel):
    id: str
    service: str
    rule_ids: list[str] = Field(min_length=1)
    title: str
    description: str
    applicability: str
    action: str
    limitations: str
    source_name: str
    source_url: str
    reviewed_at: str

    _url = field_validator("source_url")(validate_https_url)


class ContextCatalog(StrictModel):
    version: Literal[1]
    contexts: list[ContextDefinition] = Field(max_length=100)

    @model_validator(mode="after")
    def unique_ids(self) -> ContextCatalog:
        if len({context.id for context in self.contexts}) != len(self.contexts):
            raise ValueError("context ids must be unique")
        return self


def load_contexts() -> list[ContextDefinition]:
    content = files("pathlens").joinpath("data/threat_context.yaml").read_text(encoding="utf-8")
    return ContextCatalog.model_validate(yaml.safe_load(content)).contexts


def load_feed(path: Path) -> ThreatFeed:
    if path.stat().st_size > MAX_FEED_BYTES:
        raise ValueError("Threat feed exceeds 25 MiB")
    return ThreatFeed.model_validate_json(path.read_text(encoding="utf-8"))


def index_feed(feed: ThreatFeed | None) -> dict[tuple[str, str], list[Indicator]]:
    index: dict[tuple[str, str], list[Indicator]] = defaultdict(list)
    if feed:
        for indicator in feed.indicators:
            index[(indicator.type, indicator.value)].append(indicator)
    return index


def indicator_status(indicator: Indicator, observed_at: datetime, now: datetime) -> str:
    if observed_at < indicator.valid_from or now < indicator.valid_from:
        return "not_yet_valid"
    if observed_at >= indicator.valid_until or now >= indicator.valid_until:
        return "expired"
    return "active"


def match_indicators(
    observations: list[tuple[str, str, str, list[Evidence]]],
    feed: ThreatFeed | None,
    index: dict[tuple[str, str], list[Indicator]],
    observed_at: datetime,
    now: datetime | None = None,
) -> list[IndicatorMatch]:
    if not feed:
        return []
    now = now or datetime.now(UTC)
    results = []
    for indicator_type, value, observed_as, evidence in observations:
        for indicator in index.get((indicator_type, value), []):
            evidence_time = next(
                (item.observed_at for item in evidence if item.observed_at), observed_at
            )
            results.append(
                IndicatorMatch(
                    indicator_id=indicator.id,
                    indicator_type=indicator.type,
                    value=indicator.value,
                    observed_as=observed_as,
                    status=indicator_status(indicator, evidence_time, now),
                    source_name=feed.source.name,
                    source_url=feed.source.url,
                    description=indicator.description,
                    valid_from=indicator.valid_from,
                    valid_until=indicator.valid_until,
                    evidence=evidence,
                )
            )
    return results


def feed_summary(feed: ThreatFeed | None, match_count: int) -> ThreatFeedSummary:
    if not feed:
        return ThreatFeedSummary(status="not_supplied")
    return ThreatFeedSummary(
        status="loaded",
        source_name=feed.source.name,
        source_url=feed.source.url,
        generated_at=feed.generated_at,
        indicator_count=len(feed.indicators),
        match_count=match_count,
    )


def contexts_for_matches(
    definitions: list[ContextDefinition], services: set[str], rules: set[str]
) -> list[ThreatContext]:
    result = []
    for item in definitions:
        rule_id = next((rule for rule in item.rule_ids if rule in rules), None)
        if item.service not in services or rule_id is None:
            continue
        data = item.model_dump(exclude={"service", "rule_ids"})
        result.append(ThreatContext(**data, matched_rule_id=rule_id))
    return result
