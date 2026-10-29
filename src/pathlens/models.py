"""Validated input and output contracts shared by the CLI and MCP server."""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def normalize_name(value: str) -> str:
    """Return an ASCII DNS name, rejecting URLs, wildcards, and IP addresses."""
    if not isinstance(value, str) or value != value.strip() or not value:
        raise ValueError("expected a domain name without whitespace")
    try:
        name = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("invalid domain name") from exc
    if len(name) > 253 or len(name.split(".")) < 2:
        raise ValueError("expected a fully qualified domain name")
    if any(not _LABEL.fullmatch(label) for label in name.split(".")):
        raise ValueError("invalid domain label")
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    raise ValueError("expected a domain name, not an IP address")


def in_scope(name: str, domain: str) -> bool:
    return name == domain or name.endswith("." + domain)


def utc_now() -> datetime:
    return datetime.now(UTC)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CertificateRecord(BaseModel):
    # Keep certificate IDs for verifiable references; ignore unrelated crt.sh fields.
    model_config = ConfigDict(extra="ignore")
    name_value: str = Field(max_length=100_000)
    id: int | None = Field(default=None, ge=1)


class DNSRecord(StrictModel):
    name: str
    record_type: Literal["CNAME", "A", "AAAA"]
    status: Literal["answer", "nxdomain", "nodata", "timeout", "error"]
    values: list[str] = Field(default_factory=list, max_length=100)
    observed_at: datetime = Field(default_factory=utc_now)
    resolver: str = Field(default="1.1.1.1", max_length=100)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return normalize_name(value)

    @field_validator("observed_at")
    @classmethod
    def timestamp_has_timezone(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_values(self) -> DNSRecord:
        if self.status == "answer" and not self.values:
            raise ValueError("answer requires at least one value")
        if self.status != "answer" and self.values:
            raise ValueError("non-answer status cannot contain values")
        if self.record_type == "CNAME":
            if len(self.values) > 1:
                raise ValueError("CNAME has at most one value")
            self.values = [normalize_name(value) for value in self.values]
        else:
            expected_version = 4 if self.record_type == "A" else 6
            for value in self.values:
                if ipaddress.ip_address(value).version != expected_version:
                    raise ValueError(f"{self.record_type} value has the wrong IP version")
        return self


class AWSRange(BaseModel):
    model_config = ConfigDict(extra="ignore")
    ip_prefix: str | None = None
    ipv6_prefix: str | None = None
    region: str = Field(max_length=100)
    service: str = Field(max_length=100)

    @model_validator(mode="after")
    def validate_prefix(self) -> AWSRange:
        if (self.ip_prefix is None) == (self.ipv6_prefix is None):
            raise ValueError("exactly one IP prefix is required")
        value = self.ip_prefix or self.ipv6_prefix
        network = ipaddress.ip_network(value, strict=True)
        if (self.ip_prefix is not None and network.version != 4) or (
            self.ipv6_prefix is not None and network.version != 6
        ):
            raise ValueError("IP prefix has the wrong version")
        return self


class AWSRanges(BaseModel):
    model_config = ConfigDict(extra="ignore")
    syncToken: str | None = None
    createDate: str | None = None
    prefixes: list[AWSRange] = Field(default_factory=list, max_length=100_000)
    ipv6_prefixes: list[AWSRange] = Field(default_factory=list, max_length=100_000)


class Snapshot(StrictModel):
    """Raw source observations; does not itself claim ownership or exposure."""

    schema_version: Literal["1.0"] = "1.0"
    domain: str
    observed_at: datetime = Field(default_factory=utc_now)
    certificates: list[CertificateRecord] = Field(default_factory=list, max_length=100_000)
    dns_records: list[DNSRecord] = Field(default_factory=list, max_length=20_000)
    aws_ip_ranges: AWSRanges | None = None
    warnings: list[str] = Field(default_factory=list, max_length=1_000)

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        return normalize_name(value)

    @field_validator("observed_at")
    @classmethod
    def timestamp_has_timezone(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        return value


class Evidence(StrictModel):
    source: Literal["user-input", "crt.sh", "dns", "aws-ip-ranges", "service-reference"]
    description: str
    observed_at: datetime | None = None
    reference: str | None = None


class Finding(StrictModel):
    rule_id: str
    priority: Literal["high", "medium", "low", "info"]
    title: str
    explanation: str
    action: str
    evidence: list[Evidence] = Field(min_length=1)


class ThreatContext(StrictModel):
    id: str
    title: str
    description: str
    applicability: str
    action: str
    limitations: str
    source_name: str
    source_url: str
    reviewed_at: str
    matched_rule_id: str


class IndicatorMatch(StrictModel):
    indicator_id: str
    indicator_type: Literal["domain", "ip"]
    value: str
    observed_as: Literal["asset_name", "cname_target", "address"]
    status: Literal["active", "expired", "not_yet_valid"]
    source_name: str
    source_url: str
    description: str
    valid_from: datetime
    valid_until: datetime
    evidence: list[Evidence] = Field(min_length=1)


class ThreatFeedSummary(StrictModel):
    status: Literal["not_supplied", "loaded"]
    source_name: str | None = None
    source_url: str | None = None
    generated_at: datetime | None = None
    indicator_count: int = 0
    match_count: int = 0


class Asset(StrictModel):
    name: str
    discovered_by: list[str]
    discovery_evidence: list[Evidence] = Field(min_length=1)
    cname_chain: list[str]
    addresses: list[str]
    priority: Literal["high", "medium", "low", "info", "unknown"]
    findings: list[Finding]
    warnings: list[str] = Field(default_factory=list)
    threat_context: list[ThreatContext] = Field(default_factory=list)
    indicator_matches: list[IndicatorMatch] = Field(default_factory=list)


class Report(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    domain: str
    observed_at: datetime
    generated_at: datetime = Field(default_factory=utc_now)
    collection_mode: Literal["snapshot", "live"]
    assets: list[Asset]
    warnings: list[str]
    limitations: list[str]
    threat_feed: ThreatFeedSummary = Field(
        default_factory=lambda: ThreatFeedSummary(status="not_supplied")
    )

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
