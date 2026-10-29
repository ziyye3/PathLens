"""Turn public observations into review candidates with traceable evidence."""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from importlib.resources import files
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .models import Asset, DNSRecord, Evidence, Finding, Report, Snapshot, in_scope, normalize_name

MAX_ASSETS = 200
MAX_CNAME_HOPS = 8
PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3, "unknown": 4}


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    predicate: Literal["dangling_known_service", "known_service", "aws_infrastructure"]
    priority: Literal["high", "medium", "low", "info"]
    title: str
    explanation: str
    action: str


class RuleSet(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal[1]
    rules: list[Rule] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def unique_ids(self) -> RuleSet:
        if len({rule.id for rule in self.rules}) != len(self.rules):
            raise ValueError("rule ids must be unique")
        return self


class Service(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    suffixes: list[str]
    kind: Literal["suffix", "s3", "api_gateway"]
    review: bool
    reference: str


class ServiceSet(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal[1]
    services: list[Service]


def load_rules(path: Path | None = None) -> RuleSet:
    content = (
        path.read_text(encoding="utf-8")
        if path
        else (files("pathlens").joinpath("data/rules.yaml").read_text(encoding="utf-8"))
    )
    try:
        return RuleSet.model_validate(yaml.safe_load(content))
    except yaml.YAMLError as exc:
        raise ValueError("Invalid YAML rules file") from exc


def load_services() -> ServiceSet:
    content = files("pathlens").joinpath("data/services.yaml").read_text(encoding="utf-8")
    return ServiceSet.model_validate(yaml.safe_load(content))


def discover_names(snapshot: Snapshot, max_assets: int) -> tuple[dict[str, set[str]], list[str]]:
    if not 1 <= max_assets <= MAX_ASSETS:
        raise ValueError(f"max_assets must be between 1 and {MAX_ASSETS}")
    names: dict[str, set[str]] = defaultdict(set)
    names[snapshot.domain].add("user input")
    for certificate in snapshot.certificates:
        for raw_name in certificate.name_value.splitlines():
            # Wildcards are not actual observed hostnames and must not be converted into one.
            raw_name = raw_name.strip()
            if not raw_name or raw_name.startswith("*."):
                continue
            try:
                name = normalize_name(raw_name)
            except ValueError:
                continue
            if in_scope(name, snapshot.domain):
                names[name].add("crt.sh")
    for record in snapshot.dns_records:
        if in_scope(record.name, snapshot.domain):
            names[record.name].add("dns")
    # Keep the requested apex even if sorting would otherwise omit it.
    ordered = [snapshot.domain, *sorted(name for name in names if name != snapshot.domain)]
    warnings = []
    if len(ordered) > max_assets:
        warnings.append(f"Asset limit reached: analyzed {max_assets} of {len(ordered)} names.")
    return {name: names[name] for name in ordered[:max_assets]}, warnings


def service_matches(name: str, service: Service) -> bool:
    if service.kind == "s3":
        return bool(
            re.search(r"(?:^|\.)s3(?:(?:[.-]website)?[.-][a-z0-9-]+)?\.amazonaws\.com$", name)
        )
    if service.kind == "api_gateway":
        return bool(re.search(r"(?:^|\.)execute-api\.[a-z0-9-]+\.amazonaws\.com$", name))
    return any(name == suffix or name.endswith("." + suffix) for suffix in service.suffixes)


def build_chain(
    name: str, records: dict[str, list[DNSRecord]]
) -> tuple[list[str], list[DNSRecord], list[str]]:
    chain = [name]
    used: list[DNSRecord] = []
    warnings: list[str] = []
    for _ in range(MAX_CNAME_HOPS):
        answers = [
            r
            for r in records.get(chain[-1], [])
            if r.record_type == "CNAME" and r.status == "answer"
        ]
        targets = {value for record in answers for value in record.values}
        if not targets:
            break
        if len(targets) != 1:
            warnings.append(f"Conflicting CNAME answers for {chain[-1]}; path is incomplete.")
            break
        target = next(iter(targets))
        used.extend(answers)
        if target in chain:
            warnings.append(f"CNAME loop detected at {target}; path is incomplete.")
            break
        chain.append(target)
    else:
        warnings.append(f"CNAME path reached the {MAX_CNAME_HOPS}-hop limit.")
    return chain, used, warnings


def _dns_evidence(record: DNSRecord) -> Evidence:
    value = ", ".join(record.values) if record.values else record.status.upper()
    return Evidence(
        source="dns",
        description=f"{record.name} {record.record_type}: {value}; resolver {record.resolver}",
        observed_at=record.observed_at,
    )


def _finding(rule: Rule, evidence: list[Evidence]) -> Finding:
    return Finding(
        rule_id=rule.id,
        priority=rule.priority,
        title=rule.title,
        explanation=rule.explanation,
        action=rule.action,
        evidence=evidence,
    )


def analyze(
    snapshot: Snapshot,
    *,
    max_assets: int = 100,
    rules_path: Path | None = None,
    collection_mode: Literal["snapshot", "live"] = "snapshot",
) -> Report:
    rules = load_rules(rules_path).rules
    services = load_services().services
    names, limit_warnings = discover_names(snapshot, max_assets)
    records: dict[str, list[DNSRecord]] = defaultdict(list)
    for record in snapshot.dns_records:
        records[record.name].append(record)
    certificate_ids: dict[str, set[int]] = defaultdict(set)
    for certificate in snapshot.certificates:
        if certificate.id is None:
            continue
        for raw_name in certificate.name_value.splitlines():
            raw_name = raw_name.strip()
            if not raw_name or raw_name.startswith("*."):
                continue
            try:
                name = normalize_name(raw_name)
            except ValueError:
                continue
            if name in names:
                certificate_ids[name].add(certificate.id)

    networks = []
    if snapshot.aws_ip_ranges:
        for item in snapshot.aws_ip_ranges.prefixes + snapshot.aws_ip_ranges.ipv6_prefixes:
            networks.append((ipaddress.ip_network(item.ip_prefix or item.ipv6_prefix), item))

    assets: list[Asset] = []
    for name, sources in names.items():
        chain, cname_records, warnings = build_chain(name, records)
        discovery_evidence = []
        if "user input" in sources:
            discovery_evidence.append(
                Evidence(source="user-input", description=f"Requested domain: {name}")
            )
        if "crt.sh" in sources:
            ids = sorted(certificate_ids.get(name, set()))[:3]
            for certificate_id in ids or [None]:
                discovery_evidence.append(
                    Evidence(
                        source="crt.sh",
                        description=f"Name observed in certificate records: {name}",
                        observed_at=snapshot.observed_at,
                        reference=(
                            f"https://crt.sh/?id={certificate_id}"
                            if certificate_id is not None
                            else "https://crt.sh/"
                        ),
                    )
                )
        if "dns" in sources:
            discovery_evidence.append(_dns_evidence(records[name][0]))
        if not records.get(name):
            warnings.append("No DNS observations for this name; its status is unknown.")
        elif len(chain) > 1 and not records.get(chain[-1]):
            warnings.append(
                "No DNS observations for the final CNAME target; its status is unknown."
            )
        address_records = [
            record
            for hop in chain
            for record in records.get(hop, [])
            if record.record_type in ("A", "AAAA") and record.status == "answer"
        ]
        addresses = sorted({value for record in address_records for value in record.values})
        matches = [
            (hop, service)
            for hop in chain[1:]
            for service in services
            if service_matches(hop, service)
        ]
        review_matches = [(hop, service) for hop, service in matches if service.review]
        terminal_records = records.get(chain[-1], [])
        exists_evidence = any(record.status in ("answer", "nodata") for record in terminal_records)
        nx_records = [record for record in terminal_records if record.status == "nxdomain"]
        if exists_evidence and nx_records:
            warnings.append(
                "Contradictory DNS observations: NXDOMAIN and an existing name; "
                "no dangling claim made."
            )
        has_nxdomain = bool(nx_records) and not exists_evidence
        if any(
            record.status in ("timeout", "error")
            for hop in chain
            for record in records.get(hop, [])
        ):
            warnings.append("Some DNS queries failed or timed out; absence cannot be established.")

        ip_matches = []
        for record in address_records:
            for value in record.values:
                ip = ipaddress.ip_address(value)
                for network, item in networks:
                    if ip.version == network.version and ip in network:
                        ip_matches.append((record, value, network, item))
        findings: list[Finding] = []
        for rule in rules:
            if (
                rule.predicate == "dangling_known_service"
                and review_matches
                and has_nxdomain
                and not warnings
            ):
                hop, service = review_matches[0]
                evidence = [
                    *(_dns_evidence(record) for record in cname_records),
                    _dns_evidence(nx_records[0]),
                    Evidence(
                        source="service-reference",
                        description=f"{service.name}: {hop}",
                        reference=service.reference,
                    ),
                ]
                findings.append(_finding(rule, evidence))
            elif rule.predicate == "known_service" and review_matches:
                hop, service = review_matches[0]
                evidence = [
                    *(_dns_evidence(record) for record in cname_records),
                    Evidence(
                        source="service-reference",
                        description=f"{service.name}: {hop}",
                        reference=service.reference,
                    ),
                ]
                findings.append(_finding(rule, evidence))
            elif rule.predicate == "aws_infrastructure" and (matches or ip_matches):
                evidence = []
                if matches:
                    hop, service = matches[0]
                    evidence.extend(_dns_evidence(record) for record in cname_records)
                    evidence.append(
                        Evidence(
                            source="service-reference",
                            description=f"{service.name}: {hop}",
                            reference=service.reference,
                        )
                    )
                if ip_matches:
                    record, value, network, item = ip_matches[0]
                    ranges_date = snapshot.aws_ip_ranges.createDate or "unknown"
                    evidence.extend(
                        [
                            _dns_evidence(record),
                            Evidence(
                                source="aws-ip-ranges",
                                description=(
                                    f"{value} is in {network} ({item.service}, {item.region}); "
                                    f"AWS list date: {ranges_date}"
                                ),
                                reference="https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html",
                            ),
                        ]
                    )
                findings.append(_finding(rule, evidence))
        assets.append(
            Asset(
                name=name,
                discovered_by=sorted(sources),
                discovery_evidence=discovery_evidence,
                cname_chain=chain,
                addresses=addresses,
                priority=min(
                    (finding.priority for finding in findings),
                    key=PRIORITY_ORDER.__getitem__,
                    default="unknown",
                ),
                findings=findings,
                warnings=warnings,
            )
        )

    assets.sort(key=lambda asset: (PRIORITY_ORDER[asset.priority], asset.name))
    warnings = list(dict.fromkeys([*snapshot.warnings, *limit_warnings]))
    if snapshot.aws_ip_ranges is None:
        warnings.append("AWS IP ranges were not supplied; IP-based matches are unavailable.")
    return Report(
        domain=snapshot.domain,
        observed_at=snapshot.observed_at,
        collection_mode=collection_mode,
        assets=assets,
        warnings=warnings,
        limitations=[
            "Public DNS and certificates do not prove asset ownership or "
            "the existence of a vulnerability.",
            "A DNS candidate is not proof that a cloud resource can be claimed; "
            "no HTTP fingerprint is checked.",
            "Public recursive DNS lookups may be forwarded to authoritative name servers.",
            "AWS IP ranges do not cover every AWS address or prove the end customer; "
            "data may be stale.",
        ],
    )
