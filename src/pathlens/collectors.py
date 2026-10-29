"""Public-source collection. No HTTP connection is made to discovered assets."""

from __future__ import annotations

import json
from typing import Any

import dns.exception
import dns.resolver
import httpx
from pydantic import ValidationError

from .analysis import MAX_ASSETS, MAX_CNAME_HOPS, discover_names
from .models import AWSRanges, CertificateRecord, DNSRecord, Snapshot, normalize_name

CRT_URL = "https://crt.sh/"
AWS_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
DNS_RESOLVER = "1.1.1.1"
MAX_HTTP_BYTES = 25 * 1024 * 1024


class CollectionError(Exception):
    """A required public source could not be collected safely."""


def _read_json(client: httpx.Client, url: str, params: dict[str, str] | None = None) -> Any:
    chunks: list[bytes] = []
    size = 0
    try:
        with client.stream("GET", url, params=params, follow_redirects=False) as response:
            response.raise_for_status()
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > MAX_HTTP_BYTES:
                    raise CollectionError(f"Public source response exceeded {MAX_HTTP_BYTES} bytes")
                chunks.append(chunk)
        return json.loads(b"".join(chunks))
    except (httpx.HTTPError, ValueError) as exc:
        raise CollectionError(
            f"Public source unavailable or invalid: {url}: {type(exc).__name__}"
        ) from exc


def _dns_query(resolver: dns.resolver.Resolver, name: str, record_type: str) -> DNSRecord:
    status: str
    values: list[str] = []
    try:
        answer = resolver.resolve(name, record_type, raise_on_no_answer=True, search=False)
        values = [str(item).rstrip(".") for item in answer]
        status = "answer"
    except dns.resolver.NXDOMAIN:
        status = "nxdomain"
    except dns.resolver.NoAnswer:
        status = "nodata"
    except dns.exception.Timeout:
        status = "timeout"
    except (dns.exception.DNSException, OSError):
        status = "error"
    try:
        return DNSRecord(
            name=name, record_type=record_type, status=status, values=values, resolver=DNS_RESOLVER
        )
    except (ValidationError, ValueError):
        return DNSRecord(name=name, record_type=record_type, status="error", resolver=DNS_RESOLVER)


def collect_dns(names: list[str], resolver: dns.resolver.Resolver | None = None) -> list[DNSRecord]:
    if resolver is None:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [DNS_RESOLVER]
        resolver.timeout = 2.0
        resolver.lifetime = 4.0
    cache: dict[tuple[str, str], DNSRecord] = {}

    def query(name: str, kind: str) -> DNSRecord:
        key = (name, kind)
        if key not in cache:
            cache[key] = _dns_query(resolver, name, kind)
        return cache[key]

    for name in names:
        current = normalize_name(name)
        seen: set[str] = set()
        for _ in range(MAX_CNAME_HOPS + 1):
            if current in seen:
                break
            seen.add(current)
            record = query(current, "CNAME")
            if record.status == "answer":
                current = record.values[0]
                continue
            if record.status == "nodata":
                query(current, "A")
                query(current, "AAAA")
            break
    return list(cache.values())


def collect_live(domain: str, *, authorized: bool, max_assets: int = 100) -> Snapshot:
    if not authorized:
        raise CollectionError(
            "Live collection requires explicit authorization for the target domain."
        )
    if not 1 <= max_assets <= MAX_ASSETS:
        raise ValueError(f"max_assets must be between 1 and {MAX_ASSETS}")
    domain = normalize_name(domain)
    warnings: list[str] = []
    # No redirects or arbitrary URLs: the only HTTPS endpoints are the two public providers.
    with httpx.Client(timeout=15.0, follow_redirects=False, trust_env=False) as client:
        raw_certificates = _read_json(client, CRT_URL, {"q": f"%.{domain}", "output": "json"})
        if not isinstance(raw_certificates, list):
            raise CollectionError("crt.sh did not return a JSON list")
        try:
            certificates = [CertificateRecord.model_validate(item) for item in raw_certificates]
        except ValidationError as exc:
            raise CollectionError("crt.sh returned an invalid certificate record") from exc
        try:
            aws_ranges = AWSRanges.model_validate(_read_json(client, AWS_RANGES_URL))
        except (CollectionError, ValidationError) as exc:
            aws_ranges = None
            warnings.append(
                f"AWS IP ranges unavailable: {type(exc).__name__}; IP matching skipped."
            )

    snapshot = Snapshot(
        domain=domain, certificates=certificates, aws_ip_ranges=aws_ranges, warnings=warnings
    )
    names, limit_warnings = discover_names(snapshot, max_assets)
    snapshot.dns_records = collect_dns(list(names))
    snapshot.warnings.extend(limit_warnings)
    return snapshot
