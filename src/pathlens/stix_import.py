"""Conservative STIX 2.1 indicator import, not a general STIX parser."""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from .threat_intel import Indicator, Source, ThreatFeed

_PATTERN = re.compile(r"^\[(domain-name|ipv4-addr|ipv6-addr):value = '([^'\\]+)'\]$")
_INDICATOR_ID = re.compile(
    r"^indicator--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


def import_stix(
    document: Any, source: Source, *, imported_at: datetime | None = None
) -> tuple[ThreatFeed, int]:
    if not isinstance(document, dict) or document.get("type") != "bundle":
        raise ValueError("Expected a STIX bundle")
    objects = document.get("objects")
    if not isinstance(objects, list) or len(objects) > 100_000:
        raise ValueError("STIX objects must be a list of at most 100000 objects")
    indicators: list[Indicator] = []
    skipped = 0
    seen: set[str] = set()
    now = imported_at or datetime.now(UTC)
    for obj in objects:
        if not isinstance(obj, dict):
            raise ValueError("Invalid STIX object")
        if obj.get("type") != "indicator":
            skipped += 1
            continue
        if obj.get("object_marking_refs") or obj.get("granular_markings"):
            raise ValueError("Marked STIX indicators require handling controls; import refused")
        identifier = obj.get("id")
        if not isinstance(identifier, str) or not _INDICATOR_ID.fullmatch(identifier):
            raise ValueError("Invalid STIX indicator id")
        if identifier in seen:
            raise ValueError("Duplicate STIX indicator id; resolve versions before importing")
        seen.add(identifier)
        if "revoked" in obj and not isinstance(obj["revoked"], bool):
            raise ValueError("Invalid STIX revoked status")
        pattern = obj.get("pattern")
        match = _PATTERN.fullmatch(pattern) if isinstance(pattern, str) else None
        if obj.get("revoked") is True or obj.get("spec_version") != "2.1" or not match:
            skipped += 1
            continue
        if obj.get("pattern_type") != "stix":
            skipped += 1
            continue
        if match.group(1) != "domain-name":
            try:
                version = ipaddress.ip_address(match.group(2)).version
            except ValueError as exc:
                raise ValueError("Invalid STIX IP value") from exc
            if version != (4 if match.group(1) == "ipv4-addr" else 6):
                raise ValueError("STIX IP type does not match its value")
        valid_from = obj.get("valid_from")
        if not isinstance(valid_from, str):
            raise ValueError("STIX indicator missing valid_from")
        try:
            start = datetime.fromisoformat(valid_from.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("Invalid STIX valid_from") from exc
        if start.utcoffset() is None:
            raise ValueError("STIX valid_from must include a timezone")
        end = obj.get("valid_until")
        note = ""
        if end is None:
            try:
                end = start + timedelta(days=30)
            except OverflowError as exc:
                raise ValueError("STIX validity exceeds supported timestamp range") from exc
            note = " No source expiration; PathLens applies a 30-day limit from valid_from."
        elif not isinstance(end, str):
            raise ValueError("Invalid STIX valid_until")
        description = str(obj.get("description") or obj.get("name") or "STIX indicator")
        description = " ".join(description.split())[:1800] + note
        indicators.append(
            Indicator(
                id=identifier,
                type="domain" if match.group(1) == "domain-name" else "ip",
                value=match.group(2),
                description=description,
                valid_from=start,
                valid_until=end,
            )
        )
    return ThreatFeed(
        schema_version="1.0", source=source, generated_at=now, indicators=indicators
    ), skipped
