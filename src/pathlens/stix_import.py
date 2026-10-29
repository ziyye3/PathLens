"""Conservative STIX 2.1 indicator import, not a general STIX parser."""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from .threat_intel import Indicator, Source, ThreatFeed

_CLAUSE = re.compile(r"^(domain-name|ipv4-addr|ipv6-addr):value = '([^'\\]+)'$")
_IN_CLAUSE = re.compile(r"^(domain-name|ipv4-addr|ipv6-addr):value IN \((.+)\)$")
_IN_VALUE = re.compile(r"^'([^'\\]+)'$")
_INDICATOR_ID = re.compile(
    r"^indicator--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


def _supported_clauses(pattern: Any) -> list[tuple[str, str]]:
    if not isinstance(pattern, str) or not pattern.startswith("[") or not pattern.endswith("]"):
        return []
    in_clause = _IN_CLAUSE.fullmatch(pattern[1:-1])
    if in_clause:
        parts = [part.strip() for part in in_clause.group(2).split(",")]
        if len(parts) > 100:
            raise ValueError("STIX IN pattern exceeds the 100 alternative limit")
        values = [_IN_VALUE.fullmatch(part) for part in parts]
        if not all(values):
            return []
        return [(in_clause.group(1), value.group(1)) for value in values]
    parts = pattern[1:-1].split(" OR ")
    if len(parts) > 100:
        raise ValueError("STIX OR pattern exceeds the 100 alternative limit")
    matches = [_CLAUSE.fullmatch(part) for part in parts]
    if not all(matches):
        return []
    return [(match.group(1), match.group(2)) for match in matches]


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
        clauses = _supported_clauses(pattern)
        if obj.get("revoked") is True or obj.get("spec_version") != "2.1" or not clauses:
            skipped += 1
            continue
        if obj.get("pattern_type") != "stix":
            skipped += 1
            continue
        for kind, value in clauses:
            if kind != "domain-name":
                try:
                    version = ipaddress.ip_address(value).version
                except ValueError as exc:
                    raise ValueError("Invalid STIX IP value") from exc
                if version != (4 if kind == "ipv4-addr" else 6):
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
        for index, (kind, value) in enumerate(clauses, start=1):
            if len(indicators) >= 100_000:
                raise ValueError("STIX converted indicator limit exceeded")
            indicators.append(
                Indicator(
                    id=identifier if len(clauses) == 1 else f"{identifier}#or-{index}",
                    type="domain" if kind == "domain-name" else "ip",
                    value=value,
                    description=description,
                    valid_from=start,
                    valid_until=end,
                )
            )
    return ThreatFeed(
        schema_version="1.0", source=source, generated_at=now, indicators=indicators
    ), skipped
