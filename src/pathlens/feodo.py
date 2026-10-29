"""Convert a user-requested Feodo Tracker snapshot into PathLens indicators."""

from __future__ import annotations

import hashlib
import ipaddress
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from .collectors import CollectionError, _read_json
from .threat_intel import Indicator, Source, ThreatFeed

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"


def convert_feodo(data: Any, *, fetched_at: datetime) -> ThreatFeed:
    if not isinstance(data, list) or len(data) > 100_000:
        raise ValueError("Feodo response must be a list with at most 100000 entries")
    indicators: list[Indicator] = []
    seen: set[str] = set()
    for row in data:
        if not isinstance(row, dict):
            raise ValueError("Invalid Feodo entry")
        try:
            ip = str(ipaddress.ip_address(row["ip_address"]))
            first_seen = datetime.strptime(row["first_seen"], "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=UTC
            )
            port = int(row["port"])
            if not 1 <= port <= 65535 or first_seen > fetched_at:
                raise ValueError("Invalid port or future first_seen")
            status, family, last_online = (
                str(row.get(key) or "unknown")[:100] for key in ("status", "malware", "last_online")
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("Invalid Feodo entry") from exc
        key = f"{ip}|{port}|{family}"
        if key in seen:
            continue
        seen.add(key)
        digest = hashlib.sha256(key.encode()).hexdigest()[:24]
        indicators.append(
            Indicator(
                id=f"feodo-{digest}",
                type="ip",
                value=ip,
                description=(
                    f"Feodo reports port {port}, family {family}, status {status}, "
                    f"last online {last_online}. IP match does not prove current activity."
                ),
                valid_from=first_seen,
                valid_until=fetched_at + timedelta(hours=24),
            )
        )
    return ThreatFeed(
        schema_version="1.0",
        source=Source(name="Feodo Tracker recommended IP list", url=FEODO_URL),
        generated_at=fetched_at,
        indicators=indicators,
    )


def fetch_feodo() -> ThreatFeed:
    with httpx.Client(timeout=15.0, follow_redirects=False, trust_env=False) as client:
        data = _read_json(client, FEODO_URL)
    try:
        return convert_feodo(data, fetched_at=datetime.now(UTC))
    except ValueError as exc:
        raise CollectionError("Feodo returned an invalid indicator list") from exc
