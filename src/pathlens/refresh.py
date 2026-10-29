"""Foreground feed refresh; never installs a background service."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from .collectors import CollectionError
from .feodo import fetch_feodo
from .threat_intel import ThreatFeed


def watch_feodo(
    directory: Path,
    interval: int,
    *,
    cycles: int = 0,
    fetch: Callable[[], ThreatFeed] = fetch_feodo,
    wait: Callable[[float], None] = time.sleep,
    notify: Callable[[str], None] = print,
) -> None:
    if interval < 300 or cycles < 0:
        raise ValueError("interval must be at least 300 seconds and cycles nonnegative")
    if not directory.is_dir():
        raise ValueError("Output directory must already exist")
    count = 0
    while not cycles or count < cycles:
        count += 1
        try:
            feed = fetch()
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
            output = directory / f"feodo-{stamp}.json"
            with output.open("x", encoding="utf-8") as handle:
                handle.write(feed.model_dump_json(indent=2) + "\n")
            notify(f"Saved {len(feed.indicators)} indicators to {output}")
        except CollectionError as exc:
            notify(f"Feed refresh failed; existing snapshots kept: {exc}")
        if not cycles or count < cycles:
            wait(interval)
