"""Bounded, opt-in STIX pattern evaluation against explicit observations.

This is separate from the exact-IOC feed: complex patterns must not be flattened.
"""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from .models import Snapshot, in_scope, normalize_name

_ID = re.compile(r"^[a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_SCO_TYPES = {"domain-name", "ipv4-addr", "ipv6-addr"}
_MAX_INDICATORS = 20
_MAX_OBJECTS = 125
_MAX_WORKER_RSS = 256 * 1024 * 1024
_SNAPSHOT_NAMESPACE = uuid.UUID("cb6bf8b0-6188-4386-95c2-2c20f37c8084")


def snapshot_observations(snapshot: Snapshot) -> tuple[dict, dict[str, int]]:
    """Represent each in-scope DNS answer as one observation, not an attack event."""
    objects: list[dict] = []
    scos: dict[str, dict] = {}
    source_indexes: dict[str, int] = {}
    for index, record in enumerate(snapshot.dns_records):
        if record.status != "answer" or not in_scope(record.name, snapshot.domain):
            continue
        if len(source_indexes) >= 25:
            raise ValueError("STIX observation limit exceeded; provide at most 25 DNS answers")
        values = [("domain-name", record.name)]
        for value in record.values:
            kind = {"CNAME": "domain-name", "A": "ipv4-addr", "AAAA": "ipv6-addr"}[
                record.record_type
            ]
            values.append((kind, value))
        refs = []
        for kind, value in values:
            if kind != "domain-name":
                value = str(ipaddress.ip_address(value))
            identifier = f"{kind}--{uuid.uuid5(_SNAPSHOT_NAMESPACE, f'{kind}:{value}')}"
            scos[identifier] = {"type": kind, "id": identifier, "value": value}
            if identifier not in refs:
                refs.append(identifier)
        timestamp = record.observed_at.astimezone(UTC).isoformat().replace("+00:00", "Z")
        seed = f"{snapshot.domain}:{index}:{timestamp}"
        obs_id = f"observed-data--{uuid.uuid5(_SNAPSHOT_NAMESPACE, seed)}"
        source_indexes[obs_id] = index
        objects.append({
            "type": "observed-data", "id": obs_id, "first_observed": timestamp,
            "last_observed": timestamp, "number_observed": 1, "object_refs": refs,
        })
    return {"type": "bundle", "objects": [*objects, *scos.values()]}, source_indexes


def _run_worker(payload: dict, timeout: float) -> tuple[str, str | None]:
    # macOS does not support a reliable RLIMIT_AS; monitor RSS as a best-effort cap.
    import psutil

    process = subprocess.Popen(
        [sys.executable, "-m", "pathlens._stix_worker"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
    )
    deadline = time.monotonic() + timeout
    data = json.dumps(payload)
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return "", "evaluation timed out"
            try:
                stdout, _ = process.communicate(input=data, timeout=min(0.05, remaining))
                return (stdout, None) if process.returncode == 0 else ("", "evaluation failed")
            except subprocess.TimeoutExpired:
                data = None
                try:
                    if psutil.Process(process.pid).memory_info().rss > _MAX_WORKER_RSS:
                        return "", "evaluation memory limit exceeded"
                except psutil.NoSuchProcess:
                    pass
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("STIX observation and indicator timestamps must be strings")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Invalid STIX timestamp") from exc
    if parsed.utcoffset() is None:
        raise ValueError("STIX timestamps must include a timezone")
    return parsed


def _bundle(document: Any, limit: int) -> list[dict]:
    if not isinstance(document, dict) or document.get("type") != "bundle":
        raise ValueError("Expected a STIX bundle")
    objects = document.get("objects")
    if not isinstance(objects, list) or len(objects) > limit:
        raise ValueError("STIX bundle exceeds the object limit or has invalid objects")
    seen = set()
    for item in objects:
        if not isinstance(item, dict):
            raise ValueError("Invalid STIX object")
        if item.get("object_marking_refs") or item.get("granular_markings"):
            raise ValueError("Marked STIX content requires handling controls; evaluation refused")
        identifier = item.get("id")
        if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
            raise ValueError("Invalid STIX object id")
        if not identifier.startswith(f"{item.get('type')}--") or identifier in seen:
            raise ValueError("Duplicate STIX id or type/id mismatch")
        seen.add(identifier)
    return objects


def _observations(document: Any) -> tuple[list[dict], dict[str, dict]]:
    objects = _bundle(document, _MAX_OBJECTS)
    observed = []
    scos = {}
    for item in objects:
        kind = item.get("type")
        if kind == "observed-data":
            first = _timestamp(item.get("first_observed"))
            last = _timestamp(item.get("last_observed"))
            if first != last or item.get("number_observed") != 1:
                raise ValueError("Only individual observations with exact timestamps are supported")
            refs = item.get("object_refs")
            if not isinstance(refs, list) or not 1 <= len(refs) <= 10:
                raise ValueError("Each observation needs 1 to 10 object references")
            if not all(isinstance(ref, str) for ref in refs) or len(set(refs)) != len(refs):
                raise ValueError("Invalid or duplicate observation references")
            observed.append(item)
        elif kind in _SCO_TYPES:
            if set(item) - {"type", "id", "spec_version", "value"}:
                raise ValueError("Only simple domain and IP observables are supported")
            value = item.get("value")
            if not isinstance(value, str):
                raise ValueError("Observable value must be a string")
            if kind == "domain-name":
                normalize_name(value)
            else:
                try:
                    version = ipaddress.ip_address(value).version
                except ValueError as exc:
                    raise ValueError("Invalid observable IP address") from exc
                if version != (4 if kind == "ipv4-addr" else 6):
                    raise ValueError("Observable IP type does not match its value")
            scos[item["id"]] = item
        else:
            raise ValueError("Unsupported object in observations bundle")
    if len(observed) > 25:
        raise ValueError("STIX observation limit exceeded")
    if any(ref not in scos for item in observed for ref in item["object_refs"]):
        raise ValueError("Observation contains an unresolved object reference")
    return observed, scos


def evaluate_stix(
    indicators: Any,
    observations: Any,
    *,
    indicator_ids: list[str] | None = None,
    timeout: float = 5.0,
) -> dict:
    """Evaluate patterns with a separate resource-limited worker per indicator.

    Results apply only to provided observations, not to all activity on an asset.
    """
    indicator_objects = [
        item for item in _bundle(indicators, 100_000) if item.get("type") == "indicator"
    ]
    if indicator_ids:
        requested = set(indicator_ids)
        if not requested.issubset({item["id"] for item in indicator_objects}):
            raise ValueError("Selected indicator was not found")
        indicator_objects = [item for item in indicator_objects if item["id"] in requested]
    if len(indicator_objects) > _MAX_INDICATORS:
        raise ValueError("STIX indicator limit exceeded; select at most 20 indicators")
    observed, scos = _observations(observations)
    results = []
    for indicator in indicator_objects:
        identifier = indicator["id"]
        base = {"indicator_id": identifier, "observation_ids": []}
        if (
            indicator.get("type") != "indicator"
            or indicator.get("spec_version") != "2.1"
            or indicator.get("pattern_type") != "stix"
            or indicator.get("revoked", False) is not False
        ):
            results.append({**base, "status": "indeterminate", "reason": "unsupported indicator"})
            continue
        pattern = indicator.get("pattern")
        if not isinstance(pattern, str) or not pattern or len(pattern) > 4096:
            results.append({**base, "status": "indeterminate", "reason": "invalid pattern"})
            continue
        try:
            start = _timestamp(indicator.get("valid_from"))
            end = _timestamp(indicator["valid_until"]) if "valid_until" in indicator else None
            if end is not None and end <= start:
                raise ValueError("Invalid indicator validity interval")
        except ValueError:
            results.append({**base, "status": "indeterminate", "reason": "invalid validity"})
            continue
        eligible = [
            item for item in observed
            if _timestamp(item["first_observed"]) >= start
            and (end is None or _timestamp(item["first_observed"]) < end)
        ]
        now = datetime.now(UTC)
        base["indicator_status"] = (
            "not_yet_valid" if now < start else "expired" if end and now >= end else "active"
        )
        # Do not turn a lack of usable evidence into a confident negative.
        if not eligible:
            results.append(
                {**base, "status": "indeterminate", "reason": "no eligible observations"}
            )
            continue
        refs = {ref for item in eligible for ref in item["object_refs"]}
        payload = {"pattern": pattern, "objects": [*eligible, *(scos[ref] for ref in sorted(refs))]}
        stdout, error = _run_worker(payload, timeout)
        if error:
            results.append({**base, "status": "indeterminate", "reason": error})
            continue
        try:
            result = json.loads(stdout)
            if result.get("status") not in {"matched", "not_matched", "indeterminate"}:
                raise ValueError("Invalid worker result")
            ids = result.get("observation_ids", [])
            eligible_ids = {item["id"] for item in eligible}
            if not isinstance(ids, list) or any(item not in eligible_ids for item in ids):
                raise ValueError("Invalid observation IDs")
            results.append({**base, **result})
        except (ValueError, TypeError, AttributeError):
            results.append({**base, "status": "indeterminate", "reason": "invalid worker result"})
    return {"scope": "supplied observations only", "results": results}
