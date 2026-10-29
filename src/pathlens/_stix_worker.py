"""Internal worker; never prints source objects or exception details."""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime


def main() -> None:
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
        if sys.platform.startswith("linux"):
            resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
        from stix2matcher.matcher import Pattern

        payload = json.load(sys.stdin)
        pattern = Pattern(payload["pattern"], stix_version="2.1")
        inspection = pattern.inspect()
        comparisons = inspection.comparisons
        supported = {"domain-name", "ipv4-addr", "ipv6-addr"}
        if not comparisons or any(
            kind not in supported or any(path != ["value"] for path, _op, _value in clauses)
            for kind, clauses in comparisons.items()
        ):
            result = {"status": "indeterminate", "reason": "unsupported observable property"}
        else:
            bindings = pattern.match([{"type": "bundle", "objects": payload["objects"]}])
            ids = sorted({
                obj["id"] for binding in bindings for obj in binding["objects"]
                if obj.get("type") == "observed-data"
            })
            times = [
                datetime.fromisoformat(obj["first_observed"].replace("Z", "+00:00"))
                for obj in payload["objects"] if obj.get("id") in ids
            ]
            # The reference matcher may accept equality at a WITHIN boundary.
            # Check the full binding conservatively; nested scopes may be narrower.
            within = [q for q in inspection.qualifiers if q.startswith("WITHIN ")]
            limits = [re.fullmatch(r"WITHIN (\d+(?:\.\d+)?) SECONDS", q) for q in within]
            if any(limit is None for limit in limits):
                result = {"status": "indeterminate", "reason": "unsupported time qualifier"}
            elif len(times) > 1 and any(
                (max(times) - min(times)).total_seconds() >= float(limit.group(1))
                for limit in limits
            ):
                result = {"status": "indeterminate", "reason": "time boundary requires review"}
            else:
                result = {"status": "matched" if ids else "not_matched", "observation_ids": ids}
        print(json.dumps(result))
    except Exception:
        print(json.dumps({"status": "indeterminate", "reason": "unsupported or invalid pattern"}))


if __name__ == "__main__":
    main()
