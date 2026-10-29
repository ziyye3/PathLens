import json
from pathlib import Path

import pytest

from pathlens.stix_import import import_stix
from pathlens.threat_intel import Source

SAMPLE = Path(__file__).parents[1] / "examples" / "sample-stix.json"


def doc(pattern):
    data = json.loads(SAMPLE.read_text())
    data["objects"][0]["pattern"] = pattern
    return data


def test_or_alternatives_are_independent_exact_indicators():
    pattern = "[domain-name:value = 'a.example.com' OR ipv4-addr:value = '192.0.2.1']"
    feed, skipped = import_stix(doc(pattern), Source(name="Example", url="https://example.com"))
    assert skipped == 0
    assert [(item.type, item.value) for item in feed.indicators] == [
        ("domain", "a.example.com"),
        ("ip", "192.0.2.1"),
    ]
    assert feed.indicators[0].id.endswith("#or-1")
    assert feed.indicators[1].id.endswith("#or-2")


@pytest.mark.parametrize(
    "pattern",
    [
        "[domain-name:value = 'a.example.com' AND domain-name:value = 'b.example.com']",
        "[domain-name:value = 'a.example.com' OR ipv4-addr:value = '192.0.2.1'] WITHIN 10 SECONDS",
        "[domain-name:value = 'a.example.com' OR domain-name:value MATCHES '.*']",
    ],
)
def test_complex_or_qualified_patterns_are_not_flattened(pattern):
    feed, skipped = import_stix(doc(pattern), Source(name="Example", url="https://example.com"))
    assert not feed.indicators
    assert skipped == 1


def test_or_alternative_limit():
    pattern = "[" + " OR ".join(["domain-name:value = 'a.example.com'"] * 101) + "]"
    with pytest.raises(ValueError, match="limit"):
        import_stix(doc(pattern), Source(name="Example", url="https://example.com"))
