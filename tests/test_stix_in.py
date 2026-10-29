import json
from pathlib import Path

import pytest

from pathlens.stix_import import import_stix
from pathlens.threat_intel import Source

SAMPLE = Path(__file__).parents[1] / "examples" / "sample-stix.json"


def convert(pattern):
    data = json.loads(SAMPLE.read_text())
    data["objects"][0]["pattern"] = pattern
    return import_stix(data, Source(name="Example", url="https://example.com"))


def test_in_converts_exact_alternatives():
    feed, skipped = convert("[domain-name:value IN ('a.example.com', 'b.example.com')]")
    assert skipped == 0
    assert [item.value for item in feed.indicators] == ["a.example.com", "b.example.com"]


@pytest.mark.parametrize(
    "pattern",
    [
        "[domain-name:value NOT IN ('a.example.com')]",
        "[domain-name:value IN ('a.example.com') AND ipv4-addr:value = '192.0.2.1']",
        "[domain-name:value IN ('a.example.com', 'bad\\'value')]",
    ],
)
def test_complex_or_escaped_in_patterns_are_not_flattened(pattern):
    feed, skipped = convert(pattern)
    assert not feed.indicators
    assert skipped == 1


def test_in_alternative_limit():
    pattern = "[domain-name:value IN (" + ", ".join(["'a.example.com'"] * 101) + ")]"
    with pytest.raises(ValueError, match="limit"):
        convert(pattern)
