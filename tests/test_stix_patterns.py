import copy
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from pathlens.cli import app
from pathlens.models import Snapshot
from pathlens.stix_patterns import evaluate_stix, snapshot_observations

EXAMPLES = Path(__file__).parents[1] / "examples"


def fixtures():
    return (
        json.loads((EXAMPLES / "stix-pattern-indicators.json").read_text()),
        json.loads((EXAMPLES / "stix-observations.json").read_text()),
    )


def evaluate(pattern, mutate=None):
    indicators, observations = fixtures()
    indicators["objects"] = indicators["objects"][:1]
    indicators["objects"][0]["pattern"] = pattern
    if mutate:
        mutate(indicators, observations)
    return evaluate_stix(indicators, observations)["results"][0]


def test_compound_and_regex_match_same_object():
    result = evaluate(
        "[domain-name:value = 'demo.example.com' AND "
        "domain-name:value MATCHES '^demo[.]example[.]com$']"
    )
    assert result["status"] == "matched"
    assert len(result["observation_ids"]) == 1
    result = evaluate(
        "[domain-name:value = 'other.example.com' AND "
        "domain-name:value MATCHES '^demo[.]example[.]com$']"
    )
    assert result["status"] == "not_matched"


def test_distinct_observations_and_within():
    pattern = "([domain-name:value = 'demo.example.com'] AND [ipv4-addr:value = '192.0.2.10'])"
    assert evaluate(pattern + " WITHIN 60 SECONDS")["status"] == "matched"
    assert evaluate(pattern + " WITHIN 20 SECONDS")["status"] == "indeterminate"


def test_time_qualifier_start_inclusive_stop_exclusive():
    clause = "[domain-name:value = 'demo.example.com']"
    assert evaluate(
        clause + " START t'2026-10-01T00:00:00Z' STOP t'2026-10-01T00:00:01Z'"
    )["status"] == "matched"
    assert evaluate(
        clause + " START t'2026-09-30T00:00:00Z' STOP t'2026-10-01T00:00:00Z'"
    )["status"] == "not_matched"


def test_followedby_preserves_observation_order():
    left = "[domain-name:value = 'demo.example.com']"
    right = "[ipv4-addr:value = '192.0.2.10']"
    assert evaluate(f"{left} FOLLOWEDBY {right}")["status"] == "matched"
    assert evaluate(f"{right} FOLLOWEDBY {left}")["status"] == "not_matched"


def test_repeat_requires_distinct_observations():
    result = evaluate("[domain-name:value = 'demo.example.com'] REPEATS 2 TIMES")
    assert result["status"] == "not_matched"


def test_snapshot_converts_only_in_scope_dns_answers_and_preserves_indexes():
    snapshot = Snapshot.model_validate_json((EXAMPLES / "sample.json").read_text())
    bundle, indexes = snapshot_observations(snapshot)
    assert 4 not in indexes.values()  # cloudfront.net is outside the requested root
    indicators, _ = fixtures()
    indicators["objects"] = indicators["objects"][:1]
    indicators["objects"][0]["pattern"] = "[domain-name:value = 'cdn.example.com']"
    result = evaluate_stix(indicators, bundle)["results"][0]
    assert result["status"] == "matched"
    assert indexes[result["observation_ids"][0]] == 2


def test_uncertain_and_unsupported_results_are_not_false_negatives():
    assert evaluate("[file:name = 'test']")["status"] == "indeterminate"
    reference = "[domain-name:resolves_to_refs[*].value = '192.0.2.10']"
    assert evaluate(reference)["status"] == "indeterminate"
    assert evaluate("not a valid pattern")["status"] == "indeterminate"


def test_indicator_validity_filters_observations():
    def update(indicators, _observations):
        indicators["objects"][0]["valid_from"] = "2027-01-01T00:00:00Z"

    result = evaluate("[domain-name:value = 'demo.example.com']", update)
    assert result["status"] == "indeterminate"
    assert result["reason"] == "no eligible observations"


def test_marked_data_and_unresolved_refs_are_rejected():
    indicators, observations = fixtures()
    indicators["objects"][0]["object_marking_refs"] = ["marking-definition--not-public"]
    with pytest.raises(ValueError, match="Marked"):
        evaluate_stix(indicators, observations)
    indicators, observations = fixtures()
    observations["objects"][0]["object_refs"] = ["domain-name--missing"]
    with pytest.raises(ValueError, match="unresolved"):
        evaluate_stix(indicators, observations)


def test_invalid_observations_rejected_without_silent_coercion():
    indicators, observations = fixtures()
    observations["objects"][0]["number_observed"] = 2
    with pytest.raises(ValueError, match="individual observations"):
        evaluate_stix(indicators, observations)
    _, observations = fixtures()
    observations["objects"].append(copy.deepcopy(observations["objects"][-1]))
    with pytest.raises(ValueError, match="Duplicate"):
        evaluate_stix(indicators, observations)


def test_timeout_is_indeterminate():
    indicators, observations = fixtures()
    indicators["objects"] = indicators["objects"][:1]
    result = evaluate_stix(indicators, observations, timeout=0.000001)["results"][0]
    assert result["status"] == "indeterminate"
    assert result["reason"] == "evaluation timed out"


def test_hostile_regex_is_bounded():
    indicators, observations = fixtures()
    indicators["objects"] = indicators["objects"][:1]
    indicators["objects"][0]["pattern"] = "[domain-name:value MATCHES '^(a+)+$']"
    observations["objects"][2]["value"] = "a" * 62 + "b.example.com"
    result = evaluate_stix(indicators, observations, timeout=0.5)["results"][0]
    assert result["status"] == "indeterminate"
    assert result["reason"] in {"evaluation timed out", "evaluation failed"}


def test_select_indicators_from_larger_bundle_without_truncating():
    indicators, observations = fixtures()
    original = indicators["objects"][0]
    indicators["objects"] = [
        {**original, "id": f"indicator--00000000-0000-4000-8000-{index:012d}"}
        for index in range(21)
    ]
    with pytest.raises(ValueError, match="select at most 20"):
        evaluate_stix(indicators, observations)
    selected = indicators["objects"][0]["id"]
    result = evaluate_stix(indicators, observations, indicator_ids=[selected])
    assert len(result["results"]) == 1
    assert result["results"][0]["indicator_id"] == selected
    with pytest.raises(ValueError, match="not found"):
        evaluate_stix(indicators, observations, indicator_ids=["indicator--missing"])


def test_cli_outputs_only_identifiers_and_does_not_overwrite(tmp_path):
    output = tmp_path / "results.json"
    args = [
        "evaluate-stix", str(EXAMPLES / "stix-pattern-indicators.json"),
        str(EXAMPLES / "stix-observations.json"), "--output", str(output),
    ]
    first = CliRunner().invoke(app, args)
    assert first.exit_code == 0, first.output
    assert all(item["status"] == "matched" for item in json.loads(output.read_text())["results"])
    assert "demo.example.com" not in output.read_text()
    assert CliRunner().invoke(app, args).exit_code != 0
