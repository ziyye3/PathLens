import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from pathlens.analysis import analyze
from pathlens.cli import app
from pathlens.feodo import FEODO_URL, convert_feodo
from pathlens.mcp_server import analyze_snapshot
from pathlens.models import Evidence, Snapshot
from pathlens.threat_intel import Indicator, ThreatFeed, index_feed, match_indicators

ROOT = Path(__file__).parents[1]
SAMPLE = ROOT / "examples" / "sample.json"
FEED = ROOT / "examples" / "threat-feed.json"


@pytest.fixture
def snapshot():
    return Snapshot.model_validate_json(SAMPLE.read_text())


@pytest.fixture
def feed():
    return ThreatFeed.model_validate_json(FEED.read_text())


def test_context_is_scoped_to_affected_service_and_has_sources(snapshot):
    assets = {asset.name: asset for asset in analyze(snapshot).assets}
    assert [ctx.id for ctx in assets["s3.example.com"].threat_context] == ["aws-s3-dangling-alias"]
    assert [ctx.id for ctx in assets["missing.example.com"].threat_context] == [
        "aws-elastic-beanstalk-dangling-alias"
    ]
    assert assets["cdn.example.com"].threat_context == []
    for asset in assets.values():
        for ctx in asset.threat_context:
            assert ctx.source_url.startswith("https://docs.aws.amazon.com/")
            assert ctx.matched_rule_id in {finding.rule_id for finding in asset.findings}
            assert ctx.limitations


def test_exact_indicator_matching_and_provenance(snapshot, feed):
    report = analyze(snapshot, threat_feed=feed)
    asset = next(asset for asset in report.assets if asset.name == "cdn.example.com")
    matches = {
        (item.indicator_type, item.value, item.observed_as) for item in asset.indicator_matches
    }
    assert matches == {
        ("domain", "demo.cloudfront.net", "cname_target"),
        ("ip", "203.0.113.10", "address"),
    }
    assert report.threat_feed.match_count == 2
    assert all(
        item.evidence and item.source_url == feed.source.url for item in asset.indicator_matches
    )
    assert asset.priority == "info"  # TI matches do not silently change the assessment.


def test_domain_matching_is_exact_not_suffix(snapshot, feed):
    feed.indicators[0].value = "cloudfront.net"
    report = analyze(snapshot, threat_feed=feed)
    assert all(
        match.indicator_type != "domain"
        for asset in report.assets
        for match in asset.indicator_matches
    )


@pytest.mark.parametrize(
    ("observed", "now", "expected"),
    [
        ("2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z", "active"),
        ("2025-12-31T00:00:00Z", "2026-01-03T00:00:00Z", "not_yet_valid"),
        ("2026-01-02T00:00:00Z", "2026-02-01T00:00:00Z", "expired"),
        ("2026-02-01T00:00:00Z", "2026-01-03T00:00:00Z", "expired"),
    ],
)
def test_indicator_time_window_is_explicit(observed, now, expected):
    feed = ThreatFeed.model_validate(
        {
            "schema_version": "1.0",
            "source": {"name": "test", "url": "https://example.com"},
            "generated_at": "2026-01-01T00:00:00Z",
            "indicators": [
                {
                    "id": "1",
                    "type": "domain",
                    "value": "example.com",
                    "description": "test",
                    "valid_from": "2026-01-01T00:00:00Z",
                    "valid_until": "2026-02-01T00:00:00Z",
                }
            ],
        }
    )
    evidence = [Evidence(source="user-input", description="requested")]
    matches = match_indicators(
        [("domain", "example.com", "asset_name", evidence)],
        feed,
        index_feed(feed),
        datetime.fromisoformat(observed),
        datetime.fromisoformat(now),
    )
    assert matches[0].status == expected


@pytest.mark.parametrize(
    "bad_url", ["http://example.com", "https://user:secret@example.com", "file:///tmp/a"]
)
def test_feed_rejects_unsafe_source_urls(feed, bad_url):
    data = feed.model_dump(mode="json")
    data["source"]["url"] = bad_url
    with pytest.raises(ValidationError):
        ThreatFeed.model_validate(data)


def test_invalid_feed_does_not_write_reports(tmp_path):
    bad_feed = tmp_path / "bad.json"
    bad_feed.write_text('{"schema_version": "1.0"}')
    output = tmp_path / "report"
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "example.com",
            "--snapshot",
            str(SAMPLE),
            "--threat-feed",
            str(bad_feed),
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 1
    assert not output.exists()


def test_cli_mcp_and_markdown_include_matches(tmp_path):
    output = tmp_path / "report"
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "example.com",
            "--snapshot",
            str(SAMPLE),
            "--threat-feed",
            str(FEED),
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    parsed = json.loads((output / "report.json").read_text())
    assert parsed["threat_feed"]["match_count"] == 2
    assert "Synthetic example only" in (output / "report.md").read_text()
    mcp_result = analyze_snapshot(
        json.loads(SAMPLE.read_text()), threat_feed=json.loads(FEED.read_text())
    )
    assert mcp_result["threat_feed"]["match_count"] == 2


def test_feed_validation_rejects_duplicate_and_invalid_entries(feed):
    data = feed.model_dump(mode="json")
    data["indicators"].append(data["indicators"][0].copy())
    with pytest.raises(ValidationError, match="unique"):
        ThreatFeed.model_validate(data)
    with pytest.raises(ValidationError):
        Indicator.model_validate(
            {
                "id": "bad",
                "type": "ip",
                "value": "not-ip",
                "description": "x",
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2026-01-02T00:00:00Z",
            }
        )


def test_feed_rejects_terminal_control_characters(feed):
    data = feed.model_dump(mode="json")
    data["source"]["name"] = "bad\x1b[31mname"
    with pytest.raises(ValidationError, match="control characters"):
        ThreatFeed.model_validate(data)


def test_feed_not_supplied_is_not_a_clear_verdict(snapshot):
    report = analyze(snapshot)
    assert report.threat_feed.status == "not_supplied"
    assert all(not asset.indicator_matches for asset in report.assets)


def test_feodo_conversion_preserves_provenance_and_limits_lifetime():
    now = datetime(2026, 10, 30, tzinfo=UTC)
    data = [
        {
            "ip_address": "203.0.113.3",
            "port": 443,
            "first_seen": "2026-10-01 12:00:00",
            "status": "online",
            "malware": "example",
            "last_online": "2026-10-29",
        }
    ]
    feed = convert_feodo(data + data, fetched_at=now)
    assert feed.source.url == FEODO_URL
    assert len(feed.indicators) == 1
    assert feed.indicators[0].valid_until == now + timedelta(hours=24)
    assert "last online 2026-10-29" in feed.indicators[0].description
    with pytest.raises(ValueError):
        convert_feodo([{"ip_address": "invalid"}], fetched_at=now)


def test_feodo_command_fetches_only_fixed_url_and_never_overwrites(tmp_path, monkeypatch):
    import pathlens.feodo as feodo

    seen = []

    def fake_read(_client, url):
        seen.append(url)
        return []

    monkeypatch.setattr(feodo, "_read_json", fake_read)
    out = tmp_path / "feed.json"
    runner = CliRunner()
    result = runner.invoke(app, ["update-feodo", "--output", str(out)])
    assert result.exit_code == 0, result.output
    assert seen == [FEODO_URL]
    assert json.loads(out.read_text())["indicators"] == []
    assert runner.invoke(app, ["update-feodo", "--output", str(out)]).exit_code == 1
    assert seen == [FEODO_URL]


def test_feodo_network_failure_does_not_create_output(tmp_path, monkeypatch):
    import pathlens.feodo as feodo
    from pathlens.collectors import CollectionError

    def fail(_client, _url):
        raise CollectionError("unavailable") from httpx.ConnectError("unavailable")

    monkeypatch.setattr(feodo, "_read_json", fail)
    out = tmp_path / "feed.json"
    result = CliRunner().invoke(app, ["update-feodo", "--output", str(out)])
    assert result.exit_code == 1
    assert not out.exists()
