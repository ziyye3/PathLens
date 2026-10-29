import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from pathlens.analysis import analyze, discover_names, load_services, service_matches
from pathlens.models import DNSRecord, Snapshot, normalize_name

SAMPLE = Path(__file__).parents[1] / "examples" / "sample.json"


@pytest.fixture
def sample():
    return Snapshot.model_validate_json(SAMPLE.read_text(encoding="utf-8"))


def assets_by_name(report):
    return {asset.name: asset for asset in report.assets}


def rule_ids(asset):
    return {finding.rule_id for finding in asset.findings}


@pytest.mark.parametrize(
    ("name", "expected", "absent"),
    [
        (
            "missing.example.com",
            {"dangling-known-service", "known-service-review", "aws-infrastructure"},
            set(),
        ),
        (
            "s3.example.com",
            {"known-service-review", "aws-infrastructure"},
            {"dangling-known-service"},
        ),
        (
            "cdn.example.com",
            {"aws-infrastructure"},
            {"known-service-review", "dangling-known-service"},
        ),
        (
            "ip.example.com",
            {"aws-infrastructure"},
            {"known-service-review", "dangling-known-service"},
        ),
        (
            "timeout.example.com",
            {"known-service-review", "aws-infrastructure"},
            {"dangling-known-service"},
        ),
    ],
)
def test_five_synthetic_scenarios(sample, name, expected, absent):
    asset = assets_by_name(analyze(sample))[name]
    assert expected <= rule_ids(asset)
    assert absent.isdisjoint(rule_ids(asset))


def test_every_finding_has_evidence(sample):
    report = analyze(sample)
    assert all(asset.discovery_evidence for asset in report.assets)
    findings = [finding for asset in report.assets for finding in asset.findings]
    assert findings
    assert all(
        finding.evidence and all(item.description for item in finding.evidence)
        for finding in findings
    )


def test_asset_priority_uses_the_highest_matching_rule_and_sorts_first(sample):
    report = analyze(sample)
    assert report.assets[0].name == "missing.example.com"
    assert report.assets[0].priority == "high"
    assert assets_by_name(report)["example.com"].priority == "unknown"


def test_invalid_rule_yaml_is_reported_as_value_error(sample, tmp_path):
    rules = tmp_path / "invalid.yaml"
    rules.write_text("rules: [", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid YAML"):
        analyze(sample, rules_path=rules)


def test_scope_and_wildcard_are_not_added(sample):
    names, _ = discover_names(sample, 100)
    assert "not-example.com" not in names
    assert "*.example.com" not in names
    assert "example.com" in names


def test_max_assets_preserves_apex_and_reports_truncation(sample):
    names, warnings = discover_names(sample, 2)
    assert len(names) == 2
    assert "example.com" in names
    assert "limit" in warnings[0].lower()


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com",
        "*.example.com",
        "evil example.com",
        "127.0.0.1",
        "-a.example.com",
        "example.com/path",
        "example.com@evil.org",
    ],
)
def test_rejects_invalid_domains(value):
    with pytest.raises(ValueError):
        normalize_name(value)


def test_domain_normalization():
    assert normalize_name("ExAmPlE.CoM.") == "example.com"
    assert normalize_name("한글.example") == "xn--bj0bj06e.example"


def test_dns_status_validation():
    with pytest.raises(ValidationError):
        DNSRecord(name="example.com", record_type="A", status="nxdomain", values=["192.0.2.1"])
    with pytest.raises(ValidationError):
        DNSRecord(name="example.com", record_type="AAAA", status="answer", values=["192.0.2.1"])
    with pytest.raises(ValidationError):
        DNSRecord(name="example.com", record_type="CNAME", status="answer", values=[])


def test_nxdomain_with_conflicting_answer_does_not_flag_dangling(sample):
    sample.dns_records.append(
        DNSRecord(
            name="removed.us-east-1.elasticbeanstalk.com",
            record_type="A",
            status="answer",
            values=["192.0.2.5"],
        )
    )
    asset = assets_by_name(analyze(sample))["missing.example.com"]
    assert "dangling-known-service" not in rule_ids(asset)
    assert any("Contradictory" in warning for warning in asset.warnings)


def test_timeout_is_not_nxdomain(sample):
    asset = assets_by_name(analyze(sample))["timeout.example.com"]
    assert "dangling-known-service" not in rule_ids(asset)
    assert any("timed out" in warning for warning in asset.warnings)


def test_unrelated_dns_record_does_not_influence_asset(sample):
    sample.dns_records.append(
        DNSRecord(
            name="not-example.com",
            record_type="A",
            status="answer",
            values=["203.0.113.90"],
        )
    )
    report = analyze(sample)
    assert "not-example.com" not in assets_by_name(report)
    assert assets_by_name(report)["example.com"].findings == []


def test_cname_loop_is_reported_without_dangling_verdict():
    snapshot = Snapshot.model_validate(
        {
            "domain": "example.com",
            "dns_records": [
                {
                    "name": "example.com",
                    "record_type": "CNAME",
                    "status": "answer",
                    "values": ["loop.example.com"],
                },
                {
                    "name": "loop.example.com",
                    "record_type": "CNAME",
                    "status": "answer",
                    "values": ["example.com"],
                },
            ],
        }
    )
    asset = assets_by_name(analyze(snapshot))["example.com"]
    assert any("loop" in warning.lower() for warning in asset.warnings)
    assert "dangling-known-service" not in rule_ids(asset)


def test_provider_domain_matching_has_suffix_boundaries():
    cloudfront = next(s for s in load_services().services if s.name == "AWS CloudFront")
    s3 = next(s for s in load_services().services if s.name == "AWS S3")
    assert service_matches("x.cloudfront.net", cloudfront)
    assert not service_matches("x.cloudfront.net.evil.com", cloudfront)
    assert service_matches("bucket.s3.us-east-1.amazonaws.com", s3)
    assert service_matches("bucket.s3-website-us-east-1.amazonaws.com", s3)
    assert not service_matches("s3.amazonaws.com.evil.com", s3)


def test_result_round_trips_as_json(sample):
    report = analyze(sample)
    assert json.loads(report.model_dump_json())["domain"] == "example.com"
