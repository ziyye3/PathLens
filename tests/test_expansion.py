import json
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from pathlens.analysis import analyze
from pathlens.collectors import CollectionError
from pathlens.exposures import ExposureObservations, correlate_exposures
from pathlens.kev import Catalog, Observations, correlate
from pathlens.models import Snapshot
from pathlens.refresh import watch_feodo
from pathlens.stix_import import import_stix
from pathlens.taxii import fetch_collection
from pathlens.threat_intel import Source, ThreatFeed

ROOT = Path(__file__).parents[1]


def sample(name):
    return json.loads((ROOT / "examples" / name).read_text())


@pytest.fixture
def stix():
    return sample("sample-stix.json")


@pytest.fixture
def report():
    return analyze(Snapshot.model_validate(sample("sample.json")))


def source():
    return Source(name="Synthetic", url="https://example.com/feed")


def test_stix_exact_domain_conversion(stix):
    feed, skipped = import_stix(stix, source())
    assert skipped == 0
    assert feed.indicators[0].value == "demo.cloudfront.net"
    assert feed.indicators[0].type == "domain"
    assert feed.source.url == "https://example.com/feed"


def test_stix_marks_refused_and_no_output(stix, tmp_path):
    stix["objects"][0]["object_marking_refs"] = [
        "marking-definition--00000000-0000-0000-0000-000000000000"
    ]
    inp = tmp_path / "marked.json"
    inp.write_text(json.dumps(stix))
    output = tmp_path / "out.json"
    from pathlens.cli import app

    result = CliRunner().invoke(
        app,
        [
            "import-stix",
            str(inp),
            "--output",
            str(output),
            "--source-name",
            "test",
            "--source-url",
            "https://example.com/feed",
        ],
    )
    assert result.exit_code == 1
    assert "Marked" in result.output
    assert not output.exists()


def test_stix_unsupported_revoked_and_unbounded_expiry(stix):
    indicator = stix["objects"][0]
    indicator.pop("valid_until")
    feed, skipped = import_stix(stix, source())
    assert skipped == 0
    assert (feed.indicators[0].valid_until - feed.indicators[0].valid_from).days == 30
    assert "30-day" in feed.indicators[0].description
    indicator["pattern"] = (
        "[domain-name:value = 'example.com' OR domain-name:value = 'other.example']"
    )
    assert import_stix(stix, source())[1] == 1
    indicator["revoked"] = True
    assert import_stix(stix, source())[0].indicators == []


def test_stix_duplicate_versions_and_wrong_ip_type_rejected(stix):
    stix["objects"].append(stix["objects"][0].copy())
    with pytest.raises(ValueError, match="Duplicate"):
        import_stix(stix, source())
    stix["objects"].pop()
    stix["objects"][0]["pattern"] = "[ipv4-addr:value = '2001:db8::1']"
    with pytest.raises(ValueError, match="IP type"):
        import_stix(stix, source())


def test_taxii_paginates_only_original_endpoint(stix):
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/taxii+json;version=2.1"},
                json={"more": True, "next": "abc", "objects": []},
            )
        return httpx.Response(
            200,
            headers={"Content-Type": "application/taxii+json;version=2.1"},
            json={"more": False, "objects": stix["objects"]},
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        bundle = fetch_collection("https://example.com/api/collections/a/objects/", client=client)
    assert len(bundle["objects"]) == 1
    assert len(calls) == 2
    assert calls[1].url.params["next"] == "abc"
    assert calls[1].url.host == "example.com"


def test_taxii_incomplete_or_unsafe_endpoint_fails():
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _req: httpx.Response(
                200,
                headers={"Content-Type": "application/taxii+json;version=2.1"},
                json={"more": True, "objects": []},
            )
        )
    ) as client:
        with pytest.raises(CollectionError, match="incomplete"):
            fetch_collection("https://example.com/api/objects/", client=client)
    with pytest.raises(ValueError):
        fetch_collection("https://user:secret@example.com/api/objects/")


def test_taxii_does_not_follow_redirects():
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(302, headers={"Location": "https://other.example/objects/"})

    with httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True) as client:
        with pytest.raises(CollectionError):
            fetch_collection("https://example.com/api/objects/", client=client)
    assert seen == ["https://example.com/api/objects/"]


@pytest.mark.parametrize("content_type", ["application/json", "application/taxii+json;version=2.0"])
def test_taxii_rejects_wrong_media_type_or_version(content_type):
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _req: httpx.Response(
                200, headers={"Content-Type": content_type}, json={"objects": []}
            )
        )
    ) as client:
        with pytest.raises(CollectionError):
            fetch_collection("https://example.com/api/objects/", client=client)


def test_kev_requires_explicit_asset_cve_and_never_changes_priority(report):
    assets = {asset.name: asset for asset in report.assets}
    before = assets["cdn.example.com"].priority
    correlate(
        report,
        Observations.model_validate(sample("cve-observations.json")),
        Catalog.model_validate(sample("kev-sample.json")),
    )
    assert report.cve_correlation.match_count == 1
    match = assets["cdn.example.com"].vulnerability_matches[0]
    assert match.cve_id == "CVE-2099-10001"
    assert match.kev_catalog_version == "synthetic-demo"
    assert assets["cdn.example.com"].priority == before
    assert "supplied by the user" in report.limitations[-1]


def test_kev_scope_rejected_without_mutating_report(report):
    data = sample("cve-observations.json")
    data["observations"].append({**data["observations"][0], "asset": "other.example"})
    with pytest.raises(ValueError, match="outside"):
        correlate(
            report,
            Observations.model_validate(data),
            Catalog.model_validate(sample("kev-sample.json")),
        )
    assert report.cve_correlation.status == "not_supplied"
    assert not any(a.vulnerability_matches for a in report.assets)


def test_kev_does_not_infer_cve_from_service_and_handles_missing_assets(report):
    data = sample("cve-observations.json")
    data["observations"][0]["asset"] = "absent.example.com"
    correlate(
        report, Observations.model_validate(data), Catalog.model_validate(sample("kev-sample.json"))
    )
    assert report.cve_correlation.match_count == 0
    assert any("not discovered" in warning for warning in report.warnings)
    assert not any(asset.vulnerability_matches for asset in report.assets)


def test_exposure_claim_is_minimal_and_unverified(report):
    claims = ExposureObservations.model_validate(sample("exposure-observations.json"))
    correlate_exposures(report, claims)
    assert report.exposure_correlation.match_count == 1
    claim = next(a for a in report.assets if a.name == "cdn.example.com").exposure_claims[0]
    assert claim.category == "data_leak_claim"
    assert "not independently verified" in report.limitations[-1]
    data = sample("exposure-observations.json")
    data["observations"][0]["password"] = "must not be accepted"
    with pytest.raises(ValidationError):
        ExposureObservations.model_validate(data)
    data = sample("exposure-observations.json")
    data["observations"][0]["source_url"] += "?token=secret"
    with pytest.raises(ValidationError):
        ExposureObservations.model_validate(data)


def test_foreground_refresh_retains_previous_snapshots_on_failure(tmp_path):
    feed = ThreatFeed.model_validate(sample("threat-feed.json"))
    attempts = 0

    def fetch():
        nonlocal attempts
        attempts += 1
        if attempts == 2:
            raise CollectionError("unavailable")
        return feed

    delays, messages = [], []
    watch_feodo(tmp_path, 300, cycles=2, fetch=fetch, wait=delays.append, notify=messages.append)
    assert len(list(tmp_path.glob("feodo-*.json"))) == 1
    assert delays == [300]
    assert "existing snapshots kept" in messages[1]
    with pytest.raises(ValueError):
        watch_feodo(tmp_path, 10, cycles=1, fetch=fetch)


def test_cli_and_mcp_combined_offline_flow(tmp_path):
    from pathlens.cli import app
    from pathlens.mcp_server import analyze_snapshot

    out = tmp_path / "out"
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "example.com",
            "--snapshot",
            str(ROOT / "examples/sample.json"),
            "--cve-observations",
            str(ROOT / "examples/cve-observations.json"),
            "--kev-catalog",
            str(ROOT / "examples/kev-sample.json"),
            "--exposure-observations",
            str(ROOT / "examples/exposure-observations.json"),
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    report = json.loads((out / "report.json").read_text())
    assert report["cve_correlation"]["match_count"] == 1
    assert report["exposure_correlation"]["match_count"] == 1
    assert "unverified" in (out / "report.md").read_text().lower()
    mcp = analyze_snapshot(
        sample("sample.json"),
        cve_observations=sample("cve-observations.json"),
        kev_catalog=sample("kev-sample.json"),
        exposure_observations=sample("exposure-observations.json"),
    )
    assert mcp["cve_correlation"]["match_count"] == 1
    assert mcp["exposure_correlation"]["match_count"] == 1
