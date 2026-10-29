import json
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from pathlens.analysis import analyze
from pathlens.collectors import CollectionError
from pathlens.models import Snapshot
from pathlens.osv import (
    OSV_URL,
    OSVSnapshot,
    PackageObservations,
    PackageQuery,
    correlate_osv,
    fetch_query,
)

ROOT = Path(__file__).parents[1] / "examples"


def data(name):
    return json.loads((ROOT / name).read_text())


def test_osv_request_contains_only_package_and_version_and_paginates():
    requests = []

    def handler(request):
        requests.append(json.loads(request.content))
        assert str(request.url) == OSV_URL
        if len(requests) == 1:
            return httpx.Response(
                200,
                json={
                    "vulns": [{"id": "GHSA-test-1", "summary": "one"}],
                    "next_page_token": "next",
                },
            )
        return httpx.Response(
            200, json={"vulns": [{"id": "GHSA-test-2", "withdrawn": "2026-01-01T00:00:00Z"}]}
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = fetch_query(client, PackageQuery(ecosystem="PyPI", name="demo", version="1.0"))
    assert requests == [
        {"package": {"ecosystem": "PyPI", "name": "demo"}, "version": "1.0"},
        {"package": {"ecosystem": "PyPI", "name": "demo"}, "version": "1.0", "page_token": "next"},
    ]
    assert [item.id for item in result.advisories] == ["GHSA-test-1", "GHSA-test-2"]
    assert result.advisories[1].withdrawn is True


def test_osv_redirect_and_repeated_token_fail_closed():
    query = PackageQuery(ecosystem="PyPI", name="demo", version="1.0")
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(302, headers={"Location": "https://other.example/"})
        ),
        follow_redirects=True,
    ) as client:
        with pytest.raises(CollectionError):
            fetch_query(client, query)
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(200, json={"next_page_token": "same"})
        )
    ) as client:
        with pytest.raises(CollectionError, match="pagination"):
            fetch_query(client, query)


def test_osv_deduplicates_identical_results_and_rejects_conflicts():
    query = PackageQuery(ecosystem="npm", name="demo", version="1.0")
    calls = 0

    def handler(_request):
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            json={
                "vulns": [{"id": "GHSA-demo", "summary": "one"}],
                **({"next_page_token": "next"} if calls == 1 else {}),
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert len(fetch_query(client, query).advisories) == 1


def test_osv_supplied_snapshot_is_marked_unverified_and_version_not_proven():
    report = analyze(Snapshot.model_validate(data("sample.json")))
    correlate_osv(
        report,
        PackageObservations.model_validate(data("osv-observations.json")),
        OSVSnapshot.model_validate(data("osv-sample.json")),
        provenance="supplied",
    )
    assert report.osv_correlation.status == "supplied"
    assert report.osv_correlation.match_count == 1
    assert "not independently verified" in report.limitations[-1]
    asset = next(item for item in report.assets if item.name == "cdn.example.com")
    assert asset.osv_matches[0].advisory_id == "SYNTHETIC-2099-0001"
    assert asset.priority == "info"


def test_osv_missing_query_or_out_of_scope_does_not_mutate_report():
    report = analyze(Snapshot.model_validate(data("sample.json")))
    snapshot = OSVSnapshot.model_validate(data("osv-sample.json"))
    observations = data("osv-observations.json")
    observations["observations"][0]["version"] = "2.0"
    with pytest.raises(ValueError, match="does not contain"):
        correlate_osv(
            report,
            PackageObservations.model_validate(observations),
            snapshot,
            provenance="supplied",
        )
    assert report.osv_correlation.status == "not_supplied"
    observations["observations"][0]["asset"] = "other.example"
    with pytest.raises(ValueError, match="outside"):
        correlate_osv(
            report,
            PackageObservations.model_validate(observations),
            snapshot,
            provenance="supplied",
        )
    assert all(not asset.osv_matches for asset in report.assets)


def test_osv_cli_offline_and_mcp_share_result(tmp_path):
    from pathlens.cli import app
    from pathlens.mcp_server import analyze_snapshot

    out = tmp_path / "report"
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "example.com",
            "--snapshot",
            str(ROOT / "sample.json"),
            "--osv-observations",
            str(ROOT / "osv-observations.json"),
            "--osv-results",
            str(ROOT / "osv-sample.json"),
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    report = json.loads((out / "report.json").read_text())
    assert report["osv_correlation"]["status"] == "supplied"
    assert report["osv_correlation"]["match_count"] == 1
    assert "not independently verified" in (out / "report.md").read_text()
    mcp = analyze_snapshot(
        data("sample.json"),
        osv_observations=data("osv-observations.json"),
        osv_results=data("osv-sample.json"),
    )
    assert mcp["osv_correlation"]["match_count"] == 1


def test_osv_out_of_scope_is_rejected_before_network(tmp_path, monkeypatch):
    import pathlens.cli as cli

    observations = data("osv-observations.json")
    observations["observations"][0]["asset"] = "other.example"
    path = tmp_path / "observations.json"
    path.write_text(json.dumps(observations))

    def forbidden(_observations):
        raise AssertionError("network must not be called")

    monkeypatch.setattr(cli, "fetch_observations", forbidden)
    result = CliRunner().invoke(
        cli.app,
        [
            "scan",
            "example.com",
            "--snapshot",
            str(ROOT / "sample.json"),
            "--osv-observations",
            str(path),
            "--fetch-osv",
            "--output",
            str(tmp_path / "out"),
        ],
    )
    assert result.exit_code == 1
    assert "outside" in result.output


def test_osv_live_opt_in_marks_live_and_does_not_change_priority(tmp_path, monkeypatch):
    import pathlens.cli as cli

    called = []

    def fetch(observations):
        called.append(observations.observations[0].name)
        return OSVSnapshot.model_validate(data("osv-sample.json"))

    monkeypatch.setattr(cli, "fetch_observations", fetch)
    out = tmp_path / "report"
    result = CliRunner().invoke(
        cli.app,
        [
            "scan",
            "example.com",
            "--snapshot",
            str(ROOT / "sample.json"),
            "--osv-observations",
            str(ROOT / "osv-observations.json"),
            "--fetch-osv",
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    report = json.loads((out / "report.json").read_text())
    assert report["osv_correlation"]["status"] == "live"
    assert report["osv_correlation"]["match_count"] == 1
    assert called == ["synthetic-package"]
    assert (
        next(asset for asset in report["assets"] if asset["name"] == "cdn.example.com")["priority"]
        == "info"
    )


def test_osv_empty_results_never_claim_safe():
    report = analyze(Snapshot.model_validate(data("sample.json")))
    snapshot = data("osv-sample.json")
    snapshot["results"][0]["advisories"] = []
    correlate_osv(
        report,
        PackageObservations.model_validate(data("osv-observations.json")),
        OSVSnapshot.model_validate(snapshot),
        provenance="supplied",
    )
    assert report.osv_correlation.match_count == 0
    assert any(
        "empty result does not establish safety" in line.lower() for line in report.limitations
    )
