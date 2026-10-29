import json
import plistlib
import sys
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from pathlens.analysis import analyze
from pathlens.collectors import CollectionError
from pathlens.kev import Catalog, ProductObservations, correlate_products
from pathlens.launch_agent import write_launch_agent
from pathlens.models import Snapshot
from pathlens.taxii import fetch_collection

ROOT = Path(__file__).parents[1]


def example(name):
    return json.loads((ROOT / "examples" / name).read_text())


@pytest.mark.parametrize("method", ["basic", "bearer"])
def test_taxii_auth_stays_on_original_endpoint_with_pagination(method):
    seen = []

    def handler(request):
        seen.append((request.url.host, request.headers.get("authorization")))
        body = {"objects": [], "more": len(seen) == 1}
        if len(seen) == 1:
            body["next"] = "next-page"
        return httpx.Response(
            200, headers={"Content-Type": "application/taxii+json;version=2.1"}, json=body
        )

    kwargs = (
        {"basic_auth": ("sample-user", "sample-password")}
        if method == "basic"
        else {"bearer_token": "sample-token"}
    )
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        fetch_collection("https://example.com/api/objects/", client=client, **kwargs)
    assert len(seen) == 2
    assert all(host == "example.com" for host, _ in seen)
    assert all(
        header.startswith("Basic " if method == "basic" else "Bearer ") for _, header in seen
    )


def test_taxii_auth_not_forwarded_to_redirect():
    seen = []

    def handler(request):
        seen.append(request.url.host)
        return httpx.Response(302, headers={"Location": "https://other.example/objects/"})

    with httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True) as client:
        with pytest.raises(CollectionError):
            fetch_collection(
                "https://example.com/api/objects/", client=client, bearer_token="sample-token"
            )
    assert seen == ["example.com"]


def test_taxii_rejects_ambiguous_or_unsafe_auth():
    with pytest.raises(ValueError, match="Choose"):
        fetch_collection(
            "https://example.com/api/objects/", basic_auth=("user", "pass"), bearer_token="token"
        )
    with pytest.raises(ValueError, match="Invalid"):
        fetch_collection("https://example.com/api/objects/", bearer_token="secret\nheader")


def test_taxii_cli_prompts_without_saving_credentials(tmp_path, monkeypatch):
    import pathlens.taxii as taxii
    from pathlens.cli import app

    seen = []

    def fake_fetch(url, *, basic_auth=None, bearer_token=None):
        seen.append((url, basic_auth, bearer_token))
        return example("sample-stix.json")

    monkeypatch.setattr(taxii, "fetch_collection", fake_fetch)
    output = tmp_path / "feed.json"
    result = CliRunner().invoke(
        app,
        [
            "import-taxii",
            "--url",
            "https://example.com/api/objects/",
            "--source-name",
            "Sample",
            "--auth-method",
            "bearer",
            "--output",
            str(output),
        ],
        input="temporary-secret\n",
    )
    assert result.exit_code == 0, result.output
    assert seen[0][2] == "temporary-secret"
    assert "temporary-secret" not in result.output
    assert "temporary-secret" not in output.read_text()


def test_product_candidates_are_exact_bounded_and_not_verdicts():
    report = analyze(Snapshot.model_validate(example("sample.json")))
    asset = next(a for a in report.assets if a.name == "cdn.example.com")
    priority = asset.priority
    observations = ProductObservations.model_validate(example("product-observations.json"))
    correlate_products(report, observations, Catalog.model_validate(example("kev-sample.json")))
    assert report.product_correlation.candidate_count == 1
    assert asset.product_kev_candidates[0].cve_id == "CVE-2099-10001"
    assert asset.product_kev_candidates[0].supplied_version == "1.0"
    assert asset.priority == priority
    assert "not verified" in report.limitations[-1]


def test_product_name_is_not_substring_and_scope_is_checked():
    report = analyze(Snapshot.model_validate(example("sample.json")))
    data = example("product-observations.json")
    data["observations"][0]["product"] = "Example"
    catalog = Catalog.model_validate(example("kev-sample.json"))
    correlate_products(report, ProductObservations.model_validate(data), catalog)
    assert report.product_correlation.candidate_count == 0
    data["observations"][0]["asset"] = "other.example"
    with pytest.raises(ValueError, match="outside"):
        correlate_products(report, ProductObservations.model_validate(data), catalog)


def test_launch_agent_generation_only_writes_requested_file(tmp_path):
    output = tmp_path / "agent.plist"
    write_launch_agent(output, Path(sys.executable), tmp_path, 3600)
    data = plistlib.loads(output.read_bytes())
    assert data["StartInterval"] == 3600
    assert data["RunAtLoad"] is False
    assert data["ProgramArguments"][-2:] == ["--cycles", "1"]
    original = output.read_bytes()
    with pytest.raises(FileExistsError):
        write_launch_agent(output, Path(sys.executable), tmp_path, 3600)
    assert output.read_bytes() == original


def test_product_candidate_cli_fetches_only_when_requested(tmp_path, monkeypatch):
    import pathlens.cli as cli

    calls = []

    def fetch():
        calls.append("kev")
        return Catalog.model_validate(example("kev-sample.json"))

    monkeypatch.setattr(cli, "fetch_catalog", fetch)
    out = tmp_path / "out"
    result = CliRunner().invoke(
        cli.app,
        [
            "scan",
            "example.com",
            "--snapshot",
            str(ROOT / "examples/sample.json"),
            "--product-observations",
            str(ROOT / "examples/product-observations.json"),
            "--fetch-kev",
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    assert calls == ["kev"]
    report = json.loads((out / "report.json").read_text())
    assert report["product_correlation"]["candidate_count"] == 1
    assert "not verified" in (out / "report.md").read_text()


def test_product_candidate_mcp_works_with_supplied_catalog():
    from pathlens.mcp_server import analyze_snapshot

    result = analyze_snapshot(
        example("sample.json"),
        product_observations=example("product-observations.json"),
        kev_catalog=example("kev-sample.json"),
    )
    assert result["product_correlation"]["candidate_count"] == 1
