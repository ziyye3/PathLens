import httpx
import pytest
from typer.testing import CliRunner

from pathlens.cli import app
from pathlens.collectors import CollectionError
from pathlens.taxii import check_collection

URL = "https://taxii.example.com/root/collections/test/objects/"


def test_check_collection_requests_one_page_with_auth_and_no_data_retention():
    def handle(request):
        assert request.url.params["limit"] == "1"
        assert request.headers["authorization"].startswith("Basic ")
        return httpx.Response(
            200, headers={"content-type": "application/taxii+json;version=2.1"},
            json={"objects": [{"type": "indicator", "sensitive": "not returned"}], "more": True},
        )

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        assert check_collection(URL, client=client, basic_auth=("user", "password")) == (1, True)


@pytest.mark.parametrize("code", [301, 401, 403, 429, 500])
def test_http_failure_code_does_not_disclose_credentials(code):
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(code))) as client:
        with pytest.raises(CollectionError, match=f"HTTP {code}") as error:
            check_collection(URL, client=client, bearer_token="private-token")
    assert "private-token" not in str(error.value)


def test_invalid_auth_and_incorrect_envelope_are_rejected():
    with pytest.raises(ValueError, match="Choose one"):
        check_collection(URL, basic_auth=("a", "b"), bearer_token="token")
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(
        200, headers={"content-type": "application/taxii+json;version=2.1"},
        json={"objects": [], "more": "true"},
    ))) as client:
        with pytest.raises(CollectionError, match="pagination"):
            check_collection(URL, client=client)


def test_raw_taxii_output_preserves_patterns_and_refuses_markings(tmp_path, monkeypatch):
    document = {"type": "bundle", "objects": [{
        "type": "indicator", "pattern": "[domain-name:value MATCHES '^test']"
    }]}
    monkeypatch.setattr("pathlens.taxii.fetch_collection", lambda *args, **kwargs: document)
    output = tmp_path / "raw.json"
    args = ["import-taxii", "--url", URL, "--source-name", "test", "--output", str(output),
            "--raw-stix"]
    first = CliRunner().invoke(app, args)
    assert first.exit_code == 0, first.output
    assert "MATCHES" in output.read_text()
    assert output.stat().st_mode & 0o077 == 0
    marked = tmp_path / "marked.json"
    document["objects"][0]["object_marking_refs"] = ["private"]
    args[args.index(str(output))] = str(marked)
    assert CliRunner().invoke(app, args).exit_code != 0
    assert not marked.exists()
