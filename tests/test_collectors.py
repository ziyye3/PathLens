import socket

import dns.resolver
import httpx
import pytest

from pathlens.collectors import AWS_RANGES_URL, CRT_URL, CollectionError, _read_json, collect_live


def test_live_requires_authorization_before_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", lambda *args: pytest.fail("unexpected network"))
    with pytest.raises(CollectionError, match="authorization"):
        collect_live("example.com", authorized=False)


def test_live_only_requests_public_sources_and_recursive_resolver(monkeypatch):
    requests = []
    resolvers = []

    def handler(request):
        requests.append(str(request.url))
        if request.url.host == "crt.sh":
            return httpx.Response(200, json=[{"name_value": "api.example.com\nevil.com"}])
        if request.url.host == "ip-ranges.amazonaws.com":
            return httpx.Response(200, json={"prefixes": [], "ipv6_prefixes": []})
        pytest.fail(f"unexpected HTTP target: {request.url}")

    real_client = httpx.Client

    def client_factory(**kwargs):
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    class FakeResolver:
        def __init__(self, *, configure):
            assert configure is False
            self.nameservers = []
            resolvers.append(self)

        def resolve(self, name, kind, **kwargs):
            assert self.nameservers == ["1.1.1.1"]
            assert name in {"example.com", "api.example.com"}
            raise dns.resolver.NoAnswer

    monkeypatch.setattr("pathlens.collectors.httpx.Client", client_factory)
    monkeypatch.setattr("pathlens.collectors.dns.resolver.Resolver", FakeResolver)
    monkeypatch.setattr(socket.socket, "connect", lambda *args: pytest.fail("unexpected network"))
    result = collect_live("example.com", authorized=True)
    assert len(requests) == 2
    assert requests[0].startswith(CRT_URL)
    assert requests[1] == AWS_RANGES_URL
    assert {record.name for record in result.dns_records} == {"example.com", "api.example.com"}
    assert resolvers


def test_redirect_is_not_followed():
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(302, headers={"location": "https://example.com"})
        )
    ) as client:
        with pytest.raises(CollectionError):
            _read_json(client, CRT_URL)


def test_invalid_target_is_rejected_before_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", lambda *args: pytest.fail("unexpected network"))
    with pytest.raises(ValueError):
        collect_live("https://example.com", authorized=True)
