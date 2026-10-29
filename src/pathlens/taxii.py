"""Bounded TAXII 2.1 collection reader for an explicitly authorized endpoint."""

from __future__ import annotations

import json
from urllib.parse import urlsplit

import httpx

from .collectors import MAX_HTTP_BYTES, CollectionError
from .threat_intel import validate_https_url


def validate_collection_url(url: str) -> None:
    validate_https_url(url)
    parts = urlsplit(url)
    if parts.query or parts.fragment or not parts.path.endswith("/objects/"):
        raise ValueError("Expected a TAXII collection objects HTTPS URL without query or fragment")


def _read_envelope(
    client: httpx.Client,
    url: str,
    params: dict | None,
    auth: httpx.Auth | None,
    bearer_token: str | None,
) -> dict:
    try:
        headers = {"Accept": "application/taxii+json;version=2.1"}
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
        with client.stream(
            "GET",
            url,
            params=params,
            follow_redirects=False,
            headers=headers,
            auth=auth,
        ) as response:
            response.raise_for_status()
            content_type = response.headers.get("content-type", "").lower()
            pieces = [part.strip() for part in content_type.split(";")]
            if pieces[0] != "application/taxii+json":
                raise CollectionError("TAXII response has an unexpected content type")
            versions = [part for part in pieces[1:] if part.startswith("version=")]
            if versions and versions != ["version=2.1"]:
                raise CollectionError("TAXII response has an unsupported version")
            chunks = []
            size = 0
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > MAX_HTTP_BYTES:
                    raise CollectionError("TAXII response exceeds the size limit")
                chunks.append(chunk)
        return json.loads(b"".join(chunks))
    except (httpx.HTTPError, ValueError) as exc:
        raise CollectionError(f"TAXII source unavailable or invalid: {type(exc).__name__}") from exc


def fetch_collection(
    url: str,
    *,
    client: httpx.Client | None = None,
    basic_auth: tuple[str, str] | None = None,
    bearer_token: str | None = None,
) -> dict:
    validate_collection_url(url)
    if basic_auth is not None and bearer_token is not None:
        raise ValueError("Choose one TAXII authentication method")
    if basic_auth is not None:
        username, password = basic_auth
        if (
            not username
            or not password
            or ":" in username
            or any(ord(char) < 32 or ord(char) == 127 for char in username + password)
        ):
            raise ValueError("Invalid TAXII basic authentication input")
    if bearer_token is not None and (
        not bearer_token
        or len(bearer_token) > 4096
        or any(char.isspace() for char in bearer_token)
        or any(ord(char) < 33 or ord(char) > 126 for char in bearer_token)
    ):
        raise ValueError("Invalid TAXII bearer token")
    auth = httpx.BasicAuth(*basic_auth) if basic_auth is not None else None
    owned = client is None
    if client is None:
        client = httpx.Client(
            timeout=15.0,
            follow_redirects=False,
            trust_env=False,
            headers={"Accept": "application/taxii+json;version=2.1"},
        )
    try:
        items: list = []
        token: str | None = None
        seen: set[str] = set()
        for _ in range(10):
            params = {"next": token} if token else None
            envelope = _read_envelope(client, url, params, auth, bearer_token)
            if not isinstance(envelope, dict) or not isinstance(envelope.get("objects", []), list):
                raise CollectionError("Invalid TAXII envelope")
            items.extend(envelope.get("objects", []))
            if len(items) > 100_000:
                raise CollectionError("TAXII object limit exceeded")
            more = envelope.get("more", False)
            if not isinstance(more, bool):
                raise CollectionError("Invalid TAXII pagination flag")
            if not more:
                return {"type": "bundle", "objects": items}
            token = envelope.get("next")
            if not isinstance(token, str) or not token or len(token) > 1000 or token in seen:
                raise CollectionError(
                    "TAXII pagination requires a new next token; import incomplete"
                )
            seen.add(token)
        raise CollectionError("TAXII page limit reached; import incomplete")
    finally:
        if owned:
            client.close()
