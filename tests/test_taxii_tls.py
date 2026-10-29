"""Exercise authenticated TAXII over real TLS and loopback only."""

import base64
import json
import shutil
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest

from pathlens.collectors import CollectionError
from pathlens.taxii import check_collection, fetch_collection

SAMPLE = Path(__file__).parents[1] / "examples" / "sample-stix.json"


def test_authenticated_taxii_over_local_tls(tmp_path):
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl is unavailable")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
        timeout=20,
    )
    expected = "Basic " + base64.b64encode(b"test-user:test-password").decode()
    expected_bearer = "Bearer test-token"
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            seen.append(self.headers.get("Authorization"))
            if self.headers.get("Authorization") not in {expected, expected_bearer}:
                self.send_response(401)
                self.end_headers()
                return
            body = json.dumps({"objects": json.loads(SAMPLE.read_text())["objects"]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/taxii+json;version=2.1")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    except PermissionError:
        pytest.skip("sandbox does not allow a loopback listener")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"https://127.0.0.1:{server.server_port}/api/objects/"
        client_context = ssl.create_default_context(cafile=str(cert))
        with httpx.Client(verify=client_context, trust_env=False) as client:
            bundle = fetch_collection(url, client=client, basic_auth=("test-user", "test-password"))
            assert check_collection(url, client=client, bearer_token="test-token") == (1, False)
            with pytest.raises(CollectionError, match="HTTP 401"):
                check_collection(url, client=client, basic_auth=("test-user", "wrong"))
        with httpx.Client(trust_env=False) as client:
            with pytest.raises(CollectionError):
                check_collection(url, client=client, bearer_token="test-token")
        assert len(bundle["objects"]) == 1
        assert seen[:2] == [expected, expected_bearer]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
