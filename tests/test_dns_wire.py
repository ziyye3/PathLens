"""Exercise real DNS packets against an isolated loopback server, not the Internet."""

import socketserver
import threading

import dns.message
import dns.rcode
import dns.resolver
import dns.rrset

from pathlens.analysis import analyze
from pathlens.collectors import collect_dns
from pathlens.models import Snapshot


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        packet, sock = self.request
        query = dns.message.from_wire(packet)
        question = query.question[0]
        name = question.name.to_text().rstrip(".")
        kind = dns.rdatatype.to_text(question.rdtype)
        self.server.queries.append((name, kind))
        response = dns.message.make_response(query)
        if (name, kind) == ("alias.example.com", "CNAME"):
            response.answer.append(
                dns.rrset.from_text(name + ".", 60, "IN", "CNAME", "test.cloudfront.net.")
            )
        elif (name, kind) == ("test.cloudfront.net", "A"):
            response.answer.append(dns.rrset.from_text(name + ".", 60, "IN", "A", "192.0.2.7"))
        elif name not in ("alias.example.com", "test.cloudfront.net"):
            response.set_rcode(dns.rcode.NXDOMAIN)
        sock.sendto(response.to_wire(), self.client_address)


def test_dns_collector_follows_cname_via_a_real_recursive_endpoint():
    with socketserver.UDPServer(("127.0.0.1", 0), DNSHandler) as server:
        server.queries = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = ["127.0.0.1"]
            resolver.port = server.server_address[1]
            resolver.timeout = 1
            resolver.lifetime = 2
            records = collect_dns(["alias.example.com"], resolver=resolver)
        finally:
            server.shutdown()
            thread.join(timeout=2)
    assert ("alias.example.com", "CNAME") in server.queries
    assert ("test.cloudfront.net", "A") in server.queries
    assert all(record.resolver == "127.0.0.1" for record in records)
    report = analyze(Snapshot(domain="example.com", dns_records=records))
    asset = next(item for item in report.assets if item.name == "alias.example.com")
    assert asset.cname_chain == ["alias.example.com", "test.cloudfront.net"]
    assert asset.addresses == ["192.0.2.7"]
    assert {finding.rule_id for finding in asset.findings} == {"aws-infrastructure"}
