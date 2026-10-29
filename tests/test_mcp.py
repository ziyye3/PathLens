import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SAMPLE = Path(__file__).parents[1] / "examples" / "sample.json"
FEED = Path(__file__).parents[1] / "examples" / "threat-feed.json"


def test_real_mcp_stdio_handshake_and_offline_tool():
    async def check():
        params = StdioServerParameters(command=sys.executable, args=["-m", "pathlens.mcp_server"])
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            assert {tool.name for tool in listed.tools} == {"analyze_snapshot", "scan_domain"}
            result = await session.call_tool(
                "analyze_snapshot", {"snapshot": json.loads(SAMPLE.read_text())}
            )
            assert not result.isError
            assert result.structuredContent["domain"] == "example.com"
            assert result.structuredContent["collection_mode"] == "snapshot"
            with_feed = await session.call_tool(
                "analyze_snapshot",
                {
                    "snapshot": json.loads(SAMPLE.read_text()),
                    "threat_feed": json.loads(FEED.read_text()),
                },
            )
            assert not with_feed.isError
            assert with_feed.structuredContent["threat_feed"]["match_count"] == 2
            stix = json.loads((SAMPLE.parent / "stix-pattern-indicators.json").read_text())
            stix["objects"][0]["pattern"] = "[domain-name:value = 'cdn.example.com']"
            correlated = await session.call_tool(
                "analyze_snapshot",
                {"snapshot": json.loads(SAMPLE.read_text()), "stix_bundle": stix},
            )
            assert not correlated.isError
            assert correlated.structuredContent["stix_correlation"]["match_count"] == 1
            evidence = correlated.structuredContent["stix_correlation"]["results"][0]["evidence"]
            assert evidence[0]["dns_record_index"] == 2
            combined = await session.call_tool(
                "analyze_snapshot",
                {
                    "snapshot": json.loads(SAMPLE.read_text()),
                    "cve_observations": json.loads(
                        (SAMPLE.parent / "cve-observations.json").read_text()
                    ),
                    "kev_catalog": json.loads((SAMPLE.parent / "kev-sample.json").read_text()),
                    "exposure_observations": json.loads(
                        (SAMPLE.parent / "exposure-observations.json").read_text()
                    ),
                },
            )
            assert not combined.isError
            assert combined.structuredContent["cve_correlation"]["match_count"] == 1
            assert combined.structuredContent["exposure_correlation"]["match_count"] == 1
            product = await session.call_tool(
                "analyze_snapshot",
                {
                    "snapshot": json.loads(SAMPLE.read_text()),
                    "product_observations": json.loads(
                        (SAMPLE.parent / "product-observations.json").read_text()
                    ),
                    "kev_catalog": json.loads((SAMPLE.parent / "kev-sample.json").read_text()),
                },
            )
            assert not product.isError
            assert product.structuredContent["product_correlation"]["candidate_count"] == 1
            osv = await session.call_tool(
                "analyze_snapshot",
                {
                    "snapshot": json.loads(SAMPLE.read_text()),
                    "osv_observations": json.loads(
                        (SAMPLE.parent / "osv-observations.json").read_text()
                    ),
                    "osv_results": json.loads((SAMPLE.parent / "osv-sample.json").read_text()),
                },
            )
            assert not osv.isError
            assert osv.structuredContent["osv_correlation"]["match_count"] == 1
            unauthorized = await session.call_tool("scan_domain", {"domain": "example.com"})
            assert unauthorized.isError
            assert "authorization" in unauthorized.content[0].text.lower()

    asyncio.run(check())
