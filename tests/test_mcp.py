import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SAMPLE = Path(__file__).parents[1] / "examples" / "sample.json"


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
            unauthorized = await session.call_tool("scan_domain", {"domain": "example.com"})
            assert unauthorized.isError
            assert "authorization" in unauthorized.content[0].text.lower()

    asyncio.run(check())
