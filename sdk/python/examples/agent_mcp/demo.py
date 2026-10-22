"""In-memory MCP client round trip for the CCP agent example."""

import asyncio
import json

from mcp.client import Client

from server import build_server


def _demo_confirm(request):
    # DEMO ONLY: a real host asks the user before approving.
    print("[host] approve %s %s"
          % (request.intent, json.dumps(request.params)))
    print("[host] card: %s — %s (%s)"
          % (request.card.who, request.card.what, request.card.egress))
    return True


async def main():
    server, _bridge = build_server(confirm=_demo_confirm)
    async with Client(server, raise_exceptions=True) as client:
        listing = await client.list_tools()
        print("tools:", ", ".join(tool.name for tool in listing.tools))

        result = await client.call_tool("example.lookup",
                                        {"item_id": "item-123"})
        print("lookup:", result.content[0].text)

        refused = await client.call_tool("files.search", {})
        print("refused:", refused.content[0].text,
              "(is_error=%s)" % refused.is_error)


if __name__ == "__main__":
    asyncio.run(main())
