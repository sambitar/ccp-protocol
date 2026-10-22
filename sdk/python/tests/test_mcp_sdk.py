"""Real MCP client/server round trip over the Python SDK."""

import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SDK_DIR = os.path.dirname(HERE)
sys.path.insert(0, SDK_DIR)

from mcp import types  # noqa: E402
from mcp.client import Client  # noqa: E402
from mcp.server.lowlevel import Server  # noqa: E402

from ccp.adapters.mcp import McpServer  # noqa: E402
from ccp.agent import Agent  # noqa: E402
from world import STORE, build_world  # noqa: E402


def make_bridge(**overrides):
    confirm = overrides.pop("confirm", None)
    world = build_world(**overrides)
    bridge = McpServer(
        runtime=world["runtime"],
        agent=Agent(world["requester"]),
        grant=world["grant"],
        confirm=confirm,
    )
    return bridge


def make_server(bridge):
    async def on_list_tools(_context, _params):
        return types.ListToolsResult(tools=[
            types.Tool(
                name=tool.name,
                description=tool.description,
                inputSchema=tool.input_schema,
                outputSchema=tool.output_schema,
            )
            for tool in bridge.tools
        ])

    async def on_call_tool(_context, params):
        result = await bridge.call_tool(params.name, params.arguments or {})
        return types.CallToolResult(
            content=[types.TextContent(**block) for block in result.content],
            structuredContent=result.structured_content,
            isError=result.is_error,
        )

    return Server("ccp-test", version="0.0.0",
                  on_list_tools=on_list_tools,
                  on_call_tool=on_call_tool)


def text_of(result):
    return json.loads(result.content[0].text)


class McpSdkTests(unittest.IsolatedAsyncioTestCase):
    async def test_round_trip_authorized_and_refused(self):
        server = make_server(make_bridge())
        async with Client(server, raise_exceptions=True) as client:
            listing = await client.list_tools()
            self.assertEqual([tool.name for tool in listing.tools],
                             ["example.lookup"])

            result = await client.call_tool("example.lookup",
                                            {"item_id": "item-123"})
            self.assertFalse(result.is_error)
            self.assertEqual(text_of(result), STORE["item-123"])

            refused = await client.call_tool("files.search", {})
            self.assertTrue(refused.is_error)
            self.assertEqual(text_of(refused)["outcome"],
                             "intent_not_allowed")

    async def test_confirmation_through_a_host_callback(self):
        server = make_server(make_bridge(confirmation="per_action",
                                         confirm=lambda request: True))
        async with Client(server, raise_exceptions=True) as client:
            result = await client.call_tool("example.lookup",
                                            {"item_id": "item-123"})
            self.assertFalse(result.is_error)
            self.assertEqual(text_of(result), STORE["item-123"])


if __name__ == "__main__":
    unittest.main()
