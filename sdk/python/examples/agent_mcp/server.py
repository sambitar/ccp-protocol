"""Stdio MCP server exposing one user-granted CCP capability."""

import asyncio
import json
import sys

from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from world import create_world


def _demo_confirm(request):
    # DEMO ONLY: a real host asks the user before approving. The printed card
    # is the same §11.4 model a trusted UI would render.
    print("[ccp] confirmation requested: %s" % request.intent,
          file=sys.stderr)
    print("[ccp]   who:    %s" % request.card.who, file=sys.stderr)
    print("[ccp]   what:   %s" % request.card.what, file=sys.stderr)
    print("[ccp]   reads:  %s" % ", ".join(request.card.data_read),
          file=sys.stderr)
    print("[ccp]   egress: %s" % request.card.egress, file=sys.stderr)
    print("[ccp]   params: %s" % json.dumps(request.params), file=sys.stderr)
    return True


def build_server(*, confirm=None):
    """Build the MCP server and bridge; reuse from the in-memory demo."""
    bridge, _runtime = create_world(confirm=confirm)

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

    server = Server(
        "ccp-agent-demo",
        version="0.4.0",
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )
    return server, bridge


async def main():
    server, bridge = build_server(confirm=_demo_confirm)
    print("[ccp] MCP server ready with: %s"
          % ", ".join(tool.name for tool in bridge.tools), file=sys.stderr)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream,
                         server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
