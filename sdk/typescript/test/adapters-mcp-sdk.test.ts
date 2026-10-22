import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";

import { createMcpServer } from "../src/adapters/mcp.js";
import type { McpServer } from "../src/adapters/mcp.js";
import { Agent } from "../src/agent.js";
import { REQUESTER_SEED, buildWorld } from "./world.js";
import type { WorldOptions } from "./world.js";

function build(options: WorldOptions = {}, confirm?: () => boolean) {
  const world = buildWorld(options);
  return createMcpServer({
    runtime: world.runtime,
    agent: new Agent(REQUESTER_SEED),
    grant: world.grant,
    confirm,
  });
}

async function connect(bridge: McpServer) {
  const server = new Server(
    { name: "ccp-test", version: "0.0.0" },
    { capabilities: { tools: {} } }
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: bridge.tools as never,
  }));
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const result = await bridge.callTool(
      request.params.name,
      request.params.arguments ?? {}
    );
    return result as CallToolResult;
  });

  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);

  const client = new Client({ name: "ccp-test-client", version: "0.0.0" });
  await client.connect(clientTransport);
  return { client, server };
}

function textOf<T = Record<string, unknown>>(result: unknown): T {
  const blocks = (
    result as { content: Array<{ type: string; text: string }> }
  ).content;
  return JSON.parse(blocks[0].text) as T;
}

describe("MCP client round trip", () => {
  it("lists and calls a granted capability", async () => {
    const { client, server } = await connect(build());
    try {
      const { tools } = await client.listTools();
      expect(tools.map((tool) => tool.name)).toEqual(["example.lookup"]);

      const result = await client.callTool({
        name: "example.lookup",
        arguments: { item_id: "item-123" },
      });

      expect(result.isError).toBeFalsy();
      expect(textOf(result)).toEqual({ item_id: "item-123", name: "Widget" });
    } finally {
      await client.close();
      await server.close();
    }
  });

  it("returns intent_not_allowed for an ungranted tool", async () => {
    const { client, server } = await connect(build());
    try {
      const result = await client.callTool({
        name: "files.search",
        arguments: {},
      });

      expect(result.isError).toBe(true);
      expect(textOf(result).outcome).toBe("intent_not_allowed");
    } finally {
      await client.close();
      await server.close();
    }
  });

  it("resolves confirmation through the host callback", async () => {
    const { client, server } = await connect(
      build({ confirmation: "per_action" }, () => true)
    );
    try {
      const result = await client.callTool({
        name: "example.lookup",
        arguments: { item_id: "item-123" },
      });

      expect(result.isError).toBeFalsy();
      expect(textOf(result)).toEqual({ item_id: "item-123", name: "Widget" });
    } finally {
      await client.close();
      await server.close();
    }
  });
});
