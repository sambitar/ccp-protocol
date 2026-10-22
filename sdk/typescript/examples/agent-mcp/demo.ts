/**
 * Runnable proof of the MCP round trip: a real Client talks to a real Server
 * over an in-memory transport, and every tool call goes through the runtime.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";

import { createDemoAgent } from "./setup.ts";

const { bridge } = createDemoAgent({
  confirm(request) {
    // DEMO ONLY: a real host asks the user before approving.
    console.log(
      `[host] approve ${request.intent} ${JSON.stringify(request.params)}`
    );
    console.log(
      `[host] card: ${request.card.who} — ${request.card.what} (${request.card.egress})`
    );
    return true;
  },
});

const server = new Server(
  { name: "ccp-agent-demo", version: "0.4.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: bridge.tools as unknown as Tool[],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const result = await bridge.callTool(
    request.params.name,
    request.params.arguments ?? {}
  );
  return result as CallToolResult;
});

const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
await server.connect(serverTransport);

const client = new Client({ name: "ccp-demo-client", version: "0.4.0" });
await client.connect(clientTransport);

const { tools } = await client.listTools();
console.log(`tools: ${tools.map((tool) => tool.name).join(", ")}`);

const granted = await client.callTool({
  name: "example.lookup",
  arguments: { item_id: "item-123" },
});
console.log(`lookup: ${text(granted)}`);

const refused = await client.callTool({
  name: "files.search",
  arguments: {},
});
console.log(`refused: ${text(refused)} (isError=${refused.isError === true})`);

await client.close();
await server.close();

function text(result: unknown): string {
  const blocks = (
    result as { content: Array<{ type: string; text: string }> }
  ).content;
  return blocks[0].text;
}
