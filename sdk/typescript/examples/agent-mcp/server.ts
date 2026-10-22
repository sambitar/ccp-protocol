import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";

import { createDemoAgent } from "./setup.ts";

const { bridge } = createDemoAgent({
  confirm(request) {
    // DEMO ONLY: a real host must ask the user and approve this exact action.
    // The printed card is the same §11.4 model a trusted UI would render.
    console.error(`[ccp] confirmation requested: ${request.intent}`);
    console.error(`[ccp]   who:    ${request.card.who}`);
    console.error(`[ccp]   what:   ${request.card.what}`);
    console.error(`[ccp]   reads:  ${request.card.dataRead.join(", ")}`);
    console.error(`[ccp]   egress: ${request.card.egress}`);
    console.error(`[ccp]   params: ${JSON.stringify(request.params)}`);
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

// stdout carries MCP frames; all diagnostics go to stderr.
await server.connect(new StdioServerTransport());
console.error(
  `[ccp] MCP server ready with: ${bridge.tools
    .map((tool) => tool.name)
    .join(", ")}`
);
