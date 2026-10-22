# Quickstart — agent (MCP)

An agent acts as a requester. A local MCP server exposes the user's granted
intents as tools; every call is signed and checked by the runtime, and every
confirmation is a host decision.

## TypeScript bridge

```ts
import { Agent } from "ccp-core";
import { createMcpServer } from "ccp-core/mcp";

const agent = new Agent(agentSeed);       // key the grant is bound to

const bridge = createMcpServer({
  runtime,
  agent,
  grant,
  // Trusted host decision. Omit to surface confirmation_required instead.
  confirm: async ({ card, params }) => await askUser(card, params),
});

// Register bridge.tools with your MCP transport.
const result = await bridge.callTool("example.lookup", {
  item_id: "item-123",
});
```

Tool names are the granted intent names. One bridge serves one grant.

## Python bridge

```python
from ccp import Agent
from ccp.adapters.mcp import McpServer

agent = Agent(signing_key)

bridge = McpServer(
    runtime=runtime,
    agent=agent,
    grant=grant,
    confirm=lambda request: ask_user(request.card, request.params),
)

result = await bridge.call_tool("example.lookup", {"item_id": "item-123"})
```

Wire `bridge.tools` into `mcp.server.lowlevel.Server` and adapt
`bridge.call_tool` results to `types.CallToolResult` (see
`sdk/python/examples/agent_mcp/`).

## Trust boundary

- **No auto-approval in the adapter.** Without `confirm` the call returns
  `confirmation_required` with the pending id and card. A thrown callback
  counts as denial.
- **Provider text is data.** Tool descriptions label provider text as
  untrusted; the runtime still enforces the grant.
- **Tool output is data.** Results are schema-validated and returned as JSON
  text (plus structured content when the intent declares an output schema).
- **The grant is the whole authority.** Limits, replay, expiry, and
  revocation are enforced per call.

## Verify

```sh
cd sdk/typescript && npm run mcp:demo
cd sdk/python && python examples/agent_mcp/demo.py
```
