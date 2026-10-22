# Example CCP agent (MCP)

An MCP server that exposes one user-granted CCP capability as a tool. Every
tool call is signed by the agent key, submitted to the runtime, and checked
against the grant; the model never holds authority of its own.

## Run

```sh
cd sdk/typescript
npm install
npm run build
npm run mcp:demo   # in-memory client ↔ server round trip
npm run mcp        # stdio server for a real MCP host
```

The example is a `.ts` file executed directly, so it needs Node 24 (or
23.6+). On older Node, build the SDK and run the files with `npx tsx`.

`mcp:demo` prints the tool list, an authorized lookup, and the refusal for an
ungranted tool:

```
tools: example.lookup
[host] approve example.lookup {"item_id":"item-123"}
[host] card: Example Service — Look up one item from the provider's catalogue (does not send data off the device)
lookup: {"item_id":"item-123","name":"Widget"}
refused: {"outcome":"intent_not_allowed","error":"intent_not_allowed"} (isError=true)
```

## Register with an MCP host

Use an absolute path and point at the TypeScript entry point:

```json
{
  "mcpServers": {
    "ccp-agent": {
      "command": "node",
      "args": ["/absolute/path/to/sdk/typescript/examples/agent-mcp/server.ts"]
    }
  }
}
```

The server writes diagnostics to stderr; stdout is reserved for MCP frames.

## Trust boundaries

- **Approval is the host's job.** `server.ts` auto-approves so the demo runs
  without a UI. That is not a trusted confirmation and must not be copied into
  production. A real host renders the `ConfirmationRequest` card, shows the
  exact intent, params, and effects, and records the user's decision.
- **Provider text is data.** The tool description quotes the provider's
  description with an explicit "untrusted data" label. It cannot change the
  grant; the runtime decides every call.
- **Results are data.** Tool output is schema-validated, then returned as JSON
  text (plus structured content when the intent declares an output schema). Do
  not treat it as instructions.
- **The grant is the whole authority.** One bridge serves one grant. A tool
  outside the grant fails with `intent_not_allowed`; limits, replay, expiry,
  and revocation are enforced by the runtime.

## Files

| File | Purpose |
| --- | --- |
| `setup.ts` | Demo runtime, agent key, grant, and bridge |
| `server.ts` | Stdio MCP server |
| `demo.ts` | In-process MCP client round trip |
