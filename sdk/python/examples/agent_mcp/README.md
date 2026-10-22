# Example CCP agent (MCP, Python)

An MCP server that exposes one user-granted CCP capability as a tool. Every
call is signed by the agent key, submitted to the runtime, and checked against
the grant.

## Run

```sh
cd sdk/python
pip install '.[mcp]'
python examples/agent_mcp/demo.py   # in-memory client ↔ server round trip
python examples/agent_mcp/server.py # stdio server for a real MCP host
```

`demo.py` prints the tool list, an authorized lookup, and the refusal for an
ungranted tool:

```
tools: example.lookup
[host] approve example.lookup {"item_id": "item-123"}
[host] card: Example Service — Look up one item from the provider's catalogue (does not send data off the device)
lookup: {"item_id": "item-123", "name": "Widget"}
refused: {"outcome": "intent_not_allowed", "error": "intent_not_allowed"} (is_error=True)
```

## Register with an MCP host

Point the host at the stdio server with an absolute path:

```json
{
  "mcpServers": {
    "ccp-agent": {
      "command": "/usr/bin/python3",
      "args": ["/absolute/path/to/sdk/python/examples/agent_mcp/server.py"]
    }
  }
}
```

The server writes diagnostics to stderr; stdout is reserved for MCP frames.

## Trust boundaries

- **Approval is the host's job.** Both examples auto-approve so they run
  without a UI. That is not a trusted confirmation. A real host renders the
  `ConfirmationRequest.card`, shows the exact intent, params, and effects, and
  records the user's decision.
- **Provider text is data.** The tool description quotes the provider's
  description with an explicit "untrusted data" label.
- **Results are data.** Tool output is schema-validated and returned as JSON
  text (plus `structured_content` when the intent declares an output schema).
- **The grant is the whole authority.** One bridge serves one grant. Limits,
  replay, expiry, and revocation are enforced by the runtime.

## Files

| File | Purpose |
| --- | --- |
| `world.py` | Demo runtime, agent key, grant, and bridge |
| `server.py` | Stdio MCP server (`build_server` is reused by the demo) |
| `demo.py` | In-memory MCP client round trip |
