# Example CCP provider (Node + Express)

A single-file provider that serves a signed manifest, provisions one demo
grant, and accepts signed signals. It uses `ccp-core` for the runtime and
`ccp-core/express` for the HTTP adapter.

## Run

```sh
cd sdk/typescript
npm install
npm run provider
```

The example is a `.ts` file executed directly, so it needs Node 24 (or 23.6+).
On older Node, run `npx tsx examples/provider-node/server.ts` after
`npm run build`.

The script builds the SDK, then starts the server on `http://127.0.0.1:8787`
(override with `PORT`). On startup it prints:

- the manifest digest the grant is bound to
- a ready-to-run `curl` with a fresh, single-use demo signal

## Flow

1. `GET /manifest` returns the signed manifest verbatim.
2. `POST /ccp` with `{ "signal": "<canonical json>" }`. The adapter resolves
   the sender key, then `Runtime.submit` verifies the signature and decides.
   The demo grant requires confirmation, so the response is:

   ```json
   { "outcome": "confirmation_required", "request_id": "…", "pending_id": "…" }
   ```

3. `POST /ccp/confirm` with `{ "pending_id": "…", "approved": true }` runs
   the intent and returns the authorization result.

Signals are single-use: re-posting the same signal returns `replay_detected`
with HTTP 409. Restart the server for a fresh demo signal.

## What is intentionally simplified

- **One requester.** `keyResolver` returns the demo requester key. A
  production provider resolves the key from an authenticated channel bound to
  a stored contact; it never trusts a key supplied inside the signal.
- **In-memory state.** Grants, replay ids, limit counters, and pending
  confirmations live in the process. Replace the stores before scaling out.
- **No transport security.** Put the service behind TLS; CCP protects the
  document, not the connection.
- **Plain HTTP confirmation.** The demo approves through `POST /ccp/confirm`.
  A production provider confirms through its own trusted UI or device, and
  authenticates that decision separately.

The Express adapter only parses the envelope and forwards `body.signal` as a
string, so the runtime's strict parser sees the exact wire bytes. Do not
pre-parse the signal with `JSON.parse` in your own middleware.
