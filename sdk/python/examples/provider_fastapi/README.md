# Example CCP provider (FastAPI)

A single-file provider that serves a signed manifest, accepts signed signals
through `ccp.adapters.fastapi`, and confirms through a demo endpoint.

## Run

```sh
cd sdk/python
pip install '.[fastapi]'
python examples/provider_fastapi/server.py
```

The server listens on `http://127.0.0.1:8788` (override with `PORT`) and
prints a ready-to-run `curl` with a fresh, single-use demo signal.

## Flow

1. `GET /manifest` returns the signed manifest verbatim.
2. `POST /ccp` with `{ "signal": "<canonical json>" }`. The adapter resolves
   the sender key, then `Runtime.submit` verifies the signature and decides.
   The demo grant requires confirmation:

   ```json
   { "outcome": "confirmation_required", "request_id": "…", "pending_id": "…" }
   ```

3. `POST /ccp/confirm` with `{ "pending_id": "…", "approved": true }` runs the
   intent and returns the result.

Signals are single-use: re-posting returns `replay_detected` with HTTP 409.
Restart the server for a fresh demo signal.

## What is intentionally simplified

- **One requester.** `key_resolver` returns the demo key for every request. A
  production provider resolves the key from an authenticated channel bound to
  a stored contact; it never trusts a key supplied inside the signal.
- **In-memory state.** Grants, replay ids, limit counters, and pending
  confirmations live in the process.
- **Demo confirmation.** `POST /ccp/confirm` stands in for the provider's
  trusted UI. In production the decision must come from an authenticated
  human surface that shows the §11.4 card.
- **No transport security.** Put the service behind TLS; CCP protects the
  document, not the connection.

The adapter parses only the envelope and forwards `body["signal"]` as a
string, so the runtime's strict parser sees the exact wire bytes.
