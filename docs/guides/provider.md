# Quickstart — provider

A provider accepts signed signals, resolves the sender's key from its own
authenticated channel, and lets the runtime decide. The adapters never
authorize anything themselves.

The full HTTP binding (channel binding, retries, limits, and privacy) is in
[`transport.md`](transport.md).

## Express

```ts
import express from "express";
import { providerMiddleware } from "ccp-core/express";

const app = express();
app.use(express.json());

app.post(
  "/ccp",
  providerMiddleware({
    runtime,
    keyResolver: (req) => publicKeys.get(req.header("x-contact-id")),
  })
);
```

The client sends `{ "signal": "<canonical json>" }`. The adapter forwards
the string untouched, so the runtime's strict parser sees the exact bytes.

## Next.js / Web routes

```ts
import {
  createManifestHandler,
  createSignalHandler,
} from "ccp-core/next";

export const GET = createManifestHandler({ manifest: manifestWire });
export const POST = createSignalHandler({ runtime, keyResolver });
```

The signal handler reads the raw canonical JSON body; the manifest handler
serves the signed wire verbatim.

## FastAPI

```python
from fastapi import FastAPI
from ccp.adapters.fastapi import manifest_router, provider_router

app = FastAPI()
app.include_router(manifest_router(manifest.document))
app.include_router(provider_router(runtime, key_resolver))
```

`key_resolver(request)` returns the sender's `VerifyingKey` or `None`; it may
be sync or async.

## Status mapping

All HTTP adapters agree:

| Decision | Status |
| --- | --- |
| `authorized`, `confirmation_required` | 200 |
| `invalid_request` | 400 |
| unknown sender | 401 |
| `unauthenticated`, `no_matching_grant` | 403 |
| other refusals | 409 |
| unexpected exception | 500 `outcome_unknown` |

## Confirmation

`confirmation_required` is not an execution. The provider's own trusted UI
must show the §11.4 card and call `runtime.confirm(pending_id, approved)`
over an authenticated path. Do not confirm from the request handler.

## Verify

```sh
cd sdk/typescript && npm run provider      # Express, http://127.0.0.1:8787
cd sdk/python && python examples/provider_fastapi/server.py   # http://127.0.0.1:8788
```
