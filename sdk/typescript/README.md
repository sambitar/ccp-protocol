# ccp-core — CCP TypeScript SDK

The TypeScript implementation of the Capability Contacts Protocol (draft
v0.5), shaped by role: **Requester**, **Consumer**, **Runtime**, **Agent**.
It reproduces the frozen v1 through v5 vectors in `../../test-vectors/`.

Runs in browsers and Node (no Node-only APIs in `src/`).

## Install

```sh
npm install ccp-core
```

## Requester — sign a manifest and a signal

```ts
import { Requester, publicFromSeed } from "ccp-core";

const seed = crypto.getRandomValues(new Uint8Array(32));
const requester = new Requester(seed);

const manifest = requester.manifest({
  provider: { id: requester.keyId, name: "Example Service" },
  version: 1,
  intents: {
    "example.lookup": {
      params_schema: "schema:example.lookup.params.v1",
      result_schema: "schema:example.lookup.result.v1",
      required_capabilities: ["store.read"],
      placement: "local",
      data_egress: { network: false, fields: [] },
      confirmation: "grant-policy",
    },
  },
});

const signal = requester.signal({
  requestId: "req-1",
  grantDigest: "sha256:…", // the grant's manifest_digest
  intent: "example.lookup",
  params: { item_id: "item-123" },
  issuedAt: "2026-10-22T12:00:00Z",
  expiresAt: "2026-10-22T12:01:00Z",
});
```

## Consumer — verify and render a permission card

```ts
import { verifyManifest, verifySignal, permissionCard } from "ccp-core";

const verified = verifyManifest(manifest); // throws CcpError on failure
const card = permissionCard(verified.manifest, "example.lookup", {
  providerName: "Example Service",
});
// card.who / card.what / card.dataRead / card.where / card.egress /
// card.effects / card.recurrence / card.revoke

const inbox = verifySignal(signal, senderPublicKey);
```

## Runtime — enforce a grant

```ts
import {
  HostRegistry,
  MemoryAuditLog,
  MemoryGrantStore,
  MemoryManifestStore,
  Runtime,
  SchemaRegistry,
  createGrant,
  verifyManifest,
} from "ccp-core";

const manifest = verifyManifest(manifestWire);

const grant = createGrant({
  requesterKey: requester.keyId,
  contactId: "c-1",
  manifest,
  intents: ["example.lookup"],
  // Defaults to the manifest's suggested_limits. Values above the
  // suggestion are rejected (§9.2).
  limits: { calls_per_hour: 5 },
  // Defaults to the manifest policy. Confirmation can be tightened but
  // never relaxed to "none".
  expiresAt: "2026-10-22T23:00:00Z",
});

const hosts = new HostRegistry();
hosts.registerHost("store.read", (id: string) => ({ item_id: id }));
hosts.registerIntent("example.lookup", (params, access) =>
  access.call("store.read", params.item_id)
);

const runtime = new Runtime({
  grants: new MemoryGrantStore([grant]),
  manifests: new MemoryManifestStore([manifest]),
  schemas: new SchemaRegistry({
    "schema:example.lookup.params.v1": {
      type: "object",
      properties: { item_id: { type: "string" } },
      required: ["item_id"],
      additionalProperties: false,
    },
  }),
  hosts,
  audit: new MemoryAuditLog(),
});

const decision = await runtime.submit(signal, requesterPublicKey);
if (decision.outcome === "confirmation_required") {
  await runtime.confirm(decision.pending_id!, true); // trusted UI decision
}
```

`decision.outcome` is `authorized`, `confirmation_required`, or a §10.4
rejection code. `createGrant` only narrows what the manifest declares:
limits never exceed `suggested_limits`, confirmation is never relaxed,
capabilities come from the enabled intents, and placement/egress are
derived from them.

## Identity and admission (§25.8)

Publish a signed identity document, verify one for a known contact, and
let a reviewed policy answer matching requests without a click.

```ts
import {
  buildAdmissionPolicy,
  buildIdentityDocument,
  verifyAdmissionPolicy,
  verifyIdentityDocument,
} from "ccp-core";

const identity = buildIdentityDocument(
  { name: "Example Service", manifestDigest: manifest.digest,
    issuedAt: "2026-10-22T00:00:00Z", expiresAt: "2027-10-22T00:00:00Z" },
  seed
);

const peer = verifyIdentityDocument(identity, {
  expectedIdentity: knownContactKey,
  manifestDigest: manifest.digest,
});

const policy = verifyAdmissionPolicy(
  buildAdmissionPolicy(
    { version: 1, default: "confirm", rules, issuedAt, expiresAt },
    hostSeed
  ),
  { expectedHost: hostKey }
);

const { result, grant } = await runtime.admitRequest({
  policy,
  request: { requesterKey, contactId, intent, risk, now },
  manifest,
});
// result.decision is allow | confirm | deny; grant is set on allow.
```

Accepting an invitation creates a contact, never a grant. `default` must
be `confirm` or `deny`, and only `read`/`disclose` intents can be
admitted. Policy grants use a deterministic id, so a revocation is not
undone by the next matching request. See
[`docs/guides/identity.md`](../../docs/guides/identity.md) and
[`docs/consistency-audit.md`](../../docs/consistency-audit.md).

## Durable stores

`Runtime` accepts pluggable stores. The interfaces are `GrantStore`,
`ManifestStore`, `ReplayStore`, `LimitStore`, `PendingStore`, and
`AuditStore`; the in-memory implementations are prefixed with `Memory`.
Authorization-state methods may be synchronous (the defaults, or a
synchronous SQLite driver) or asynchronous (Postgres, a remote store);
the runtime awaits them. `ManifestStore` stays synchronous because
verified manifests are immutable and can be loaded at startup.

Three methods carry atomicity requirements:

- `LimitStore.tryReserve` reserves one unit against every limit or none,
  in one transaction.
- `ReplayStore.markIfNew` inserts atomically and returns `false` when the
  request id already exists.
- `PendingStore.take` removes and returns a confirmation atomically, so it
  can be resolved at most once across processes.

```ts
const runtime = new Runtime({
  grants: postgresGrants,
  manifests: new MemoryManifestStore([manifest]), // immutable; load at startup
  replay: postgresReplay,
  limits: postgresLimits,
  pending: postgresPending,
  audit: postgresAudit,
  schemas,
  hosts,
});
```

See `docs/guides/persistence.md` for the SQL shape and the full contract.

### Node (SQLite)

The package ships a durable implementation on the built-in `node:sqlite`
module, with no extra dependency. It is Node-only and never imported by the
browser-safe core:

```ts
import { Runtime } from "ccp-core";
import { SqliteStores } from "ccp-core/node";

const stores = new SqliteStores("ccp.db"); // or ":memory:"
const runtime = new Runtime({ ...stores, schemas, hosts });
// ...
stores.close();
```

`node:sqlite` requires Node 22.5+ (available without a flag in Node 24, where
it is still marked experimental).

## Agent — wrap a tool call

```ts
import { Agent, attenuates } from "ccp-core";

const agent = new Agent(agentSeed);
const wire = agent.signalFor(
  { intent: "example.lookup", params: { item_id: "item-123" } },
  grant,
  { requestId: "req-2", issuedAt: "…", expiresAt: "…" }
);

// Delegation must be no broader than the parent grant (§15.1).
attenuates(parentGrant, childGrant);
```

## Adapters — meet each framework in place

Adapters are subpath exports, so the core bundle stays free of Express and
React. They never decide authorization themselves; they parse the request,
resolve the sender key, and call the runtime.

### Express provider

```ts
import express from "express";
import { providerMiddleware } from "ccp-core/express";

const app = express();
app.use(express.json());
app.post(
  "/ccp",
  providerMiddleware({
    runtime,
    // Resolve from your authenticated channel, not from the signal.
    keyResolver: (req) => publicKeys.get(req.header("x-contact")),
  })
);
```

The middleware reads `{ "signal": "<canonical json>" }` and forwards the
string untouched. It answers 200 for `authorized`/`confirmation_required`,
400 for `invalid_request`, 401 when the sender is unknown, 403 for
`unauthenticated`/`no_matching_grant`, and 409 for other refusals.

### Next.js / Web routes

```ts
import { createManifestHandler, createSignalHandler } from "ccp-core/next";

export const GET = createManifestHandler({ manifest: manifestWire });
export const POST = createSignalHandler({ runtime, keyResolver });
```

The signal handler takes the raw canonical JSON as the body and returns a
standard `Response`; it has no Next.js dependency and also works in any
`Request`/`Response` runtime. The manifest handler serves the signed wire
verbatim.

### React permission card

```tsx
import { usePermissionCard } from "ccp-core/react";

const { status, card, decision, approve, deny } = usePermissionCard({
  runtime,
  signal,
  publicKey,
  card: permissionCardModel,
});
```

Headless: render `card` however you like. `status` is `loading`,
`authorized`, `confirmation_required`, `rejected`, or `cancelled`; calling
`approve()` / `deny()` resolves a pending confirmation. The hook submits once
per signal.

### MCP agent bridge

```ts
import { createMcpServer } from "ccp-core/mcp";

const bridge = createMcpServer({
  runtime,
  agent, // Agent key the grant is bound to
  grant,
  // Trusted host decision. Omit to surface confirmation_required instead.
  confirm: async ({ params, card }) => askUser(card, params),
});

registerToolsOnYourMcpServer(bridge.tools);
const result = await bridge.callTool("example.lookup", {
  item_id: "item-123",
});
```

One bridge serves one grant; tool names are the granted intent names. The
adapter signs every call and lets the runtime decide. It never auto-approves:
without `confirm`, a `confirmation_required` outcome is returned with the
pending id and the §11.4 card. Tool results are data, not instructions.

Runnable examples: `examples/provider-node/` (HTTP provider) and
`examples/agent-mcp/` (MCP; `npm run mcp:demo`).

## Tests

```sh
npx vitest run        # v1/v2/v3 vectors + role unit tests
npx tsc --noEmit      # typecheck
```
