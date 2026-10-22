# Quickstart — runtime

The runtime is the enforcement point: it verifies signatures, matches grants,
applies limits and replay protection, performs two-phase confirmation, and
calls host functions. Adapters only parse and delegate.

## TypeScript

```ts
import {
  HostRegistry,
  MemoryStores,
  Runtime,
  SchemaRegistry,
  publicFromSeed,
} from "ccp-core";

const schemas = new SchemaRegistry({
  "schema:example.lookup.params.v1": paramsSchema,
});

const hosts = new HostRegistry();
hosts.registerHost("store.read", (itemId: string) => store[itemId]);
hosts.registerIntent("example.lookup", (params, access) =>
  access.call("store.read", params.item_id)
);

const stores = new MemoryStores({ grants: [grant], manifests: [manifest] });
const runtime = new Runtime({
  ...stores,
  schemas,
  hosts,
  clock: () => now,
});

const decision = await runtime.submit(signal, publicFromSeed(requesterSeed));

if (decision.outcome === "confirmation_required") {
  // Only a trusted UI decides this.
  await runtime.confirm(decision.pending_id!, true);
}
```

- `submit` and `confirm` are asynchronous because store implementations may
  be remote or file-backed.
- `MemoryStores` is the default in-process set. Durable stores implement
  `GrantStore`, `ReplayStore`, `LimitStore`, `PendingStore`, and
  `AuditStore`; mutation methods must be atomic (`tryReserve`, `markIfNew`,
  `take`).
- Set lifecycle state through your store (for example, `grant.state =
  "revoked"` for in-memory grants). Revocation and expiry are re-checked
  when a pending confirmation is resolved.
- Limits: `await runtime.limits.counters(grant.id)`.
- Audit: read events from your audit store (`MemoryAuditLog.events()` for
  the in-memory default).

## Python

```python
from ccp import AuditLog, GrantStore, HostRegistry, ManifestStore, Runtime, SchemaRegistry

runtime = Runtime(
    grants=GrantStore([grant]),
    manifests=ManifestStore([manifest]),
    schemas=SchemaRegistry({"schema:example.lookup.params.v1": params_schema}),
    hosts=hosts,
    audit=AuditLog(),
    clock=lambda: now,
)

decision = runtime.submit(signal, requester.verifying_key())
if decision.needs_confirmation:
    runtime.confirm(decision.pending_id, True)
```

Lifecycle helpers live on the grant: `grant.pause()`, `grant.suspend()`,
`grant.resume()`, `grant.revoke()`. Resuming a revoked or expired grant
raises. Limits are at `runtime.limits.counters("g-1")`; audit events at
`runtime.audit.events()`.

## Rules that matter

- A manifest never authorizes; only a stored grant does.
- Verification order is fixed: protocol → grant → signer → digest →
  lifecycle → expiry → intent → params → request expiry → replay → limits →
  capabilities → confirmation.
- `now >= expires_at` is expired, for both grants and signals.
- Limits reject when `counter + 1 > limit`.
- Provider output and tool results are untrusted data.

## Verify

```sh
cd sdk/typescript && npx vitest run test/runtime.test.ts test/runtime-stores.test.ts
cd sdk/python && /usr/bin/python3 -m unittest discover -s tests
```
