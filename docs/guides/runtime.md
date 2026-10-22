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
- Host functions declare a contract: `registerHost(name, fn, { class, risk,
  minConfirmation, idempotency, network, placement, fields })`. Core hosts
  may omit it; an extension host without a class is rejected. The defaults
  are local, offline, no fields, and read-only. A per-action floor forces
  confirmation even when the manifest says `none` (§12, §26.4). See
  [`host-catalogue.md`](host-catalogue.md).
- Lifecycle goes through the runtime, because it must persist and audit the
  change (§9.4):

  ```ts
  await runtime.pauseGrant(id, "temporary stop");   // reversible
  await runtime.suspendGrant(id, "key changed");    // needs a check first
  await runtime.resumeGrant(id);                    // re-checks expiry/manifest
  await runtime.revokeGrant(id, "user asked");      // permanent
  await runtime.suspendContact(contactId, "review"); // every grant for one contact
  ```

  `resumeGrant` refuses revoked and expired grants and requires the approved
  manifest to still be stored. Pause keeps limits, replay protection, and
  audit history. The recorded reason is returned as `detail` on
  `grant_paused`, `grant_suspended`, and `grant_revoked`.
- Verify a contact's identity through the runtime so a key change suspends
  its grants (§7.4): `await runtime.verifyContactIdentity(document, {
  contactId, expectedIdentity })`. A forged document returns
  `unauthenticated` and changes nothing. A grant suspended by a key change
  cannot be resumed; create a new grant after re-introducing the contact.
- Policy admission is one call: `runtime.admitRequest({ policy, request,
  manifest })` evaluates the policy, creates or reuses the deterministic
  grant, and audits the admitting rule (§25.8.3). It returns `allow`,
  `confirm`, or `deny` plus the grant, if any. Execution still goes through
  `submit`.
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

Lifecycle and admission go through the runtime, so the change is persisted
and audited (§9.4, §25.8.3):

```python
runtime.pause_grant("g-1", "temporary stop")
runtime.suspend_grant("g-1", "key changed")
runtime.resume_grant("g-1")          # re-checks expiry and the manifest
runtime.revoke_grant("g-1", "user asked")
runtime.suspend_contact("c-1", "review")

outcome = runtime.admit_request(policy, request, manifest)
# outcome.result.decision is allow/confirm/deny; outcome.grant is set on allow

runtime.verify_contact_identity(
    document, contact_id="c-1", expected_identity=contact.identity)
# A key change raises identity_changed and suspends the contact's grants.
```

The model helpers (`grant.pause()`, `grant.suspend()`, `grant.resume()`,
`grant.revoke()`) only change an object in memory. With a durable store they
do not persist; call the runtime methods instead. Limits are at
`runtime.limits.counters("g-1")`; audit events at `runtime.audit.events()`.

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
