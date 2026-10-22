# Quickstart

Go from zero to a signed request being authorized, then refused after a
revocation, without reading the draft first.

Every CCP deployment runs the same five steps:

1. A **provider** publishes a signed manifest. Publishing grants nothing.
2. A **consumer** approves specific intents, creating a local **grant**.
3. A **requester** signs a **signal** bound to the approved manifest digest.
4. A **runtime** verifies the signal against the grant and decides.
5. The consumer can **revoke** at any time; the next request is refused.

## Choose a lane

| Lane | What you get | Run it |
| --- | --- | --- |
| TypeScript | Full runtime: grants, replay, limits, confirmation, hosts, audit, adapters | `cd sdk/typescript && npm run quickstart` |
| Python | Full runtime, same semantics | `cd sdk/python && python examples/quickstart.py` |
| Rust | Full runtime via `ccp-runtime`: grants, replay, limits, confirmation, hosts, audit, SQLite | `cargo run --example quickstart --manifest-path runtime/Cargo.toml` |

All three run in CI. Every lane exercises the complete loop: a signed
manifest, a local grant, a signed signal, the runtime decision, and a refusal
after revocation. The Rust kernel keeps a smaller decision-only example for
callers that already own their state.

## TypeScript

Runnable file: [`sdk/typescript/examples/quickstart/run.ts`](../sdk/typescript/examples/quickstart/run.ts).

```ts
import {
  HostRegistry, MemoryAuditLog, MemoryGrantStore, MemoryManifestStore,
  Runtime, SchemaRegistry, createGrant, signManifest, signSignal,
  verifyManifest,
} from "ccp-core";

const manifest = verifyManifest(signManifest({ provider, version: 1, intents }, providerSeed));

const grant = createGrant({
  contactId: "c-1",
  requesterKey,
  manifest,
  intents: ["example.lookup"],
  createdAt: "2026-10-22T10:00:00Z",
  expiresAt: "2030-01-01T00:00:00Z",
});

const runtime = new Runtime({
  grants: new MemoryGrantStore([grant]),
  manifests: new MemoryManifestStore([manifest]),
  schemas,
  hosts,
  audit: new MemoryAuditLog(),
});

const decision = await runtime.submit(signal, requesterPublicKey);
```

Output:

```text
decision: authorized {"item_id":"item-123","name":"Widget"}
after revoke: grant_revoked
```

## Python

Runnable file: [`sdk/python/examples/quickstart.py`](../sdk/python/examples/quickstart.py).

```python
from ccp import Runtime, create_grant, sign_manifest, sign_signal, verify_manifest

manifest = verify_manifest(sign_manifest(provider, 1, intents, provider_key))

grant = create_grant(
    contact_id="c-1",
    requester_key=requester.key_id,
    manifest=manifest,
    intents=["example.lookup"],
    created_at="2026-10-22T10:00:00Z",
    expires_at="2030-01-01T00:00:00Z",
)

runtime = Runtime(grants=GrantStore([grant]), manifests=ManifestStore([manifest]),
                  schemas=schemas, hosts=hosts, audit=AuditLog())

decision = runtime.submit(signal, requester.verifying_key())
```

Output is identical:

```text
decision: authorized {'item_id': 'item-123', 'name': 'Widget'}
after revoke: grant_revoked
```

## Rust

Runnable file: [`runtime/examples/quickstart.rs`](../runtime/examples/quickstart.rs).

```rust
use ccp_runtime::{create_grant, CreateGrantOptions, HostRegistry, Runtime,
                  RuntimeOptions, SchemaRegistry};

let grant = create_grant(CreateGrantOptions {
    id: None,
    contact_id: "c-1".to_string(),
    requester_key: requester_key_id.clone(),
    manifest: manifest.clone().into(),
    intents: vec!["example.lookup".to_string()],
    limits: None,
    confirmation: None,
    capabilities: None,
    placement: None,
    egress: None,
    created_at: Some("2026-10-22T10:00:00Z".to_string()),
    expires_at: "2030-01-01T00:00:00Z".to_string(),
    state: None,
    state_reason: None,
    admitted_by: None,
})?;

let mut runtime = Runtime::new(RuntimeOptions {
    schemas: Some(schemas),
    hosts: Some(hosts),
    ..RuntimeOptions::default()
});
runtime.grants.add(grant);
runtime.manifests.add(manifest.clone());

let decision = runtime.submit(&signed_signal, &requester_public_key);
if decision.outcome == "confirmation_required" {
    runtime.confirm(decision.pending_id.as_deref().unwrap(), true);
}
```

Output:

```text
decision: authorized
result: {"item_id":"item-123","name":"Widget"}
after revoke: grant_revoked
```

The runtime is synchronous: mutating methods take `&mut self`, and callers own
concurrency. The kernel example at
[`kernel/examples/quickstart.rs`](../kernel/examples/quickstart.rs) remains the
right entry point when you only need the deterministic §10.3 decision over
values you already loaded.

## What each step maps to

| Step | Spec | SDK surface |
| --- | --- | --- |
| Manifest | §8 | `signManifest` / `sign_manifest`, `verifyManifest` / `verify_manifest` |
| Grant | §9, §26.1 | `createGrant` / `create_grant` |
| Signal | §10 | `signSignal` / `sign_signal` |
| Decision | §10.3 | `Runtime.submit` / `Runtime.submit` |
| Revocation | §9.4.4 | `runtime.revokeGrant` / `runtime.revoke_grant` |

## Going further

- [Identity and admission](guides/identity.md) — publish an identity, admit
  requests under a reviewed policy.
- [Runtime](guides/runtime.md) — lifecycle, confirmation, host contracts.
- [Persistence](guides/persistence.md) — durable stores, atomicity rules.
- [Transport](guides/transport.md) — the HTTP binding.
- [Host catalogue](guides/host-catalogue.md) — core and extension hosts.
- [Implementation status](implementation-status.md) — what each language
  actually implements.

## Versions

The specification is draft `0.5`; the packages are `0.5.1`. The draft label
and the package version move independently: the label is the wire/semantic
revision, the package version is the release.
