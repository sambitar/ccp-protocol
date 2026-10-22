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
| Rust | Kernel only: canonical JSON, Ed25519, schema, decision, state machine | `cargo run --example quickstart --manifest-path kernel/Cargo.toml` |

All three run in CI. The TypeScript and Python lanes are the complete loop;
the Rust lane is the deterministic decision over values you supply, because
the Rust runtime does not exist yet (see
[`implementation-status.md`](implementation-status.md)).

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

Runnable file: [`kernel/examples/quickstart.rs`](../kernel/examples/quickstart.rs).

```rust
use ccp_kernel::{decision::decide, parse_strict, serialize};

let grant = parse_strict(GRANT)?;
let signal = parse_strict(SIGNAL)?;
let outcome = decide(
    Some(&grant), &signal, "key:ed25519:requester", "2026-10-22T12:00:00Z",
    &seen, &counters, Some(&intent_spec), Some(&params_schema),
    &["0.5-draft", "0.4-draft"],
);
```

Output:

```text
canonical grant: {"capabilities":["store.read"],...}
decision: authorized
after revoke: grant_revoked
```

The kernel does not store grants, count limits, resolve replay, hold pending
confirmations, or mediate hosts. Those live in the TypeScript and Python
runtimes. A Rust application that needs them must port the runtime or call
one of those SDKs.

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
