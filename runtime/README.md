# CCP runtime (Rust)

`ccp-runtime` is the Rust runtime for the Capability Contacts Protocol. It is
the same layer as `ccp-core` (TypeScript) and `ccp-protocol` (Python): it owns
the grant store, replay set, limit counters, pending confirmations, schema
registry, host registry, and audit log, and exposes `submit` and `confirm`.

The deterministic core stays in [`ccp-kernel`](../kernel): strict canonical
JSON, Ed25519, the §25.3 schema subset, the §10.3 decision, and the §26.3 state
machine. The runtime calls `ccp_kernel::decision::decide`; it does not
reimplement it.

## Kernel or runtime?

| You need | Use |
| --- | --- |
| Verify a document, decide over values you already loaded, sign or canonicalize | `ccp-kernel` |
| Grants, replay, limits, confirmation, host mediation, lifecycle, audit | `ccp-runtime` |

The kernel and its Go, JS, Kotlin, and Swift bindings are portable
deterministic cores. `ccp-runtime` is a host-side runtime.

## Quick start

From the repository root:

```sh
cargo run --example quickstart --manifest-path runtime/Cargo.toml
```

Output:

```text
decision: authorized
result: {"item_id":"item-123","name":"Widget"}
after revoke: grant_revoked
```

The runnable source is [`examples/quickstart.rs`](examples/quickstart.rs).

## Shape

```rust
use ccp_runtime::{create_grant, Runtime, RuntimeOptions};

let mut runtime = Runtime::new(RuntimeOptions {
    schemas: Some(schemas),
    hosts: Some(hosts),
    ..RuntimeOptions::default()
});

runtime.grants.add(grant);
runtime.manifests.add(manifest);

let decision = runtime.submit(&signal_document, &requester_public_key);
if decision.outcome == "confirmation_required" {
    // Only a trusted UI decides this.
    let done = runtime.confirm(decision.pending_id.as_deref().unwrap(), true);
}
```

`Runtime::new` takes stores, schemas, hosts, an audit sink, a clock, and the
supported wire labels. Every option has an in-memory or standard default.

## Synchronous by design

The runtime is synchronous and every mutating method takes `&mut self`.
Callers own concurrency: wrap a runtime in a mutex, or keep one per thread.
There is no async trait, no Tokio dependency, and no transport layer.

This is a deliberate difference from the TypeScript runtime, whose store
contract is `Awaitable<T>`. The Rust traits are the same contract without the
async colouring. Atomicity requirements are unchanged:

- `ReplayStore::mark_if_new` inserts or returns false.
- `LimitStore::try_reserve` reserves one unit against every limit or none.
- `PendingStore::take` removes and returns at most once.
- `GrantStore::add` is an upsert; revocation must be visible to the next
  `find`.

## Stores

```rust
pub trait GrantStore {
    fn add(&mut self, grant: Grant);
    fn get(&self, id: &str) -> Option<Grant>;
    fn find(&self, requester_key: &str, manifest_digest: &str) -> Option<Grant>;
    fn remove(&mut self, id: &str) -> Option<Grant>;
    fn all(&self) -> Vec<Grant>;
}
```

The other five are `ManifestStore`, `ReplayStore`, `LimitStore`,
`PendingStore`, and `AuditStore`. See [`src/stores.rs`](src/stores.rs).

`MemoryStores` bundles the in-process defaults. `MemoryAuditLog::events()`
exposes the local audit records for tests and trusted UIs.

### Durable SQLite stores

The `sqlite` feature adds `ccp_runtime::sqlite::SqliteStores`, implementing the
same six contracts over one connection:

```toml
[dependencies]
ccp-runtime = { version = "0.5.1", features = ["sqlite"] }
```

```rust
use ccp_runtime::sqlite::SqliteStores;
use ccp_runtime::{Runtime, RuntimeOptions};

let stores = SqliteStores::open("ccp.db")?;
let mut runtime = Runtime::new(RuntimeOptions {
    grants: Some(Box::new(stores.grants)),
    manifests: Some(Box::new(stores.manifests)),
    replay: Some(Box::new(stores.replay)),
    limits: Some(Box::new(stores.limits)),
    pending: Some(Box::new(stores.pending)),
    audit: Some(Box::new(stores.audit)),
    ..RuntimeOptions::default()
});
```

`:memory:` works for tests. `try_reserve`, `mark_if_new`, and `take` run in
`BEGIN IMMEDIATE` transactions. Revocation and pending confirmations survive a
process restart; `tests/sqlite.rs` verifies both. The schema matches
[`docs/guides/persistence.md`](../docs/guides/persistence.md).

## Hosts, identity, and admission

- Every host has a contract: class, risk, confirmation floor, idempotency,
  network permission, placement, and declared fields (§26.4). Core hosts may
  omit it; an extension host must declare a class.
- A per-action floor forces confirmation even when the manifest says `none`.
- Placement and egress are checked before execution and again inside every
  `HostAccess::call` (§12).
- `verify_contact_identity` suspends all non-revoked grants for a contact on
  a valid key change (`identity_changed`). A forged document suspends nothing.
- `admit_request` creates or reuses the deterministic `pg-...` grant, refuses
  an intent whose hosts require a human, and never resurrects a revoked grant
  (§25.8.3).

## Verification

```sh
cargo fmt --manifest-path runtime/Cargo.toml --check
cargo clippy --manifest-path runtime/Cargo.toml --all-targets --features sqlite -- -D warnings
cargo test --manifest-path runtime/Cargo.toml --features sqlite
cargo run --example quickstart --manifest-path runtime/Cargo.toml
```

`tests/vectors.rs` runs the frozen v1-v5 suites through the runtime surface.
`conformance/run.py` runs TypeScript, Python, and Rust and requires three-way
agreement.

## Layout

| File | Responsibility |
| --- | --- |
| `src/runtime.rs` | `Runtime`: submit, confirm, execute, lifecycle, admission |
| `src/model.rs` | grants, decisions, pending, identity and admission records |
| `src/stores.rs` | store traits and in-memory defaults |
| `src/grants.rs` | least-authority grant derivation |
| `src/hosts.rs` | host contracts, registry, access proxy |
| `src/identity.rs` | identity documents, admission policies, deterministic ids |
| `src/consumer.rs` | manifest and signal verification, permission cards |
| `src/sqlite.rs` | durable stores (`sqlite` feature) |
| `src/vectors.rs` | language-neutral conformance runner |
| `src/bin/conformance.rs` | CLI wrapper for `conformance/run.py` |
| `tests/` | runtime, identity, egress, vectors, sqlite |
