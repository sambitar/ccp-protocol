# Capability Contacts Protocol (CCP)

An open protocol for least-authority requests between a requester (a person,
a service, or an AI agent) and a user's device or another executor chosen by
the user.

A requester publishes a signed capability manifest describing the operations
it may request. The user approves a specific subset in a trusted client; the
client creates a local grant bound to the requester's key and the manifest
version. A runtime verifies every signal against the grant and rejects
requests that are unauthorized, malformed, expired, replayed, or outside
limits. Signals name installed capabilities and carry typed parameters; they
never carry executable code.

- **Specification:** [`CCP_Working_Draft_v0.5.md`](CCP_Working_Draft_v0.5.md)
  (working draft; not final)
- **Status:** reference implementations at 0.5.1. PyPI (`ccp-protocol`) and
  crates.io (`ccp-kernel`) are published. npm `ccp-core` and the new
  `ccp-runtime` crate await publishing. Not security-audited.

## Repository map

| Path | Contents |
| --- | --- |
| `CCP_Working_Draft_v0.5.md` | The protocol specification |
| `test-vectors/` | Frozen conformance vectors: v1 base, v2 adversarial, v3 dual-label, v4 identity and admission, v5 host contracts |
| `kernel/` | Rust kernel with a C ABI and WASM build |
| `runtime/` | `ccp-runtime` Rust runtime: grants, replay, limits, confirmation, hosts, identity, audit, SQLite |
| `sdk/typescript/` | `ccp-core` TypeScript SDK and framework adapters |
| `sdk/python/` | `ccp-protocol` Python SDK and FastAPI/MCP adapters |
| `bindings/` | Go, JS, Kotlin, and Swift bindings over the kernel |
| `conformance/` | Cross-language conformance and interop harness |
| `docs/guides/` | Operational guides (persistence, transport, namespaces, identity, host catalogue, quickstarts) |
| `docs/quickstart.md` | End-to-end loop in TypeScript, Python, and the Rust kernel |
| `docs/implementation-status.md` | Spec section to language to vectors |
| `docs/consistency-audit.md` | Principle-to-path audit of every authority mechanism |
| `docs/plans/` | Phased build plans |
| `phase4/`, `phase4-confirm/` | Independent-implementation reports |

## Quick start

The Rust runtime is a complete implementation:

```sh
cargo run --example quickstart --manifest-path runtime/Cargo.toml
```

The TypeScript and Python lanes are complete loops; the Rust lane runs the
same loop through `ccp-runtime` and also ships the kernel example. See
[`docs/quickstart.md`](docs/quickstart.md).

Provider (Node + Express):

```sh
cd sdk/typescript
npm install
npm run provider
```

Provider (Python + FastAPI):

```sh
cd sdk/python
/usr/bin/python3 examples/provider_fastapi/server.py
```

Agent over MCP:

```sh
cd sdk/typescript
npm run mcp:demo
```

Role-level API examples live in [`sdk/typescript/README.md`](sdk/typescript/README.md),
[`sdk/python/README.md`](sdk/python/README.md), and
[`runtime/README.md`](runtime/README.md).

## Verify

Run each gate from the repository root:

```sh
# Python SDK
/usr/bin/python3 -m unittest discover -s sdk/python/tests

# TypeScript SDK
cd sdk/typescript && npm install && npx vitest run && npx tsc --noEmit

# Rust kernel
cargo test --manifest-path kernel/Cargo.toml

# Rust runtime
cargo test --manifest-path runtime/Cargo.toml --features sqlite
cargo run --example quickstart --manifest-path runtime/Cargo.toml

# Cross-language conformance and interop
/usr/bin/python3 conformance/run.py
/usr/bin/python3 conformance/interop.py
```

Requirements: Node 18+ (Node 24 to run the `.ts` examples directly),
Python 3.10+ with `cryptography`, and a Rust toolchain. The WASM build also
needs `rustup target add wasm32-unknown-unknown`.

## Scope

The deterministic core is specified and implemented: strict canonical JSON
(§25.1), Ed25519 (§25.2), the schema subset (§25.3), the §10.3 decision, and
the §26.3 state machine. The TypeScript, Python, and Rust implementations are
independent and share the frozen vectors as their contract.

The initial profile is deliberately small. It standardizes a handful of
read/control host functions (§26.4) and is declarative-only (§25.5). The
following are left to the application or deferred to later profiles:

- transport and channel binding (§13, §25.4) — a proposed HTTP binding is
  in [`docs/guides/transport.md`](docs/guides/transport.md);
- identity documents, introduction, and admission policy (§25.8) — the wire
  format and verification sequence are fixed; see
  [`docs/guides/identity.md`](docs/guides/identity.md);
- trust decisions, contact directories, and key rotation (§7.3, §25.8.4);
- side-effecting and networked intents (§25.6, §26.4);
- remote execution and data-egress enforcement (§26.5);
- a discovery registry and governance (§19.3, §26.8).

See [`docs/guides/persistence.md`](docs/guides/persistence.md) for the durable
store contract.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) for
the full text. The protocol specification in `CCP_Working_Draft_v0.5.md` is
distributed under the same licence unless a separate specification licence is
adopted (§26.8).
