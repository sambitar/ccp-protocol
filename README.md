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
- **Status:** reference implementations. Not security-audited, and not yet
  published to package registries.

## Repository map

| Path | Contents |
| --- | --- |
| `CCP_Working_Draft_v0.5.md` | The protocol specification |
| `test-vectors/` | Frozen conformance vectors (v1) and the adversarial v2 set |
| `kernel/` | Rust kernel with a C ABI and WASM build |
| `sdk/typescript/` | `ccp-core` TypeScript SDK and framework adapters |
| `sdk/python/` | `ccp-protocol` Python SDK and FastAPI/MCP adapters |
| `bindings/` | Go, JS, Kotlin, and Swift bindings over the kernel |
| `conformance/` | Cross-language conformance and interop harness |
| `docs/guides/` | Operational guides (persistence, transport, namespaces, host catalogue, quickstarts) |
| `docs/plans/` | Phased build plans |
| `phase4/`, `phase4-confirm/` | Independent-implementation reports |

## Quick start

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

Role-level API examples live in [`sdk/typescript/README.md`](sdk/typescript/README.md)
and [`sdk/python/README.md`](sdk/python/README.md).

## Verify

Run each gate from the repository root:

```sh
# Python SDK
/usr/bin/python3 -m unittest discover -s sdk/python/tests

# TypeScript SDK
cd sdk/typescript && npm install && npx vitest run && npx tsc --noEmit

# Rust kernel
cargo test --manifest-path kernel/Cargo.toml

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
- identity bootstrap and trust (§4.2, a non-goal);
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
