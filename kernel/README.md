# CCP kernel (Rust)

A portable implementation of the deterministic protocol core: strict
canonical JSON, Ed25519, the §25.3 schema subset, the §10.3 decision, and
the §26.3 state machine. It is a third, independent implementation beside
the TypeScript and Python SDKs.

## This is a kernel, not a runtime

The kernel has no grant store, manifest store, replay store, limit
counters, pending confirmations, host registry, audit log, or transport.
It verifies and decides over values you pass in. The C ABI and WASM build
expose the same deterministic core and nothing more.

The runtime lives in [`../runtime/`](../runtime). Use `ccp-kernel` when you
need the deterministic core over values you already loaded; use
`ccp-runtime` (crate `ccp-runtime`) when you need grants, replay, limits,
pending confirmations, host mediation, lifecycle, or audit. See
[`../docs/implementation-status.md`](../docs/implementation-status.md) and the
runnable kernel example in [`examples/quickstart.rs`](examples/quickstart.rs).

## Build and test

From the repository root:

```sh
cargo test --manifest-path kernel/Cargo.toml
cargo fmt --manifest-path kernel/Cargo.toml --check
cargo clippy --manifest-path kernel/Cargo.toml -- -D warnings

cargo build --release --manifest-path kernel/Cargo.toml
cargo build --release --target wasm32-unknown-unknown --manifest-path kernel/Cargo.toml

node bindings/js/test.mjs

cc -Wall -Wextra -I kernel/include \
   kernel/c-tests/smoke.c kernel/target/release/libccp_kernel.a \
   -lpthread -ldl -lm -o /tmp/ccp-smoke && /tmp/ccp-smoke
```

`wasm32-unknown-unknown` must be installed once:

```sh
rustup target add wasm32-unknown-unknown
```

## Layout

| File | Responsibility |
| --- | --- |
| `src/value.rs` | `Value` and accessors |
| `src/json.rs` | strict parser and canonical serializer |
| `src/crypto.rs` | Ed25519, base64url, key ids, SHA-256 |
| `src/schema.rs` | §25.3 schema subset |
| `src/decision.rs` | §10.3 decision and confirmation policy |
| `src/state_machine.rs` | §26.3 transitions |
| `src/capi.rs` | C ABI and JSON envelopes |
| `include/ccp.h` | C header |
| `c-tests/smoke.c` | native smoke test |
| `examples/quickstart.rs` | kernel-level decision loop |
| `tests/vectors.rs` | v1, v2, v3 conformance |

## C ABI

```c
uint8_t *ccp_alloc(size_t length);
void     ccp_free(uint8_t *pointer, size_t length);
const uint8_t *ccp_result_ptr(void);
size_t   ccp_result_len(void);

int32_t ccp_canonicalize(const uint8_t *pointer, size_t length);
int32_t ccp_decide(const uint8_t *pointer, size_t length);
int32_t ccp_next_state(const uint8_t *pointer, size_t length);
int32_t ccp_sign(const uint8_t *pointer, size_t length);
int32_t ccp_verify(const uint8_t *pointer, size_t length);
int32_t ccp_sign_document(const uint8_t *pointer, size_t length);
```

Each call returns `0` on success and `1` on a protocol error. The result
buffer always contains a JSON envelope:

```json
{"ok":true,"value":…}
{"ok":false,"error":"duplicate"}
```

Input pointers must be valid for `length` bytes of UTF-8; the Rust exports
are `unsafe` for that reason, while the C header is unchanged.

| Operation | Input |
| --- | --- |
| `ccp_canonicalize` | the raw JSON document |
| `ccp_decide` | `{grant, signal, signer, now, seen, counters, intent_spec, params_schema}` |
| `ccp_next_state` | `{from, event}` |
| `ccp_sign` | `{seed_hex, message_hex}` |
| `ccp_verify` | `{public_key_hex, message_hex, signature_field}` |
| `ccp_sign_document` | `{document, seed_hex}` |

The result buffer is valid until the next exported call. `ccp_result_ptr`
and `ccp_result_len` take a lock while reading; copy the bytes before making
another call if you need them longer.

## Design notes

- **Own parser.** `serde_json` accepts duplicate keys and cannot both reject
  floats and preserve arbitrary integers. The parser is small and enforces
  the profile directly.
- **Arbitrary integers.** Numbers are `BigUint`; there is no floating-point
  representation anywhere in the kernel.
- **Normalized keys.** Objects are sorted by the NFC form of each key, as
  §25.1 requires; keys that collide after normalization are duplicates.
- **`signature` placement.** It is last only in the top-level signed object;
  nested objects sort normally.
- **UTF-8.** Rust strings cannot contain unpaired surrogates, and escaped
  lone surrogates are rejected as `malformed`.
- **No wasm-bindgen.** The WASM build uses the same C ABI and is loaded with
  `WebAssembly.instantiate`; the build needs only `cargo` and the target.
- **Thread safety.** The result buffer is behind a `Mutex`. The protocol
  functions are pure; concurrent calls are safe, but the last completed call
  wins in the shared buffer.
- **Independence.** The TS and Python kernels are deliberately not replaced
  by this core; they remain independent implementations used to validate the
  spec.

## Vector status

| Suite | Cases |
| --- | --- |
| canonical v1 | 18 |
| canonical v2 | 21 |
| canonical v3 | 3 |
| validation v1 | 18 |
| validation v2 | 17 |
| validation v3 | 5 |
| state machine v1 | 10 |
| Ed25519 KAT | 3 |
| Ed25519 signing | 2 |
| **total** | **97** |

`cargo test` covers all of them for the Rust API. `bindings/js/test.mjs`
covers the same 97 through WASM. The C smoke test covers canonicalization,
normalization, duplicates, a decision, a state transition, and an Ed25519
KAT.
