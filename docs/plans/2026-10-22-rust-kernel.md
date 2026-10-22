# Portable Rust Kernel Plan

**Goal:** one vetted core for canonical JSON, Ed25519, the schema subset, the decision, and the state machine, callable from Rust, WASM, and C — passing the same v1 and v2 vectors as the independent TS and Python implementations.

**Architecture:** A `no_std`-friendly (but `std`-using) Rust library at `kernel/` implements the protocol primitives with its own strict parser and a `BigUint` number model. A small string-based C ABI exposes five operations. The same exports compile to `wasm32-unknown-unknown`; `bindings/js` loads the module and runs the vectors in Node. The native `staticlib` is exercised by a C smoke test.

**Tech Stack:** Rust 1.98, `ed25519-dalek` 3, `sha2`, `unicode-normalization`, `num-bigint`, `base64`. WASM via the plain `wasm32-unknown-unknown` target (no wasm-bindgen). Node 24 for the JS harness. `cc` for the C smoke test.

**Spec:** `CCP_Working_Draft_v0.5.md` §10.3, §25.1–25.3, §26.1, §26.3. Contract: `test-vectors/` + `test-vectors/v2/`.

## Global Constraints

- The kernel must pass all v1 vectors and the v2 set.
- The TS and Python kernels stay independent; do not replace them with the Rust core in this phase.
- No floats anywhere in the number model; integers are arbitrary precision.
- The C ABI never panics on untrusted input; every error is a returned code plus a JSON envelope.
- WASM and native builds share the same exported symbols.
- `test-vectors/*.json` v1 stays frozen. v2 is extended once, for the normalized-key sort case, and documented.
- Commit only when the user asks.

## Toolchain notes

- Rust is installed; the `wasm32-unknown-unknown` target is not yet installed.
- `wasm-bindgen`, `wasm-pack`, and `cbindgen` are not installed. The WASM binding therefore uses the C ABI directly (operable from `WebAssembly.instantiate`), and `kernel/include/ccp.h` is hand-maintained. This keeps the build to `cargo` alone; the roadmap's outcome (WASM passes the vectors in Node) is unchanged.
- Crates.io is reachable.

## New finding: sort normalized keys

`§25.1` says keys are NFC and sorted by Unicode scalar value. Both SDKs currently sort the *input* keys and then normalize them:

```
{"e\u0301":1,"f":2}  →  {"é":1,"f":2}     (wrong)
```

`f` (U+0066) sorts before `é` (U+00E9). The canonical output must be `{"f":2,"é":1}`. The Rust kernel sorts the folded keys, then emits them; the v2 set gains `cj2-021`, and both SDKs are fixed in Task 8.

## File map

| File | Responsibility |
| --- | --- |
| `kernel/Cargo.toml` | crate, deps, `cdylib` + `staticlib` + `rlib` |
| `kernel/src/lib.rs` | module wiring and public Rust API |
| `kernel/src/value.rs` | `Value` and accessors |
| `kernel/src/json.rs` | strict parser, canonical serializer, `-0`/NFC/surrogate rules |
| `kernel/src/crypto.rs` | Ed25519, base64url, key id, signing digest |
| `kernel/src/schema.rs` | §25.3 subset validator |
| `kernel/src/decision.rs` | pure §10.3 decision |
| `kernel/src/state_machine.rs` | §26.3 transitions |
| `kernel/src/capi.rs` | C ABI + JSON envelopes |
| `kernel/include/ccp.h` | hand-maintained C header |
| `kernel/c-tests/smoke.c` | native C smoke test |
| `kernel/tests/vectors.rs` | v1 + v2 vector conformance |
| `kernel/README.md` | build, ABI, test commands |
| `bindings/js/index.mjs` | WASM loader |
| `bindings/js/test.mjs` | runs v1 + v2 vectors through WASM |
| `bindings/js/README.md` | usage |

## ABI

```c
uint8_t *ccp_alloc(size_t len);
void     ccp_free(uint8_t *ptr, size_t len);
const uint8_t *ccp_result_ptr(void);
size_t   ccp_result_len(void);

int32_t ccp_canonicalize(const uint8_t *ptr, size_t len);
int32_t ccp_decide(const uint8_t *ptr, size_t len);
int32_t ccp_next_state(const uint8_t *ptr, size_t len);
int32_t ccp_sign(const uint8_t *ptr, size_t len);
int32_t ccp_verify(const uint8_t *ptr, size_t len);
```

Each call returns `0` on success and `1` on a protocol error; the result buffer always contains valid JSON:

```json
{"ok":true,"value":…}
{"ok":false,"error":"duplicate"}
```

Inputs:

| Function | Input |
| --- | --- |
| `ccp_canonicalize` | the raw JSON document |
| `ccp_decide` | `{"grant","signal","signer","now","seen","counters","intent_spec","params_schema"}` |
| `ccp_next_state` | `{"from":null\|"…","event":"…"}` |
| `ccp_sign` | `{"seed_hex":"…","message_hex":"…"}` → `{public_key_hex,key_id,signature_hex,signature_field}` |
| `ccp_verify` | `{"public_key_hex":"…","message_hex":"…","signature_field":"…"}` → `true/false` |

The result buffer is valid until the next call. `ccp_alloc`/`ccp_free` use a length-preserving boxed slice.

---

### Task 1: Scaffold and canonical JSON

**Files:** `kernel/Cargo.toml`, `kernel/src/{lib,value,json}.rs`, `kernel/tests/vectors.rs`.

- [ ] `rustup target add wasm32-unknown-unknown`.
- [ ] Create the crate with `crate-type = ["cdylib", "staticlib", "rlib"]`, `edition = "2021"`, `panic = "abort"` in release.
- [ ] `Value`: `Null | Bool | Int(BigUint) | Str(String) | Array(Vec<Value>) | Object(Vec<(String, Value)>)`.
- [ ] Parser: recursive descent; reject floats/exponents, `-0`, leading zeros, NaN/Infinity, duplicate keys (exact and NFC-folded), unpaired surrogates, raw control chars, trailing content.
- [ ] Serializer: NFC values and keys, code-point sort of **folded** keys, `signature` last only at the top level, minimal escaping, lowercase `\u00xx`.
- [ ] Tests: all v1 and v2 canonical vectors; call `canonicalize(document)` and compare the error code or output.

**Verify:** `cargo test --test vectors` passes the canonical suite (v1 18 + v2 21 after Task 8).

### Task 2: Ed25519 and digests

**Files:** `kernel/src/crypto.rs`, vector tests.

- [ ] Seed → public key, `key:ed25519:<b64url>` key id, deterministic RFC 8032 signature, `ed25519:<b64url>` field.
- [ ] Verify with strict canonical checks.
- [ ] SHA-256 over canonical signing bytes → `sha256:<hex>` digests.
- [ ] Tests: v1 `kat_vectors` and `signing_vectors` (public key, key id, signature, wire, signing hash).

**Verify:** `cargo test --test vectors` includes 3 KAT + 2 signing vectors.

### Task 3: Schema subset and decision

**Files:** `kernel/src/{schema,decision}.rs`.

- [ ] Port the §25.3 subset: `type`, `properties`, `required`, `additionalProperties`, `items`, `enum`, `const`, numeric bounds, `multipleOf`, string length, `pattern`, array length/uniqueness. `pattern` may use the `regex` crate; add it if needed.
- [ ] Port §10.3 in order: protocol → grant → signer → digest → lifecycle (explicit states first) → expiry (`now >= expires_at`) → intent → params → request expiry → replay → limits (`counter + 1 > limit`) → capabilities → confirmation.
- [ ] Confirmation policy: grant `none`/`per_action`, else manifest policy, else `per_action`.
- [ ] Tests: v1 + v2 validation vectors with the fixed intent spec and params schema.

**Verify:** `cargo test --test vectors` includes 18 + 17 validation vectors.

### Task 4: State machine

**Files:** `kernel/src/state_machine.rs`.

- [ ] Ten `(from, event) -> to` transitions, with `start` mapped to `None` and an error for undefined transitions.
- [ ] Tests: v1 `state-machine.json` (10 vectors) and an undefined-transition test.

### Task 5: C ABI and native build

**Files:** `kernel/src/capi.rs`, `kernel/include/ccp.h`, `kernel/c-tests/smoke.c`.

- [ ] Implement alloc/free/result and the five operations with JSON envelopes; no panics on malformed input.
- [ ] `cargo build --release` emits `libccp_kernel.a` and `.so`.
- [ ] Compile the smoke test against the staticlib and run it:
      `cc kernel/c-tests/smoke.c kernel/target/release/libccp_kernel.a -lpthread -ldl -lm -o /tmp/ccp-smoke && /tmp/ccp-smoke`
      (add `-lm`/`-ldl` only if the linker asks).
- [ ] Smoke asserts: canonicalize `{"b":1,"a":2}` → `{"a":2,"b":1}`, a native state transition, and one Ed25519 KAT.

### Task 6: WASM build and JS binding

**Files:** `bindings/js/{index.mjs,test.mjs,README.md}`.

- [ ] `cargo build --release --target wasm32-unknown-unknown` emits `kernel/target/wasm32-unknown-unknown/release/ccp_kernel.wasm`.
- [ ] Loader exports `canonicalize`, `decide`, `nextState`, `sign`, `verify`; re-create typed-array views after every call.
- [ ] `test.mjs` runs v1 + v2 canonical and validation, v1 state machine, and v1 Ed25519; prints counts and exits non-zero on failure.
- [ ] Verify: `node bindings/js/test.mjs` prints all-green counts.

### Task 7: Kernel docs

**Files:** `kernel/README.md`.

- [ ] Build matrix (`cargo test`, native lib, wasm), ABI table, safety notes (result buffer lifetime, no floats, thread safety), and the independence rationale.

### Task 8: Cross-language normalized-sort fix

**Files:** `test-vectors/v2/generate.py` (add `cj2-021`), `sdk/typescript/src/json.ts`, `sdk/python/ccp/canonical.py`, `CCP_Working_Draft_v0.5.md` §25.1.

- [ ] Add `cj2-021`: `{"e\u0301":1,"f":2}` → `{"f":2,"é":1}`; regenerate v2.
- [ ] TS: fold keys, detect collisions, sort folded keys, emit folded keys.
- [ ] Python: the same.
- [ ] Spec: state that sorting applies to the NFC form.
- [ ] Add the case to the Rust tests and confirm it passes from the start.

### Task 9: Full gate

- [ ] `cargo test` in `kernel/` (unit + vector suites).
- [ ] `cargo build --release` and the C smoke test.
- [ ] `node bindings/js/test.mjs`.
- [ ] `/usr/bin/python3 conformance/run.py --skip-build` and `conformance/interop.py --skip-build`.
- [ ] `sdk/typescript`: typecheck + full suite; `sdk/python`: full suite.
- [ ] `cargo clippy -- -D warnings` (fix or document allow-listed lints).

## Self-review

- Coverage: all five primitives, three call surfaces (Rust/WASM/C), both vector sets, and the newly found ordering bug.
- No placeholders: exact files, ABI, commands, expected results.
- Independence: the TS and Python kernels are untouched except for the shared canonical fix; the Rust core is a third implementation.
