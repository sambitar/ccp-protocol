# CCP kernel — JavaScript (WASM)

A dependency-free loader for `kernel/target/wasm32-unknown-unknown/release/ccp_kernel.wasm`.
The module exports a string-based C ABI; this wrapper handles allocation and
the shared result buffer.

This is a kernel binding: it exposes canonicalization, signing, verification,
the decision, and the state machine. It has no grant store, replay store,
limit counters, host registry, audit log, or transport. For an end-to-end
runtime, use `ccp-core` in `sdk/typescript`.

## Build

```sh
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown --manifest-path kernel/Cargo.toml
```

## Use

```js
import { loadKernel } from "./index.mjs";

const kernel = await loadKernel();

const { code, result } = kernel.canonicalize('{"b":1,"a":2}');
// code === 0, result === { ok: true, value: '{"a":2,"b":1}' }

kernel.decide({ grant, signal, signer, now, seen, counters,
                intent_spec, params_schema });
kernel.nextState({ from: "authorized", event: "no_confirmation" });
kernel.sign({ seed_hex, message_hex });
kernel.verify({ public_key_hex, message_hex, signature_field });
kernel.signDocument({ document, seed_hex });
```

Every method returns `{ code, result }`; `result` is the parsed envelope
`{ok: true, value}` or `{ok: false, error}`.

## Test

```sh
node bindings/js/test.mjs
```

Runs the v1 and v2 vectors (canonical, validation, state machine, Ed25519)
through WASM: 89 cases.

## Notes

- The loader re-creates typed-array views after each call because WASM memory
  may grow during a call.
- The result buffer is valid until the next kernel call; the loader parses it
  immediately.
- Node 24 is required (`WebAssembly.instantiate` and ESM).
