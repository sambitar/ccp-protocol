# Cross-language conformance and interop

Two independent implementations — `sdk/typescript` and `sdk/python` — must
agree on the v1 contract (`test-vectors/*.json`) and the adversarial v2 set
(`test-vectors/v2/*.json`), and must be able to verify each other's signed
documents.

## Run

```sh
/usr/bin/python3 conformance/run.py       # vector suites, both SDKs
/usr/bin/python3 conformance/interop.py   # sign in each, verify in the other
```

Both build the TypeScript SDK first. Pass `--skip-build` when `dist/` is
already current. Requirements: Node 24, Python 3.10+, `cryptography` in the
Python interpreter (use `/usr/bin/python3`).

## Layout

| File | Responsibility |
| --- | --- |
| `sdk/typescript/conformance/run.mjs` | TS harness |
| `sdk/typescript/conformance/interop.mjs` | TS sign/verify |
| `sdk/python/conformance/run.py` | Python harness |
| `sdk/python/conformance/interop.py` | Python sign/verify |
| `run.py` | runs both harnesses over v1 and v2, compares results |
| `interop.py` | orchestrates the four interop steps and byte comparison |

## Harness contract

```
node conformance/run.mjs <vectors-dir>
python3 conformance/run.py <vectors-dir>
```

Each reads whichever of `canonical-json.json` and `validation.json` exist in
the directory, prints one JSON object, and exits non-zero if any case
failed:

```json
{
  "canonical-json": {"passed": 20, "failed": 0, "failures": []},
  "validation": {"passed": 17, "failed": 0, "failures": []}
}
```

A failure is `{"id", "expected", "got"}`. Validation cases use the same
fixed intent spec and params schema as the SDK vector tests.

`run.py` fails if either SDK fails or if the two summaries disagree on pass
counts or failing ids.

## Interop contract

```
node conformance/interop.mjs generate <out.json>
node conformance/interop.mjs verify <in.json>
python3 conformance/interop.py generate <out.json>
python3 conformance/interop.py verify <in.json>
```

A generated file contains:

```json
{
  "manifest_wire": "…",
  "manifest_digest": "sha256:…",
  "signal_wire": "…",
  "signal_signing_sha256": "…"
}
```

`verify` checks the manifest signature, the signal signature, the digest,
and the signing hash. The documents use fixed seeds and include
NFC-decomposed values, an astral character, and an integer beyond 2^64.
Ed25519 is deterministic, so `interop.py` also requires the two generated
files to be byte-identical.

Current result:

```
test-vectors       canonical-json   ts 18/18  py 18/18  agree
test-vectors       validation       ts 18/18  py 18/18  agree
test-vectors/v2    canonical-json   ts 21/21  py 21/21  agree
test-vectors/v2    validation       ts 17/17  py 17/17  agree
test-vectors/v3    canonical-json   ts 3/3    py 3/3    agree
test-vectors/v3    validation       ts 5/5    py 5/5    agree
conformance: ok

ts generate    ok
py generate    ok
ts verify py   ok
py verify ts   ok
manifest_wire:           identical
manifest_digest:         identical
signal_wire:             identical
signal_signing_sha256:   identical
interop: ok
```

## Rust kernel

The portable kernel has its own gates (see `kernel/README.md`):

```sh
cargo test --manifest-path kernel/Cargo.toml
cargo build --release --target wasm32-unknown-unknown --manifest-path kernel/Cargo.toml
node bindings/js/test.mjs
```

It passes the same 97 cases through the Rust API and through WASM; the C
smoke test covers the native ABI.

## Adding a case

1. Add the case to `test-vectors/v2/generate.py` and regenerate.
2. Both SDK suites and both harnesses pick it up automatically.
3. If the implementations disagree, decide which behavior the spec requires
   before changing either SDK. Fix the spec if it is genuinely ambiguous.

v1 files are frozen; do not edit them. A new edge belongs in v2 or, after a
new freeze, in a later versioned directory.
