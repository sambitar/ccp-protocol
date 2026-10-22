# Contributing to CCP

Thanks for helping. This repository contains the protocol specification and
several independent reference implementations. Keep the spec and the
implementations in agreement.

## Ground rules

1. **The specification is the source of truth.** If code and
   `CCP_Working_Draft_v0.5.md` disagree, the spec wins. If the prose is
   genuinely ambiguous, fix the prose in the same change.
2. **v1 vectors are frozen.** Do not edit `test-vectors/*.json`. Add new edge
   cases to `test-vectors/v2/`, regenerate, and let the suites pick them up.
3. **Keep the kernels independent.** The TypeScript and Python kernels are
   hand-written and must not be replaced by the Rust kernel. Independence is
   how the spec is validated (§18).
4. **The core stays declarative.** Signals never carry executable code
   (§25.5).
5. **Normative changes** need a version bump and a conformance-vector update.
   Security-relevant changes need review (§26.8).

## Development

Run the gates from the repository root before opening a pull request:

```sh
/usr/bin/python3 -m unittest discover -s sdk/python/tests
cd sdk/typescript && npm install && npx vitest run && npx tsc --noEmit
cargo test --manifest-path kernel/Cargo.toml
/usr/bin/python3 conformance/run.py
/usr/bin/python3 conformance/interop.py
```

Add `pip install 'ccp-protocol[dev]'` (from `sdk/python/`) to run the FastAPI and
MCP adapter tests.

## Adding a conformance case

1. Add the case to `test-vectors/v2/generate.py` and regenerate:
   `/usr/bin/python3 test-vectors/v2/generate.py`.
2. Both SDK test suites and both conformance harnesses pick it up
   automatically.
3. If the implementations disagree, decide what the specification requires
   before changing either SDK. If the spec is ambiguous, fix the spec.

Never edit the frozen v1 files. A new edge belongs in v2 or in a later
versioned directory after a new freeze.

## Submitting changes

- Work on a feature branch and open a pull request against the default
  branch. Do not commit directly to `main`.
- Keep changes focused; unrelated fixes belong in a separate pull request.
- Run the gates above and report the result in the pull request.
- Do not commit build output: `dist/`, `node_modules/`, `target/`,
  `__pycache__/`, `coverage/`, and the language build directories are ignored
  by `.gitignore`.

## Licence

This repository is licensed under the Apache License, Version 2.0. By
contributing, you agree that your contributions are licensed under the same
terms (Apache-2.0 §5). See [`LICENSE`](LICENSE).
