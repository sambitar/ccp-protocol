# Implementation status

What each language actually implements, at package version `0.5.1`.

Legend: **yes** = implemented and tested in CI; **partial** = a helper or a
subset, with the limit named; **no** = not implemented.

## Kernel versus runtime

- A **kernel** verifies and decides over values you pass in. It stores
  nothing.
- A **runtime** owns the grant store, replay set, limit counters, pending
  confirmations, host registry, and audit log, and exposes `submit` and
  `confirm`.

`ccp-kernel` and the Go/JS/Kotlin/Swift bindings are kernels. `ccp-core`
(TypeScript), `ccp-protocol` (Python), and `ccp-runtime` (Rust) are runtimes.

| Area | Spec | Rust | TypeScript | Python | Vectors |
| --- | --- | --- | --- | --- | --- |
| Strict canonical JSON | §25.1 | yes | yes | yes | v1, v2, v3 |
| Ed25519, key ids | §25.2 | yes | yes | yes | v1 |
| Schema subset | §25.3 | yes | yes | yes | v1 |
| §10.3 decision | §10.3 | yes | yes | yes | v1, v2, v3 |
| Side-effect state machine | §26.3 | yes | yes | yes | v1 |
| Identity documents | §25.8.1 | yes | yes | yes | v4 |
| Introduction (contact only) | §25.8.2 | partial | partial | partial | v4 |
| Admission policy | §25.8.3 | yes | yes | yes | v4 |
| Policy → grant → audit path | §25.8.3 | yes | yes | yes | runtime tests |
| Grant lifecycle (pause/suspend/resume/revoke) | §9.4 | yes | yes | yes | runtime tests |
| Key-change suspension | §7.4 | yes | yes | yes | runtime tests |
| Durable stores | §14 | yes (`ccp-runtime` `sqlite` feature) | yes (`ccp-core/node`, SQLite) | yes (`ccp.stores_sqlite`) | restart tests |
| HTTP transport binding | §25.7 | no | yes (Express, Next) | yes (FastAPI) | interop |
| MCP bridge | §15 | no | yes | yes | — |
| Host contracts and floors | §26.4 | yes | yes | yes | v5 |
| Placement and egress enforcement | §12 | yes | yes | yes | runtime tests |
| C ABI, WASM, native bindings | §25 | yes (`ccp-kernel`) | — | — | v1–v3 via `bindings/js` |
| Remote execution | §26.5 | no | no | no | — |
| Key rotation, recovery, multi-device | §25.8.4 | no | no | no | — |
| Resource limits (CPU, time, size) | §11.3 | partial (quota counters only) | partial (quota counters only) | partial (quota counters only) | — |
| Delegation enforcement | §26.6 | no | partial (`attenuates` is a pure check) | partial (`attenuates` is a pure check) | — |
| Registry governance | §19.2.1 | no | no | no | — |
| Maven Central, SwiftPM, Android AAR | — | no | — | — | — |

## Notes

- "Vectors" names the suite that catches a regression, not exhaustive
  coverage of the section.
- The kernel and its bindings pass the 97 v1–v3 cases. v4 (identity) and v5
  (host contracts) are SDK-level suites and also run against `ccp-runtime`.
- `bindings/swift` has no sources or package manifest yet. The directory is a
  placeholder and says so.
- The reference runtime is TypeScript; Python and Rust mirror it.
- `ccp-runtime` has no HTTP, MCP, or FFI layer. The kernel keeps the portable
  C ABI and WASM role; the runtime is host-side and transport-independent.

## Updating this table

Change the status only in the same commit as the implementation and its test.
A row marked **yes** without a test fails the audit rule in
[`consistency-audit.md`](consistency-audit.md): a primitive is not done until
the supported path uses it.
