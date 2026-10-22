# Security review — CCP v0.4 draft

**Date:** 2026-10-22
**Scope:** spec prose, TypeScript SDK, Python SDK, Rust kernel (native,
WASM, C ABI), Go and Kotlin/JVM bindings, MCP and HTTP adapters.
**Method:** manual review against Appendix A and §17, cross-implementation
conformance (v1 + v2 vectors), deterministic property tests, and code
inspection. This is a self-review by the implementation author, not an
independent audit.

## Result

No unmitigated invariant violation was found in the reviewed scope. Four
implementation defects were found and fixed in earlier phases or this one
(see Findings). Several residual risks are deployment or platform
responsibilities and are listed below.

## Appendix A invariants

| # | Invariant | Enforcement | Evidence | Status |
| --- | --- | --- | --- | --- |
| 1 | A contact alone never grants authority | Grants bind `requester_key` + manifest digest; contacts are labels | `decision.ts` / `decision.py` / `decision.rs`; v-005, v-006; property tests | Met |
| 2 | A valid signature alone never grants authority | Signature verification is followed by grant lookup; no grant → `no_matching_grant` | runtime submit paths; v-004 | Met |
| 3 | Paused/suspended cannot authorize; revoked/expired cannot resume | Explicit lifecycle states checked before derived expiry | v-007–v-010, v2-008–v2-011; `Grant.resume` guard (Python) | Met |
| 4 | A manifest describes possible requests; only a local grant authorizes | Manifest store is advisory; grant lookup precedes every side effect | runtime tests; v-001/robustness cases | Met |
| 5 | Every invocation checks identity, grant, intent, params, expiry, replay, limits, placement | Ordered §10.3 check in all three kernels | v1+v2 validation vectors; property tests | Met for local execution; placement/egress are declarative (see #10) |
| 6 | Unknown or malformed security data fails closed | Strict parser rejects duplicates, floats, negatives, surrogates, bad UTF-8; decision defaults to rejection | v1+v2 canonical vectors; random-text property tests | Met |
| 7 | Provider content cannot render trusted UI or change grants | Cards are built by the consumer from verified manifests; provider text is labelled untrusted; adapters never approve | `consumer.ts` / `consumer.py`; MCP adapters; React hook | Met |
| 8 | No arbitrary provider-supplied code in the initial profile | Intents are declarative schemas; execution calls registered host functions | schema modules; host registries; no eval/WASM loading | Met |
| 9 | Revocation blocks new invocations; limits of cancellation are stated | Lifecycle check on every submit and confirm; docs state in-flight/remote work is not undone | v-007, v2-008; `README`/`SECURITY.md` | Met for new invocations; in-flight cancellation is not implemented |
| 10 | A remote executor receives only allowed data | Egress is declared in manifests and pinned by grants; no remote transport is shipped | manifest/grant models; §26.5 | Partial: enforcement is the host's responsibility |
| 11 | Delegation cannot expand authority | `attenuates` checks intents, capabilities, placement, expiry, limits, egress, confirmation | `agent.ts`, `agent.py`; `agent.test.ts`, `test_roles.py` | Met in TS/Python; kernel does not implement delegation |
| 12 | High-impact effects have confirmation, idempotency, recovery | Two-phase confirmation, replay state, atomic limits, side-effect state machine | runtime tests; state-machine vectors; MCP adapter | Partial: remote recovery is profile work |
| 13 | No overstated privacy/trust claims | §26.7 table repeated in docs; demo auto-approval is flagged | `SECURITY.md`, MCP/React READMEs | Met |

## §17 threat coverage

| Threat | Control | Residual risk |
| --- | --- | --- |
| Unauthorized requester | Signature + grant key binding | Key compromise until revocation |
| Malicious provider | Scope, limits, expiry, audit | Provider can describe itself deceptively; UI must use the runtime card |
| Manifest bait-and-switch | Digest pinning | Host must store the approved digest durably |
| Replay | Request ids + replay store | In-memory default loses state on restart |
| Duplicate side effect | Confirmation + state machine | Remote idempotency is executor-specific |
| Limit bypass via concurrency | Atomic `tryReserve` | Durable stores must implement atomicity |
| Forged consent UI | Host-owned confirmation | Malicious host UI is out of scope |
| Prompt injection | Data-only tool output; runtime enforcement | Model may still propose harmful actions; runtime rejects them |
| Confused deputy | Signer/grant/digest/intent binding | Delegation chains are not implemented in the Rust kernel |
| Excessive disclosure | Typed schemas + capabilities | Field-level egress enforcement is host work |
| Remote endpoint compromise | Declared trust boundary | No remote transport shipped |
| Malicious module | No executable requests | Extension profiles need their own review |
| Relay metadata | Transport-dependent | Not mitigated |
| Key compromise | Revocation/lifecycle | Rotation/recovery is profile work |
| Runtime compromise | Minimal trusted code | OS compromise defeats local enforcement |

## Findings

| Finding | Severity | Resolution |
| --- | --- | --- |
| TS schema `minLength`/`maxLength` counted UTF-16 units, not code points | Medium (portability/validation bypass for astral strings) | Fixed; `test/properties.test.ts` |
| Python `multipleOf` used floating division, losing precision for large integers | Medium (validation mismatch for big values) | Fixed with integer modulo; `test_properties.py` |
| Both SDKs sorted keys before NFC normalization (wrong canonical order) | High (canonical byte mismatch, failed interop) | Fixed in Phase 7; `cj2-021`; spec clarified |
| Unpaired surrogates were accepted or crashed | High (cross-language divergence, signing defects) | Fixed in Phase 6; `cj2-008`–`cj2-010`; spec clarified |
| `__proto__` key mutated a JS object prototype | High (parser integrity) | Fixed; `cj2-014` |
| `-0` accepted by Python | Low (profile violation) | Fixed; `cj2-006` |

## Residual risks and open items

1. **No independent audit.** Required before high-impact deployments.
2. **Regex dialects** are not normalized; use the common subset.
3. **In-memory stores** are the default; durability and atomicity are the
   host's responsibility.
4. **Remote execution** is not implemented; the HTTP transport is
   specified (§25.7), but egress enforcement and endpoint authentication
   remain deployment concerns.
5. **Identity bootstrap is format-only.** §25.8 fixes the document and
   admission-policy formats and the verification sequence. It provides no
   discovery, no trust decision, and no key rotation. A host that creates
   contacts from invite links without verifying the fingerprint has no
   identity guarantee.
6. **Revocation durability depends on the deterministic id.** §25.8.3
   fixes a `pg-…` id derived from the policy digest, rule, requester, and
   intent, and `admit()` refuses revoked ids. A host that invents its own
   grant ids, or that drops revoked ids, re-opens the resurrection path.
7. **License is Apache-2.0**; a separate specification licence remains a
   governance choice (§26.8).
8. **Swift/Apple and Android app builds** are not tested here.
9. **Fuzzing** is deterministic property testing, not coverage-guided
   fuzzing; `cargo-fuzz` has not been run.

## Checklist

- [x] Appendix A invariants mapped to code and tests
- [x] §17 threats mapped to controls and residual risks
- [x] Cross-implementation conformance (v1 + v2 + v3 + v4) green
- [x] Property tests for canonicalization and decisions
- [x] Portability defects fixed and covered
- [ ] Independent third-party review
- [ ] Coverage-guided fuzzing
- [ ] Platform builds outside Linux (Apple, Android app)
