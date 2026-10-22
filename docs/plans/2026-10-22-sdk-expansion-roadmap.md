# CCP Multi-Language SDK Expansion — Roadmap

**Goal:** Deliver a good, usable CCP SDK to every major audience (web/Node, Python/agents, native mobile, Go/Rust) in a strict one-at-a-time sequence, where each phase produces working, testable software on its own.

**Architecture:** Two layers. A small, byte-exact *kernel* (canonical JSON, Ed25519, schema subset, §10.3 decision, §26.3 state machine) and thin *role-shaped skins* per language — `Requester`, `Consumer`/`Runtime`, `Agent`. Audience-specific *adapters* meet each user in their own workflow (MCP for agents, React/Next for web, middleware for providers). The frozen vectors in `test-vectors/` are the cross-language conformance contract.

**Tech Stack:** TypeScript (browser + Node), Python 3.9+, Rust (WASM + C ABI), Swift, Kotlin, Go. Ed25519 via `@noble/ed25519` (TS) and `cryptography` (Python).

**Spec:** `CCP_Working_Draft_v0.5.md`; contract: `test-vectors/`.

## Global Constraints

- Every implementation MUST reproduce every vector in `test-vectors/*.json`.
- Strict canonical JSON (§25.1): no floats, negatives, `NaN`, or `Infinity`; duplicate keys rejected; NFC strings and keys; keys sorted by Unicode code point; `signature` always last.
- Ed25519 (§25.2): 32-byte RFC 8032 seed; `key:ed25519:<base64url>`; `ed25519:<base64url>` signatures; base64url is RFC 4648 §5 unpadded.
- Core is declarative-only (§25.5): signals never carry executable code.
- Transport-independent: an SDK never assumes a transport.
- The TypeScript core MUST run in both browser and Node (no Node-only APIs in `src/`).
- Commit only when the user explicitly asks.

## The sequence

| # | Phase | Subsystem | Delivers | Depends on | Detailed plan |
|---|-------|-----------|----------|------------|---------------|
| 0 | Layout | repo | `sdk/python`, `sdk/typescript`, `adapters/`, `conformance/`, CI | — | Task 0 below |
| 1 | TS kernel | `sdk/typescript` | canonical, crypto, schema, decision, state machine; 51/51 vectors | 0 | `2026-10-22-ts-kernel.md` |
| 2 | TS roles | `sdk/typescript` | `Requester`, `Consumer`, `Runtime`, `Agent` surfaces | 1 | written at Phase 2 start |
| 3 | TS web + provider | `adapters/` | React/Next permission hook, Express middleware, example provider | 2 | written at Phase 3 start |
| 4 | TS agent | `adapters/mcp` | MCP server exposing capabilities as tools | 2 | written at Phase 4 start |
| 5 | Python roles | `sdk/python` | `Requester`/`Consumer`/`Agent`; FastAPI middleware; Python MCP | 0 | written at Phase 5 start |
| 6 | Conformance | `conformance/` | shared runner, TS↔Python interop, adversarial vectors | 1, 5 | written at Phase 6 start |
| 7 | Rust kernel | `kernel/` | WASM + C ABI kernel; 51/51 vectors | 1, 5 | written at Phase 7 start |
| 8 | Native | `bindings/` | Swift, Kotlin, Go over the kernel; requester examples | 7 | written at Phase 8 start |
| 9 | Hardening | all | security review, fuzzing, expanded catalogue, release | all | written at Phase 9 start |

Each phase is an independent, testable subsystem. Do not start a phase until its dependencies are green.

---

## Phase 0 — Layout

**Goal:** a clean multi-language tree with the conformance contract at the root.

**Files:**
- Move `sdk/` → `sdk/python/` (keep history).
- Create `sdk/typescript/`, `adapters/`, `conformance/`, `docs/guides/`.
- Create root `README.md` (repo map) and `CONTRIBUTING.md`.
- Create `.github/workflows/ci.yml`: run Python tests and TS tests; run vector conformance.

**Key tasks:**
1. `git mv sdk _sdk_tmp && mkdir -p sdk && git mv _sdk_tmp sdk/python`.
2. Fix path resolution in `sdk/python/tests/test_vectors.py`: the vector dir is now `dirname(dirname(SDK_DIR))/test-vectors`, not `dirname(SDK_DIR)/test-vectors`.
3. Update `sdk/python/README.md` links from `../test-vectors/` to `../../test-vectors/`.
4. Add `ci.yml` with a Python job (`/usr/bin/python3 -m unittest discover -s sdk/python/tests`) and a TS job (added in Phase 1).

**Exit criteria:** the existing Python suite is still 20/20 green from the new path; `git status` is clean after commit.

---

## Phase 1 — TypeScript kernel

**Goal:** a browser+Node TS package that reproduces all 51 frozen vectors.

**Files:** `sdk/typescript/{package.json,tsconfig.json,vitest.config.ts}`, `src/{json.ts,parse.ts,crypto.ts,schema.ts,decision.ts,state-machine.ts,signing.ts,index.ts}`, `test/*.test.ts`.

**Key tasks:** strict parser (duplicate keys, integer precision, float/negative/NaN rejection), canonical serializer (NFC, code-point sort, `signature` last), Ed25519 key IDs + sign/verify, schema subset, pure decision, state machine, vector runner.

**Exit criteria:** `npx vitest run` green; all 51 vectors pass.

**Detailed plan:** `2026-10-22-ts-kernel.md`.

---

## Phase 2 — TypeScript role surfaces

**Goal:** idiomatic, typed APIs shaped by role, not by internal modules.

**Files:** `sdk/typescript/src/{requester.ts,consumer.ts,runtime.ts,agent.ts,errors.ts}`, `sdk/typescript/test/*.test.ts`, `sdk/typescript/README.md`.

**Key tasks:**
- `Requester`: build + sign a manifest; build + sign a signal. No grant logic.
- `Consumer`: verify an inbound manifest/signal; produce a permission-card model (plain-language fields from §11.4).
- `Runtime`: grant store, two-phase confirmation, host registry, audit; wrap the Python runtime semantics.
- `Agent`: wrap a tool call into a scoped signal; enforce attenuation (delegation is no broader than the parent).
- Typed errors mirroring §10.4.

**Exit criteria:** the TS runtime replicates the Python end-to-end scenarios (authorized, confirmation, replay, limits, lifecycle, failure modes); `Requester`/`Consumer`/`Runtime`/`Agent` each have a quickstart example.

---

## Phase 3 — TypeScript web + provider adapters

**Goal:** meet web developers and providers where they work.

**Files:** `adapters/react/` (permission-card hook), `adapters/next/` (route handlers), `adapters/express/` (provider middleware), `examples/provider-node/`.

**Key tasks:**
- React hook `usePermissionCard(signal)` that renders the §11.4 fields and resolves confirmation.
- Next.js route handlers for manifest serving and signal verification.
- Express middleware that verifies a signed signal against the grant store.
- A runnable example provider (Node) with a manifest and one intent.

**Exit criteria:** the example provider serves a manifest, accepts a signed signal, and returns an authorized result; the hook renders a permission card in a minimal example.

---

## Phase 4 — TypeScript agent adapter (MCP)

**Goal:** let AI agents use CCP capabilities with least authority.

**Files:** `adapters/mcp/` (server, tool mapping), `examples/agent-mcp/`.

**Key tasks:**
- An MCP server exposing each approved intent as a tool.
- Map a tool call to a signed signal; require a grant; bounded by limits/confirmation.
- Treat all tool output as untrusted input (§15.3).
- A demo agent that calls a capability through MCP.

**Exit criteria:** the MCP tool call round-trips through the runtime; an unauthorized tool call is rejected with the correct §10.4 code.

---

## Phase 5 — Python role surfaces + adapters

**Goal:** parity with the TS role APIs, plus Python-native integrations.

**Files:** `sdk/python/ccp/{requester.py,consumer.py,agent.py}`, `adapters/fastapi/`, `adapters/mcp-python/`, `examples/`.

**Key tasks:**
- Expose `Requester`/`Consumer`/`Agent` over the existing runtime.
- FastAPI middleware for provider/consumer.
- A Python MCP server (for Python agent stacks).
- Keep the vector suite green.

**Exit criteria:** Python role APIs match TS behavior on the same scenarios; adapters have runnable examples.

---

## Phase 6 — Cross-language conformance and interop

**Goal:** prove the spec, not just one implementation.

**Files:** `conformance/{README.md,run.*,interop.*}`, expanded `test-vectors/`.

**Key tasks:**
- A language-neutral runner description; each SDK ships a thin harness.
- Interop: TS signs a manifest/signal → Python verifies, and vice versa.
- Adversarial vectors: duplicate keys, Unicode collisions, astral-plane key sort, clock-boundary cases, replay, limit equality.
- Freeze a second vector set (`test-vectors/v2/`).

**Exit criteria:** TS↔Python interop passes; both implementations pass the expanded suite; every newly found ambiguity is fixed in the spec.

---

## Phase 7 — Portable kernel (Rust → WASM + C ABI)

**Goal:** one vetted core for new platforms, without abandoning independent implementations.

**Files:** `kernel/{Cargo.toml,src/lib.rs,src/wasm.rs,src/capi.rs}`, `bindings/js/`.

**Key tasks:**
- Implement canonical JSON, Ed25519, schema subset, decision, state machine in Rust.
- Expose WASM via `wasm-bindgen` and a C ABI via `cbindgen`.
- Pass all vectors from Rust, WASM, and the C ABI.
- Keep the hand-written TS and Python kernels as *independent* implementations for spec validation.

**Exit criteria:** `cargo test` green; the WASM binding passes the vectors in Node; the C ABI has a smoke test.

---

## Phase 8 — Native bindings

**Goal:** reach device/mobile and Go audiences via the kernel.

**Files:** `bindings/{swift,kotlin,go}/`, `examples/`.

**Key tasks:**
- Swift package (iOS/macOS) over the C ABI; a requester example.
- Kotlin/JVM + Android over the C ABI (JNI or JNA); a requester example.
- Go via cgo; a requester example.
- Each binding runs the vectors.

**Exit criteria:** each binding passes the vector suite and has a working requester example.

---

## Phase 9 — Hardening and release

**Goal:** make it trustworthy and distributable.

**Files:** `SECURITY.md`, `docs/guides/*`, release config for each registry.

**Key tasks:**
- Security review against §17 and Appendix A invariants.
- Fuzz the canonical parser and the decision function (property tests against the vectors).
- Expand the host catalogue beyond the §26.4 core, with review.
- Publish: npm (`ccp-core`), PyPI (`ccp-protocol`), crates.io, SwiftPM, Maven.
- One quickstart per role: web, provider, agent, runtime.

**Exit criteria:** independent security review checklist completed; packages published; quickstarts verified from a clean environment.

---

## Task 0 — Restructure (run first)

```sh
# from the repo root
git mv sdk _sdk_tmp
mkdir -p sdk
git mv _sdk_tmp sdk/python

# vector path now lives two levels up from sdk/python/tests
# edit sdk/python/tests/test_vectors.py:
#   ROOT_DIR = os.path.dirname(SDK_DIR)          -> becomes
#   ROOT_DIR = os.path.dirname(os.path.dirname(SDK_DIR))
# edit sdk/python/README.md: ../test-vectors/ -> ../../test-vectors/

/usr/bin/python3 -m unittest discover -s sdk/python/tests
# expect: 20 tests, OK
```

Do not start Phase 1 until Task 0 is green.
