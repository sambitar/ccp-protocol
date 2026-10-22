# Hardening and Release Plan

**Goal:** make the protocol, the SDKs, and the kernel trustworthy and distributable: an evidence-backed security review, property/fuzz tests, a reviewed host catalogue, per-role quickstarts, and release-ready package configs.

**Architecture:** No protocol changes. Hardening adds tests and review evidence around the three independent implementations, fixes two portability gaps found during review, and prepares local release artifacts with an explicit list of what still requires credentials or platforms not present here.

**Spec:** `CCP_Working_Draft_v0.5.md` §17, §19.2, §25.3, §26.4, §26.8, Appendix A.

## Global Constraints

- All 51 v1 vectors, 38 v2 vectors, both SDK suites, the Rust/WASM/C kernel gates, Go, and Kotlin stay green.
- `test-vectors/` v1 stays frozen.
- No license is chosen here; publishing without one is a release blocker and a user decision (§26.8).
- Do not touch the uncommitted TypeScript persistence refactor in the working tree.
- Publishing requires registry credentials and is reported as prepared, not done.
- Commit only when the user asks.

## Findings from the review

1. **Schema string length differs across languages.** TS uses `value.length` (UTF-16 code units); Python and Rust count Unicode code points. JSON Schema defines length in code points. Fix TS to count code points and add tests.
2. **Python `multipleOf` uses floating division.** For large integers this loses precision; TS and Rust use integer modulo. Fix Python to use `%` for integers and add a large-integer test.
3. **Regex dialect is not standardized in the subset.** JS, Python `re`, and Rust `regex` differ. Document the limitation: schemas should use a common subset; the runtime cannot make dialects agree.
4. **No independent review, no license, no registry credentials.** The review here is a self-review; publishing is blocked on user-owned decisions and accounts.

## File map

| Path | Responsibility |
| --- | --- |
| `SECURITY.md` | threat model, invariants, reporting, limitations |
| `docs/security-review.md` | Appendix A checklist with code and test evidence |
| `docs/release.md` | registry checklist, local artifact results, blockers |
| `docs/guides/host-catalogue.md` | core hosts and reviewed extension candidates |
| `docs/guides/{web,provider,agent,runtime}.md` | per-role quickstarts |
| `kernel/tests/properties.rs` | randomized canonical/decision invariants |
| `sdk/python/tests/test_properties.py` | randomized canonical/decision invariants |
| `sdk/typescript/test/properties.test.ts` | randomized canonical/decision invariants |
| `sdk/typescript/src/schema.ts` | code-point string length |
| `sdk/python/ccp/schema.py` | integer `multipleOf` |
| `sdk/typescript/package.json` | publish file list, engine |
| `sdk/python/pyproject.toml` | readme, classifiers, keywords |
| `kernel/Cargo.toml` | readme, keywords, categories |
| `docs/plans/2026-10-22-hardening-release.md` | this plan |

---

### Task 1: Property and fuzz tests

**Rust** (`kernel/tests/properties.rs`):
- [ ] Seeded xorshift PRNG; no new dependencies.
- [ ] Generate depth-limited values with ASCII, NFD sequences, astral characters, controls, quotes, and backslashes.
- [ ] Invariants: `serialize(parse(serialize(v))) == serialize(v)`; parse succeeds on canonical output; integer round-trips exactly.
- [ ] Feed random UTF-8 strings (syntax-heavy pool) to `parse_strict`: it must return `Ok` or `Err`, never panic; on `Ok`, canonicalization must succeed.
- [ ] Decision determinism: randomized states/timestamps/counters/seen over a valid base; two calls agree; outcome is in the known set.
- [ ] 500 iterations per property; run under `cargo test`.

**Python** (`sdk/python/tests/test_properties.py`):
- [ ] Same invariants with `random.Random(seed)`; include lone-surrogate strings (must raise `CanonicalError`).
- [ ] Decision determinism with randomized overrides; 300 iterations.

**TypeScript** (`sdk/typescript/test/properties.test.ts`):
- [ ] Deterministic `mulberry32`; same canonical/parse invariants and decision determinism; 300 iterations.
- [ ] Error messages from random strings must be in the known error-code set.

### Task 2: Portability fixes

- [ ] TS `schema.ts` string length uses `Array.from(value).length`.
- [ ] Python `schema.py` `multipleOf` uses integer modulo when both values are integers.
- [ ] Tests: astral `minLength`/`maxLength` in TS/Python/Rust; `multipleOf` with `18446744073709551616` in Python and Rust.
- [ ] Document the regex-dialect limitation in `docs/security-review.md` and the host catalogue.

### Task 3: Security review

- [ ] `SECURITY.md`: scope, threat model summary (§17), reporting path, supported versions, limitations (no independent review, demo auto-approval, in-memory stores, no transport).
- [ ] `docs/security-review.md`: one row per Appendix A invariant (13) with enforcement point, evidence (test/file), and status; plus the §17 threat table mapped to controls and residual risks.
- [ ] Explicitly list gaps: no third-party audit, no license, MCP example auto-approval, regex dialects, platform coverage (no Apple/Android app build), durable-store responsibility.

### Task 4: Host catalogue

- [ ] `docs/guides/host-catalogue.md`: the six core hosts from §26.4 and
      extension candidates (`calendar.read`, `contacts.read`, `mail.search`,
      `files.write`, `net.request`, `wallet.transaction.prepare`,
      `wallet.transaction.submit`, `device.operation`, `model.infer`,
      `wallet.address.read`). The frozen v5 host vectors retain the older
      `payment.*` sketch names; see the catalogue's naming warning.
- [ ] For each extension: purpose, minimum scope, confirmation requirement, idempotency/recovery, egress, and review status. State that none are enabled by the SDK and each needs its own §19.2 review.

### Task 5: Quickstarts

- [ ] `docs/guides/web.md`: requester + React permission card (TS async runtime).
- [ ] `docs/guides/provider.md`: Express, Next, and FastAPI.
- [ ] `docs/guides/agent.md`: MCP bridge (TS/Python), confirmation boundary.
- [ ] `docs/guides/runtime.md`: TS async runtime and Python runtime; lifecycle, limits, audit, stores.
- [ ] Every snippet is taken from working code; each guide ends with the exact verified command.

### Task 6: Release preparation

- [ ] TS `package.json`: `"files": ["dist", "README.md"]`, `"engines": {"node": ">=18"}`.
- [ ] Python `pyproject.toml`: `readme`, classifiers, keywords.
- [ ] Rust `Cargo.toml`: `readme`, keywords, categories.
- [ ] `docs/release.md`: commands and credential requirements per registry; local artifact evidence; blockers (license, npm scope, PyPI/crates tokens, Maven/Swift absence).
- [ ] Build local artifacts: `npm pack --dry-run` (dist only), `pip wheel --no-deps`, `cargo package --allow-dirty` (verify build).
- [ ] Do not publish.

### Task 7: Full gate

- [ ] `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`.
- [ ] `node bindings/js/test.mjs`; C smoke.
- [ ] TS typecheck + full suite; Python suite.
- [ ] `conformance/run.py --skip-build`, `conformance/interop.py --skip-build`.
- [ ] Go `go test ./...`; Kotlin `build.sh test`.
- [ ] Packaging dry runs.

## Self-review

- Coverage: every Appendix A invariant has an enforcement point and evidence; both new portability gaps are fixed and tested.
- Honesty: publication, external audit, and Apple/Android app builds are called out as not completed.
- No new dependencies in the kernel; property tests are deterministic and fast.
