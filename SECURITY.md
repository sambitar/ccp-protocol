# Security

CCP is a draft protocol (v0.4) with reference implementations in TypeScript,
Python, Rust, Go, and Kotlin/JVM. This document describes the threat model,
the security properties the implementations try to preserve, and how to
report a problem.

## Supported versions

| Version | Status |
| --- | --- |
| 0.5.x (draft) | current development line |

There are no supported production releases yet. Do not deploy CCP with
high-impact capabilities (money movement, physical access, destructive data
operations) without an independent review of your deployment.

## Reporting a vulnerability

Report suspected vulnerabilities privately to the maintainer. Do not open a
public issue with exploit details. Include:

- the affected implementation (spec, TS, Python, Rust kernel, binding),
- the smallest reproduction you can produce,
- the invariant or threat you believe is violated (Appendix A / §17),
- whether the issue is in the protocol, an implementation, an adapter, or
  documentation.

Acknowledgement and a remediation plan will be provided as soon as
practicable. No bug bounty is offered.

## Threat model

CCP assumes the consumer's trusted runtime and operating system are not
fully compromised. If malware controls the device or the runtime, local
enforcement can fail. The protocol does not make that problem disappear.

| Threat | Control in these implementations |
| --- | --- |
| Unauthorized requester | Signature verification plus a stored grant bound to the requester key and manifest digest |
| Malicious provider | Scoped intents, limits, expiry, audit; provider text is untrusted |
| Manifest bait-and-switch | Grants pin the manifest digest; mismatches are rejected |
| Replay | Unique request ids, bounded expiry, durable replay state |
| Duplicate side effect | Two-phase confirmation and the side-effect state machine |
| Limit bypass via concurrency | Atomic reserve-all-or-none limit accounting (host store responsibility) |
| Forged consent UI | Confirmation is a host decision from the §11.4 card; adapters never approve |
| Prompt injection | Tool/provider content is data; authorization is outside the model |
| Confused deputy | Requests are bound to signer, grant, digest, and intent |
| Excessive disclosure | Typed schemas, required capabilities, declared egress |
| Remote endpoint compromise | Remote execution is not implemented in these SDKs; egress is declarative |
| Malicious module | No executable requests in the core; schemas are declarative |
| Key compromise | Grant lifecycle states and revocation; rotation is profile work |
| Runtime compromise | Minimize trusted code; independent review recommended |

## Security properties

Guaranteed under an uncompromised runtime:

- local enforcement of grants,
- data minimization through typed schemas,
- no executable requests in the core,
- revocation blocks new invocations,
- canonical encoding and signature checks are deterministic across
  implementations.

Not guaranteed, and must not be claimed:

- that `local` placement prevents a remote party from reading data,
- that a relay observes nothing,
- anonymity or hidden metadata,
- that a remote executor forgets data it received.

## Known limitations

- **No independent audit.** `docs/security-review.md` is a self-review. It
  is evidence, not assurance by a third party.
- **In-memory defaults.** SDK stores are in-process by default. Durable
  grants, replay state, limits, and pending confirmations are the host's
  responsibility; a process restart loses them. Both SDKs ship a SQLite
  implementation (`ccp.stores_sqlite.SqliteStores` in Python, and
  `SqliteStores` from `ccp-core/node` in Node); other deployments must
  supply their own durable stores.
- **Demo auto-approval.** Examples approve confirmations automatically so
  they run without a UI. That is not a trusted confirmation and is marked in
  the code and READMEs.
- **No remote transport.** The SDKs do not implement remote execution or
  transport encryption; those are deployment choices.
- **Regex dialects.** Schema `pattern` support relies on each language's
  regex engine. The subset does not normalize dialects; use patterns that
  behave identically in ECMAScript, Python `re`, and Rust `regex`.
- **Platform coverage.** The Rust kernel is tested natively, in WASM, and via
  the C ABI. Go and JVM are tested. Swift, iOS/macOS, and an Android app/AAR
  are not built in this repository.

## Verification

Run the security-relevant suites:

```sh
cargo test --manifest-path kernel/Cargo.toml
node bindings/js/test.mjs
/usr/bin/python3 conformance/run.py --skip-build
/usr/bin/python3 sdk/python/tests/test_vectors.py   # or unittest discover
cd sdk/typescript && npx vitest run
cd bindings/go && go test ./...
bindings/kotlin/build.sh test
```

See `docs/security-review.md` for the invariant-by-invariant evidence.
