# Design consistency audit

The protocol's value is not that it defines signatures; it is that every
authority path is walkable. This audit checks each stated principle against a
reachable mechanism and a test. It exists because revocation was missing in
practice even though the specification required it: the primitive existed, the
supported path did not.

Method: for each principle, trace **statement → mechanism → path a developer
can actually take → test**. A mechanism without a path counts as missing.

## Verdict

| §3 principle | Mechanism | Reachable path | Test | Status |
| --- | --- | --- | --- | --- |
| 1. Relationship is not authority | contact record vs grant | `verifyIdentityDocument` then `createGrant`; invites create no grant (§25.8.2) | `identity.test.ts`, `identity.py` | pass |
| 2. Least authority | `createGrant` narrows limits, capabilities, placement, egress | `createGrant` / `create_grant` in both SDKs | `grants.test.ts`, `test_grants.py` | fixed |
| 3. Local enforcement | `decide` + `Runtime` | `Runtime.submit` | `runtime.test.ts`, `test_runtime.py` | pass |
| 4. No executable requests | declarative intents only | signal schema rejects code; runtime executes installed intents | `parse`/`vectors` | pass |
| 5. Explicit disclosure | placement + egress on grant and card | `permissionCard`; host metadata enforcement | `egress.test.ts`, `test_egress.py` | fixed |
| 6. Revocation under user control | lifecycle states | `runtime.revokeGrant` / `revoke_grant` | `runtime.test.ts`, SQLite reopen | fixed |
| 7. Safe defaults | fail-closed decisions | `decide`, `admit` defaults | `vectors-validation`, `v4` | pass |
| §7.4 key change | verify → suspend → new grant | `runtime.verifyContactIdentity` | `identity-runtime.test.ts` | fixed |
| 9. Human-usable security | permission card | `permissionCard` | `consumer.test.ts` | pass |
| 10. Agents get no exemption | grants only | `Agent.signalFor` + runtime | `agent.test.ts` | pass |

## Findings

### A. Revocation had no supported path (high, fixed)

`Grant.revoke()` existed in Python but only mutated an object. With
`SqliteStores` the mutation was discarded, and TypeScript had no helper at all.
A policy-created grant also received a random id, so revoking one record did
not bind the next admission.

Fixed:

- `Runtime.revokeGrant(id, reason?)` / `Runtime.revoke_grant(id, reason=None)`
  write through the grant store, append a `revoked` audit event, and return the
  updated record.
- Policy grants use the deterministic `pg-` id (§25.8.3), so a revocation
  survives later admissions.
- `confirm()` re-reads the grant instead of trusting the request snapshot, so a
  revoke invalidates an open confirmation even with a durable store.

### B. Pause, suspend, and resume were not reachable (high, fixed)

§9.4 makes pause and suspend distinct states and requires resume to re-check
authority. Neither SDK could reach those states through the runtime.

Fixed: `pauseGrant`, `suspendGrant`, `resumeGrant`, `suspendContact` (and the
Python equivalents). `resumeGrant` refuses revoked and expired grants and
requires the approved manifest to still be stored. Pause preserves limits,
replay protection, and audit history. A recorded `state_reason` is returned in
the decision's `detail` for paused, suspended, and revoked outcomes.

### C. Python lacked least-authority grant construction (high, fixed)

TypeScript's `createGrant` enforced narrowing; Python callers constructed
`Grant` directly, so the same code could produce a broader grant on one SDK
than the other.

Fixed: `ccp.grants.create_grant` mirrors the TypeScript derivation: limits
cannot exceed `suggested_limits`, capabilities are exactly those required,
placement and egress are derived, and confirmation cannot relax to `none`
without `admitted_by`.

### D. Policy admission was not wired to grants or audit (high, fixed)

§25.8.3 requires the host to create or reuse the grant and record the admitting
rule. The SDKs shipped `admit` and `admittedGrant` but no path that did both.

Fixed: `Runtime.admitRequest` / `Runtime.admit_request` evaluates the policy,
consults revoked ids from the store, creates or reuses the deterministic grant,
audits `{event: "admitted", rule_id}`, and leaves execution to `submit`.

### E. Multiple grants per manifest were resolved arbitrarily (medium, fixed)

A requester can hold a manual grant and a policy grant over the same manifest
digest. `GrantStore.find(requester, digest)` returned one of them, so a signal
could be rejected with `intent_not_allowed` even though another grant enabled
the intent.

Fixed: the runtime prefers a grant that enables the requested intent, then an
active one. `find` remains the fast path.

### F. Model helpers bypassed persistence (medium, fixed by path)

`Grant.pause()`, `suspend()`, `resume()`, and `revoke()` remain pure state
transitions. Using them with a durable store loses the change. The guides now
point at the runtime methods; the model helpers are documented as in-memory
only.

### G. A key change detected but did not suspend anything (high, fixed)

§7.4 requires the runtime to suspend affected grants when a contact's key
changes. `verifyIdentityDocument` reported `identity_changed`, but it is pure,
so nothing happened to the grants.

Fixed: `Runtime.verifyContactIdentity` / `verify_contact_identity` verifies
the document, suspends the contact's grants on a genuine key change, and
audits `identity_changed`. A forged document returns `unauthenticated` and
suspends nothing, so an attacker cannot force a suspension. A grant suspended
this way cannot be resumed; the consumer creates a new grant after
re-introducing the contact (§25.8.4).

### H. Egress was declared but never enforced (high, fixed)

§12 requires a runtime to block undeclared destinations and data categories
where technically enforceable. The grant carried `placement` and `egress`,
and `attenuates` compared them, but execution ignored both because host
functions had no metadata to compare against.

Fixed: `registerHost` / `register_host` now accept `network`, `placement`, and
`fields`, defaulting to local, offline, and none. The runtime refuses with
`capability_unavailable` when the intent's placement is not granted, a host
cannot serve it, a host needs network the grant denies, or a host may transmit
a field the grant does not allow. `HostAccess.call` repeats the check so a
dynamic call cannot escape the ceiling (§26.4).

## Open items

These are known, bounded gaps. None of them lets a requester gain authority it
was not granted.

| Item | Why it is open | What closes it |
| --- | --- | --- |
| 1. Resource limits | Only quota counters (`calls_per_hour`) are enforced. §11.3 is a SHOULD for CPU, time, and size. | Timeouts and payload caps in the executor wrapper; a stated limit per host class. |
| 2. Delegation enforcement | `attenuates` is a pure check; sub-grants are not resolved by the runtime. §26.6 defers this. | A delegated-grant store and a runtime path that selects the narrowest grant. |
| 3. Contact-level pause | §9.4.1 is a MAY. Suspension is provided; pause at contact level is not. | A `pauseContact` wrapper over the same transition. |

## Reproducing

The audit is executable rather than aspirational: each "pass" and "fixed" row
maps to a test.

```sh
(cd sdk/typescript && npx vitest run)
(cd sdk/python && /usr/bin/python3 -m unittest discover -s tests)
/usr/bin/python3 conformance/run.py --skip-build
```

## Rule for future additions

A feature is not done when the primitive exists. It is done when the supported
path uses it, the durable store keeps it, and a test fails if it regresses.
Revocation failed that bar for a release; the same check applies to every new
capability, extension host, and convenience API.
