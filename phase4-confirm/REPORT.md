# CCP independent-implementation confirmation report

**Implementer run:** confirmation (second independent implementer)
**Spec:** `CCP/CCP_Working_Draft_v0.3.md`
**Implementation:** `CCP/phase4-confirm/implement.py` (pure rules, no vector data embedded)
**Runner:** `CCP/phase4-confirm/verify.py`
**Method:** derived all rules from the spec prose only, then executed against the four
frozen vector files. The generators (`test-vectors/generate_vectors.py`,
`test-vectors/validation.py`) and `phase4/` were not read.

---

## 1. Matched / total per vector set

| Vector set | Rule | Matched / total |
| --- | --- | --- |
| `canonical-json.json` | §25.1 strict canonical JSON | **18 / 18** |
| `ed25519.json` | §25.2 Ed25519 + key/signature encoding (3 KAT + 2 signing) | **5 / 5** |
| `state-machine.json` | §26.3 side-effect state machine | **10 / 10** |
| `validation.json` | §10.3 + §26.1 + §10.4 validation decision | **18 / 18** |

**Total: 51 / 51 matched.**

Every vector matched byte-for-byte (canonical bytes, `signing_input` and its SHA-256,
Ed25519 public keys / key IDs / signatures / signature fields / wire forms, state-machine
transitions, and validation decisions).

---

## 2. Remaining ambiguities

**Verdict: the prose was sufficient to reproduce every frozen vector with zero
reverse-engineering, but it is not yet fully self-sufficient.** There remain a handful of
points where I had to make an inference and where two independent implementers could
reasonably diverge. The frozen vectors happen to exercise these cases in a way that
pinned the right answer, but the prose alone does not always pin it. These are listed
below in decreasing order of importance.

### 2.1 (Main) The `unauthenticated` vs `no_matching_grant` boundary in the decision layer

This is the one place I am not confident another implementer would land on the same rule
from prose alone.

§10.3 step 2 says "authenticate the sender against the contact's bound key … return
`unauthenticated`". §10.3 step 4 says "find an active grant whose `requester_key` equals
the authenticated sender **and** whose `manifest_digest` equals the signal's
`grant_digest`; if none exists, return `no_matching_grant`".

The frozen vectors (`v-005` vs `v-006`) force a specific split:

- `v-005`: signer ≠ `requester_key`, digest matches → **`unauthenticated`**.
- `v-006`: signer = `requester_key`, digest mismatches → **`no_matching_grant`**.

So the `requester_key` comparison belongs to step 2 (authentication), and step 4 only
checks the digest. I derived this, but it requires reading "the contact's bound key"
(§7.1, §25.4) as "the grant's `requester_key`" and noticing that step 4's own
"`requester_key` equals the authenticated sender" clause is already discharged by step 2.
A reader could just as naturally place the `requester_key` comparison in step 4 and return
`no_matching_grant` for a signer mismatch — which would contradict `v-005`.

A second, sharper ambiguity lives in the null-grant case (`v-004`): `grant = null` → the
vector expects **`no_matching_grant`**, not `unauthenticated`. The decision layer is given
only a single grant (or `null`) plus `signer`; there is no contact store. So
"authentication" is not independently checkable — I inferred it as "the signer must equal
the candidate grant's `requester_key`" and, when no grant exists, the flow falls through
to step 4's "none exists" → `no_matching_grant`. The prose does not state this fallthrough
explicitly, and a strict step-order reading (auth before grant-find) could plausibly
produce `unauthenticated` instead.

The `README.md` describes `signer` as "the already-authenticated requester key", which
adds to the confusion: if authentication already happened upstream, the only remaining
identity check available to the decision layer is `signer == grant.requester_key`.

### 2.2 §10.3 step 5 omits `paused` and `suspended`

Step 5 says only "confirm the grant has not **expired or revoked**". But the error codes
(§10.4) include `grant_paused` and `grant_suspended`, §26.1 defines `state` to include
`paused` and `suspended`, and §9.4 requires that paused/suspended grants deny new
invocations. I rejected `paused`/`suspended` (`v-008`, `v-009`), but the step-5 sentence
does not name them, so a reader must cross-reference three other sections to conclude the
full set of rejection codes. Minor, but the prose in step 5 is incomplete.

### 2.3 Precedence between derived expiry and the explicit `state` field

§26.1 says "the `expired` state is derived from the timestamp regardless of the stored
`state` field". I therefore checked `now >= expires_at` **before** the explicit
`revoked`/`paused`/`suspended` states. No vector combines "revoked (or paused/suspended)"
with "already expired", so this precedence is untested. The prose supports expiry-first,
but the interaction (e.g., a grant that is both `state: revoked` and past its `expires_at`)
is not explicitly resolved.

### 2.4 The decision layer's implicit manifest

The validation decision requires the manifest's `required_capabilities` (step 10) and the
params schema (step 7), but the decision layer is given only the grant, signal, signer,
and context — no manifest. For the single core intent `example.lookup`, the manifest is
fixed by §8.2 (`required_capabilities: ["store.read"]`) and §25.3 (params schema: one
required string `item_id`, `additionalProperties: false`), so I hardcoded both. This is
derivable, but the prose never states that a validation implementation may/should treat
the `example.lookup` manifest as a compile-time constant rather than resolving
`manifest_digest` through a manifest store. A reader could assume a manifest lookup step
that the frozen data does not provide.

### 2.5 Error code for params-schema failures not named inline

Step 7 ("validate parameters strictly against the approved schema") does not state which
§10.4 code a schema violation yields. I used `invalid_request` (consistent with step 1's
"missing field … is `invalid_request`" and "reject … unsupported required fields"), which
matches `v-012`/`v-013`/`v-014`. Defensible, but the code is inferred rather than stated.

### 2.6 Minor / latent, not exercised by any frozen vector

These do not affect the frozen vectors but would affect a novel input, so I record them
for completeness rather than claiming the prose is airtight:

- **`\u00XX` hex letter case (§25.1):** the spec writes `\u00XX` for control characters
  outside `\b \t \n \f \r`, but does not say whether the two hex digits are upper- or
  lower-case. No vector contains such a control character (the only control character
  tested is `\n`, which uses the short form). I emitted lower-case (`\u0001`), matching
  RFC 8785 / Python's `json` convention. Since §25.1 says "the exact byte-level output is
  fixed by the conformance test vectors", the absence of any such vector leaves the byte
  output genuinely undetermined.
- **`NaN`/`Infinity` not named in §25.1:** the spec says "only non-negative integers MAY
  appear" and "floating-point values MUST NOT appear", but never names `NaN`/`Infinity`.
  Rejecting them (as `constant`, per the vector `README`) is implied, but not stated.
- **Number-error precedence:** `-1.5` is both a floating-point value and a negative value;
  §25.1 does not say which rejection wins. I classified a leading `-` as `negative` before
  a `.`/`e` as `float`. Only `-1` (integer-negative) and `1.0`/`1e3` (non-negative float)
  are tested, so the mixed case is unstated.
- **Sorting by code point (not UTF-16 code unit):** the spec is explicit, but no vector
  uses non-BMP (astral-plane) object keys, so the distinction is untested. (I sort by
  code point, as required.)
- **`request_expired` vs `replay_detected` order:** step 8 lists them in that order; no
  vector has a request that is simultaneously expired and replayed, so the ordering is
  untested.

---

## 3. Discrepancies

**None.** All 51 vectors matched exactly on the first full run.

(For transparency: my only environment adjustment was that the active `python3` was a
venv without `cryptography`; I ran with `/usr/bin/python3`, which provides
`cryptography 50.0.2`, exactly as the task environment described.)

---

## 4. Suggested minimal spec edits

1. **§10.3 steps 2 and 4 — disambiguate authentication vs grant matching.** State
   explicitly that step 2 authenticates the sender's identity and that, in the decision
   layer, "authenticated" means the sender's key equals the candidate grant's
   `requester_key`; that a mismatch yields `unauthenticated`; and that step 4 then only
   checks `manifest_digest` equality, yielding `no_matching_grant` on mismatch **or when
   no grant record exists at all**. This collapses ambiguity 2.1.

2. **§10.3 step 5 — enumerate the full non-`active` set.** Change "expired or revoked" to
   something like "not expired, revoked, paused, or suspended (state ∈ §26.1)", and state
   the precedence: derived expiry is checked first ("regardless of the stored `state`"),
   then the explicit lifecycle states. This collapses 2.2 and 2.3.

3. **§10.3 step 7 — name the code.** Add "…validate parameters strictly against the
   approved schema, returning `invalid_request` on failure." (collapses 2.5).

4. **§25.1 — pin the `\u00XX` letter case.** Add "with lowercase hexadecimal digits
   (`\u0000`…`\u001f`)" (or uppercase, whichever is intended) and add a conformance vector
   containing a control character outside `\b \t \n \f \r`. Collapses 2.6's first bullet.

5. **§25.1 — name `NaN`/`Infinity`.** Add "the non-standard constants `NaN`, `Infinity`,
   and `-Infinity` MUST be rejected" and pin the error label used by the conformance
   vectors. Collapses 2.6's second bullet.

6. **§10.3 step 10 / §26.1 — note the fixed manifest.** Add a sentence that, for the
   initial profile, the `example.lookup` manifest's `required_capabilities` (`["store.read"]`)
   and params schema (§25.3) are fixed profile constants the runtime may compile in, so a
   validator need not perform a `manifest_digest` lookup. Collapses 2.4.
