# CCP Phase 4 — Independent Implementation Report

**Spec under test:** `CCP/CCP_Working_Draft_v0.3.md`
**Implementer:** independent re-implementation from prose only (no access to
`generate_vectors.py` or `validation.py`).
**Environment:** `/usr/bin/python3` (3.12.3), `cryptography` 50.0.2 for Ed25519.
**Artifacts:** `CCP/phase4/` — `ccp_canonical.py`, `ccp_ed25519.py`,
`ccp_state_machine.py`, `ccp_validation.py`, `run_all.py`.

---

## 1. Matched / total

| Vector set | Matched / total |
| --- | --- |
| canonical-json | 18/18 |
| ed25519 (kat) | 3/3 |
| ed25519 (signing) | 2/2 |
| state-machine | 10/10 |
| validation | 18/18 |

Every frozen vector reproduced. However, several results required choices that
are **not** derivable from the prose and were reconstructed from the vectors
themselves (flagged inline below). Those are the places where two independent
implementers would most likely diverge.

---

## 2. Ambiguities in the prose

### 2.1 Canonical JSON (§25.1)

1. **§25.1 "Strings" vs "Objects" — are object keys NFC-normalized too?**
   The NFC requirement is stated for *strings*; object keys are also JSON
   strings, but the "Objects" bullet only mentions sorting. I normalized both
   keys and values. An implementer who normalizes only values would diverge on
   any document whose keys are not already NFC.

2. **§25.1 — duplicate keys that collide only after NFC normalization.**
   Prose says "duplicate keys MUST cause rejection" but does not say whether
   two distinct raw spellings that normalize to the same NFC string (e.g.
   `"e\u0301"` and `"\u00e9"`) count as duplicates. I rejected them. No vector
   exercises this.

3. **§25.1 — exact escape form for control characters.**
   "the minimal escape set (quotation mark, reverse solidus, and the control
   characters U+0000 through U+001F) MUST be used" does not state whether
   control characters use the short escapes (`\n`, `\t`, `\r`, `\b`, `\f`) or
   the `\uXXXX` form for all. Vector `cj-007` pins `\u000a` → `\n`, but only
   for newline. I used RFC 8259's five short escapes plus `\uXXXX` for the
   remaining control characters. Which control bytes get which form is
   otherwise unspecified.

4. **§25.1 — `signature` ordering is scoped to the top-level signed object.**
   "`signature` MUST be the final field, emitted after the sorted fields and
   not subject to key-sort order" reads as a rule about the signed envelope.
   My recursive serializer applies the exemption at *every* nesting level, so a
   nested object with a key literally named `signature` would also be reordered
   to last. The prose does not say whether the exemption is recursive or
   top-level-only. No vector nests a `signature` key.

5. **§25.1 — "Unicode code point order" for keys outside the BMP.**
   Code-point order and UTF-16 code-unit order agree for ASCII/BMP but diverge
   for supplementary-plane characters (surrogate pairs). The prose does not
   say which is meant. I used Python code-point ordering. Untested.

6. **§25.1 — `-0`.** "only non-negative integers" — is `-0` negative? It
   parses to integer `0`; I accepted it. The prose does not address signed
   zero.

7. **§25.1 — top-level scalars.** The canonical form is defined for objects and
   arrays; the prose never addresses a top-level bare string/number/bool/null.
   I handle them, but they are untested and unspecified.

### 2.2 Ed25519 (§25.2)

8. **§25.2 — private key is the seed, not the expanded scalar.**
   "Ed25519 (RFC 8032)" does not state whether a 32-byte private key is the
   RFC 8032 *seed* (Section 5.1.5) or the already-expanded scalar. RFC 8032
   defines both. I treated it as the seed (matching `cryptography`'s
   `from_private_bytes` and the KAT vectors). A scalar-only interpretation
   would derive a different public key and signatures.

9. **§25.2 — "unpadded base64url" implies the alphabet but not the
   padding rule for lengths that need it.** "unpadded" resolves this (strip
   `=`), but the phrase only appears once and could be missed; no ambiguity in
   practice once read.

### 2.3 State machine (§26.3)

10. **§26.3 — the transition *event* vocabulary is not defined.**
    The mermaid diagram names the *states* and labels only four edges with
    *conditions* ("confirmation required", "no confirmation", "approved",
    "denied"). The initial `[*] → received` edge, `received → authorized`,
    `executing → completed/failed/cancelled/outcome_unknown`, and the `[*]`
    pseudo-state have no names. The vector file introduces event names
    `start`, `arrive`, `validate_ok`, `succeeded`, `failed`, `cancelled`,
    `outcome_lost` that appear nowhere in prose. I mapped them by position.
    Two implementers would almost certainly pick different names (e.g.
    `success` vs `succeeded`, `outcome_unknown` vs `outcome_lost`).

11. **§26.3 vs §10.3 — where does rejection live relative to the machine?**
    The mermaid starts at `received`; §10.3's rejections (unauthenticated,
    no_matching_grant, …) are not states. The prose does not state that
    rejection happens *before* a request enters `received` (the vector README
    asserts this, but that is documentation, not prose). The boundary between
    the validation sequence and the state machine is implicit.

### 2.4 Signal validation (§10.3, §26.1, §10.4)

12. **§25.3 / §8.2 — the concrete `example.lookup` params schema is absent.**
    This is the largest gap. §25.3 defines the schema *language* (a JSON Schema
    subset), and §8.2 references `schema:example.lookup.params.v1` **by URI
    only**. The actual schema content — that `item_id` is a required string and
    `additionalProperties` is `false` — appears nowhere in prose or vectors as a
    schema. I reconstructed it from the §10.2 illustrative signal and vectors
    `v-012`/`v-013`/`v-014`. An implementer without the vectors cannot perform
    §10.3 step 7 at all.

13. **§26.1 / §8.2 — source of an intent's `required_capabilities`.**
    The grant record (§26.1) carries `capabilities` ("required host
    capabilities and resource scopes"), which is consumer-selected, while the
    manifest (§8.2) carries `required_capabilities` (`["store.read"]`). Step 10
    ("host capabilities … match the grant") requires knowing the *intent's*
    requirement, which is manifest data not present in the validation vector's
    grant or signal. I hardcoded `example.lookup → ["store.read"]` from §8.2.
    The relationship between grant `capabilities` and manifest
    `required_capabilities` (subset? equality?) is undefined.

14. **§10.3 steps 2 vs 4 — `unauthenticated` vs `no_matching_grant`.**
    Step 2 is "authenticate the sender," step 4 is "find an active grant
    matching the requester and digest." A wrong signer key is both "not
    authenticated" and "no grant matches this requester." The vectors force a
    split (wrong signer → `unauthenticated`, wrong digest → `no_matching_grant`,
    absent grant → `no_matching_grant`), but the prose does not define that
    split, nor does it explain that "authenticate" is against the *contact* key
    binding (§7, §25.4) rather than the grant. The vector supplies only a single
    grant and no contact record, so the contact-level vs grant-level distinction
    cannot be faithfully reproduced.

15. **§19.1 vs §10.3 — protocol version comparison.**
    §19.1 says "reject an unsupported *major* protocol version," but the label
    `0.3-draft` is "descriptive only" and "not a version negotiation
    mechanism." Under semver, `0.2-draft` and `0.3-draft` share major `0`, so
    "major version" would not reject `0.2-draft`. The vector expects exact
    rejection. I compared the full string against `"0.3-draft"`. The prose
    never defines what string(s) a runtime must accept or the comparison
    (exact vs major vs prefix).

16. **§26.1 / §9.4 — grant expiry: state field vs `expires_at` timestamp.**
    `state` enumerates `expired`, and `expires_at` is a timestamp. Vector
    `v-010` has `state: "active"` with a past `expires_at` and expects
    `grant_expired`, so expiry is computed from the timestamp regardless of the
    state field. The prose does not say whether `expired` is auto-derived from
    `expires_at`, whether the state field is authoritative, or which takes
    precedence when they disagree.

17. **§26.1 / §10.3 — timestamp comparison and the `now` boundary.**
    `created_at`/`expires_at`/`issued_at`/`expires_at` are "RFC 3339" but the
    prose specifies neither the comparison (string vs parsed instant) nor
    whether expiry is inclusive or exclusive at exactly `now` (`<` vs `<=`),
    nor clock-skew policy. I used lexical string comparison with `<=`. The
    vectors never place a timestamp exactly equal to `now`, so the boundary is
    untested and genuinely ambiguous.

18. **§9.2 / §10.3 — cumulative-limit boundary (`>=` vs `>`).**
    "cannot exceed a shared limit" reads as `counter > limit` (still allowed at
    equality), but vector `v-017` has `counter == limit` (10 == 10) and expects
    `limit_exceeded`, implying `>=`. I used `>=`. The prose does not define
    whether the counter counts completed calls or includes the in-flight
    reservation, nor the comparison operator.

19. **§26.1 / §10.3 — counter keying.**
    The grant has `limits.calls_per_hour` and the context has
    `counters.calls_per_hour`; I matched them by name. The prose does not
    define counter naming, nor whether counters are per-intent, per-grant, or
    global, nor their reset period/timezone (§9.2 says a runtime "MUST define"
    these, i.e. it is left to the implementation).

20. **§26.2 / §26.1 — confirmation-policy encoding and semantics.**
    §26.2 defines *categories* (`read`, `disclose`, `write`, `irreversible`)
    with prose defaults ("none", "per action", "per action, always"). The grant
    record's `confirmation` field (§26.1) is "the confirmation policy per
    intent," but the vectors encode it as the literal strings `"none"` and
    `"per_action"` keyed by intent. The prose never defines these literal values
    or their mapping to the category defaults. I treated `"per_action"` as
    `confirmation_required` and *any other value* as `authorized` (a guess).
    The manifest's own `confirmation: "grant-policy"` (§8.2) is a third value
    whose semantics ("defer to the grant") are only implied.

21. **§10.1 / §10.3 — request expiry field and `issued_at`.**
    §10.1 lists "an expiry or validity window" without naming the field, and
    step 8 says "request expiry" without naming the field. I checked
    `expires_at <= now` and ignored `issued_at`. Whether `issued_at` must be
    validated (not in the future, within clock skew) is unspecified and
    untested.

22. **§10.3 step 8 — replay scope.**
    "nonce/request ID uniqueness" does not say whether uniqueness is global,
    per-signer, or per-grant. The vector's `context.seen` is a flat list; I
    treated it as global. The prose does not define the replay-protection scope
    or retention window.

23. **§10.4 / §10.3 step 10 — `capability_unavailable` predicate.**
    I interpreted "the intent's required capabilities are not all present in
    `grant.capabilities`" as `capability_unavailable`. But the code could also
    mean "the host cannot provide an installed capability," independent of the
    grant. The prose does not define the exact predicate, and the vector's
    signal (empty `grant.capabilities`) is consistent with more than one
    interpretation.

24. **§10.1 / §10.3 step 1 — missing required signal fields.**
    Step 1 says to reject "unsupported required fields," and §10.1 enumerates
    required fields, but no vector tests a signal missing e.g. `intent` or
    `request_id`. My `decide()` uses `.get()` with defaults, so a missing
    `grant_digest` would surface as `no_matching_grant` rather than the more
    natural `invalid_request`. Field-presence validation and its error code are
    unspecified.

---

## 3. Discrepancies

None. Every frozen vector reproduced exactly (canonical bytes, Ed25519 KATs and
signatures, state transitions, and validation decisions).

For the record, the following choices were made with the benefit of the vectors
and are the most likely sources of a *latent* discrepancy (i.e. the vectors
happen to agree with my guesses, but the prose does not justify them):

- The `example.lookup` params schema (ambiguity 12).
- The intent's required capabilities (ambiguity 13).
- The `unauthenticated` vs `no_matching_grant` split (ambiguity 14).
- Exact-string protocol version comparison (ambiguity 15).
- `>=` at the cumulative-limit boundary (ambiguity 18).
- Confirmation policy values `"none"`/`"per_action"` (ambiguity 20).
- State-machine event names (ambiguity 10).

None of these is a *vector* error; they are prose under-specifications that the
reference implementation had to resolve one way and an independent
implementation would resolve possibly another.

---

## 4. Suggested minimal spec edits

1. (A1) §25.1 "Strings" — add: "This NFC requirement applies to object
   **keys** as well as string **values**."
2. (A2) §25.1 "Objects" — add: "Keys that differ only by Unicode normalization
   form MUST be treated as duplicate keys."
3. (A3) §25.1 "Escaping" — add: "Control characters are escaped using the
   short forms `\b` (U+0008), `\t` (U+0009), `\n` (U+000A), `\f` (U+000C),
   `\r` (U+000D); all other control characters use the `\u00XX` form."
4. (A4) §25.1 — add: "The `signature` field's final-position rule applies only
   to the top-level signed object; nested objects are sorted normally."
5. (A5) §25.1 "Objects" — clarify: "sorted in ascending order of Unicode scalar
   value (code point), not UTF-16 code unit."
6. (A6) §25.1 "Numbers" — add: "`-0` is rejected (a leading minus sign is not
   permitted)."
7. (A7) §25.1 — add: "The canonical encoding applies to any JSON value,
   including a top-level string, number, boolean, or null."
8. (A8) §25.2 — add: "The private key is the 32-byte RFC 8032 §5.1.5 *seed*;
   public-key derivation and signing follow RFC 8032 §5.1.5/§5.1.6."
9. (A9) §25.2 — add the base64url alphabet explicitly: "RFC 4648 §5 base64url
   (`A–Z a–z 0–9 - _`), padding `=` omitted."
10. (A10) §26.3 — replace the mermaid-only presentation with an explicit
    transition table, or label every edge with a named event, e.g.:
    `start --arrive--> received --validate_ok--> authorized`, etc., defining
    `arrive`, `validate_ok`, `succeeded`, `failed`, `cancelled`,
    `outcome_lost` in prose.
11. (A11) §26.3 — add: "Rejection (§10.4 codes other than
    `confirmation_required`) occurs during the §10.3 validation sequence,
    before the request enters `received`."
12. (A12) §25.3 — add the frozen `example.lookup.params.v1` schema inline (or
    in a normative registry), e.g.
    `{"type":"object","properties":{"item_id":{"type":"string"}},
    "required":["item_id"],"additionalProperties":false}`.
13. (A13) §26.1 — add: "A grant authorizes an intent only if every capability
    in the manifest's `required_capabilities` for that intent is present in the
    grant's `capabilities`."
14. (A14) §10.3 — split step 2 and step 4 explicitly: "Authenticate the sender
    against the contact's bound key; if unauthenticated return
    `unauthenticated`. Then locate a grant whose `requester_key` equals the
    sender and whose `manifest_digest` equals the signal's `grant_digest`; if
    none, return `no_matching_grant`."
15. (A15) §19.1 / §10.3 — replace "major protocol version" with the concrete
    rule: "A runtime for this profile MUST accept exactly the `ccp` value
    `\"0.3-draft\"` and reject any other value with `invalid_request`."
16. (A16) §26.1 / §9.4 — add: "A grant is `expired` when `now >= expires_at`,
    regardless of the stored `state` field; the runtime derives `expired` from
    the timestamp."
17. (A17) §26.1 — add: "All timestamps are RFC 3339 UTC (`...Z`), compared
    lexically; a request or grant whose `expires_at` is lexically `<=` the
    current time is expired."
18. (A18) §9.2 — add: "A limit is exceeded when the relevant counter is
    greater than or equal to the limit value (`counter >= limit`), where the
    counter includes the in-flight reservation."
19. (A19) §26.1 — add the counter-key convention: "Counters are keyed by the
    limit name in `limits` and are maintained per grant."
20. (A20) §26.1 — define the `confirmation` field encoding: "`confirmation` is
    an object mapping intent id to one of `none` or `per_action`; `per_action`
    yields `confirmation_required`, `none` yields `authorized`."
21. (A21) §10.3 step 8 — name the fields: "Reject with `request_expired` when
    the signal's `expires_at` is `<= now`; `issued_at` is recorded but not a
    separate rejection condition in this profile."
22. (A22) §10.3 step 8 — add: "Replay protection is keyed on `request_id` and
    scoped to the requester/grant pair (this profile: a single global set)."
23. (A23) §10.3 step 10 — add the concrete predicate: "If any capability
    required by the intent's manifest is absent from the grant's `capabilities`,
    return `capability_unavailable`."
24. (A24) §10.3 step 1 — add: "A signal missing any field listed in §10.1 is
    `invalid_request`."
