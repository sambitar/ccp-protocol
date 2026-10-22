# CCP conformance test vectors

Machine-readable vectors for the parts of the initial interoperable
profile that must be deterministic. Each set is generated and self-checked
by a reference script that is also a runnable implementation of the rule.

- Spec: `../CCP_Working_Draft_v0.5.md`
- Rules implemented: §25.1 (strict canonical JSON), §25.2 (Ed25519),
  §26.3 (side-effect state machine), §10.3/§26.1 (signal validation and
  grant matching), §25.8 (identity documents and admission policies),
  §26.4 (host contracts and confirmation floors).

## Files

| File | Generator | Covers |
| --- | --- | --- |
| `canonical-json.json` | `generate_vectors.py` | strict canonical JSON: key sort, whitespace, NFC, escaping, and rejection of floats/duplicate keys/NaN/negative integers. |
| `ed25519.json` | `generate_vectors.py` | RFC 8032 Ed25519 known-answer tests, plus end-to-end signing of a canonical signal and manifest. |
| `state-machine.json` | `generate_vectors.py` | the `received → … → completed/failed/cancelled/outcome_unknown` transition table. |
| `validation.json` | `validation.py` | the §10.3 validation-decision matrix (grant matching, expiry, replay, limits, confirmation, etc.). |
| `v2/` | `v2/generate.py` | adversarial canonical and validation boundaries; see `v2/README.md`. |
| `v3/` | `v3/generate.py` | 0.5 dual-label compatibility; see `v3/README.md`. |
| `v4/identity.json` | `v4/generate.py` | §25.8 identity documents, admission policies, and admission decisions. |
| `v5/hosts.json` | `v5/generate.py` | §26.4 host contracts: classes, risk, confirmation floors, egress. |

## Regenerating

```sh
python3 generate_vectors.py
python3 validation.py
/usr/bin/python3 v2/generate.py
/usr/bin/python3 v3/generate.py
/usr/bin/python3 v4/generate.py
/usr/bin/python3 v5/generate.py
```

v1 is frozen. v2 is additive and is exercised by `conformance/run.py` and
the SDK test suites.

`generate_vectors.py` requires Python 3.8+ and the `cryptography` package.
`validation.py` is pure standard library. `v4/generate.py` also requires
`cryptography`: it signs with fixed seeds. Each script exits 0 only if every
vector passes its self-check.

## `canonical-json.json`

Each entry is one of:

```json
{ "id": "cj-001", "name": "key sort (flat)",
  "document": "{\"b\":1,\"a\":2}",
  "expected_canonical": "{\"a\":2,\"b\":1}" }
```

or, for inputs that must be rejected:

```json
{ "id": "cj-014", "name": "reject float",
  "document": "{\"a\":1.0}",
  "expect_error": "float" }
```

`expect_error` values: `float`, `negative`, `duplicate`, `constant`.

An implementation parses `document` with duplicate-key rejection and
`NaN`/`Infinity` rejection, then re-serializes canonically. The result
must equal `expected_canonical` byte-for-byte, or the parse must fail
with the named `expect_error`.

## `ed25519.json`

- `kat_vectors` — RFC 8032 Ed25519 known-answer tests: given
  `secret_key_hex`, derive `public_key_hex` and `key_id`, sign
  `message_hex`, and match `signature_hex`.
- `signing_vectors` — protocol-level: canonicalize `document` (with
  `signature` excluded) to get `signing_input`, then sign it. The result
  is given as `signature_hex`, `signature_field`
  (`ed25519:<base64url>`), and the final `wire` form. The
  `signing_input_sha256` field lets an implementation check it produced
  identical signing bytes without embedding the full string.

## `state-machine.json`

Each entry is a `(from, event, to)` transition:

```json
{ "id": "sm-003", "from": "authorized",
  "event": "confirmation_required", "to": "awaiting_confirmation" }
```

Rejection (invalid, unauthorized, expired, replayed, or out-of-scope) is
not a machine state: it happens during the §10.3 validation sequence,
before a request enters `received`.

## `validation.json`

Each entry is a full validation case: a grant record (§26.1), a signal,
the authenticated `signer` key, a validation `context` (current time,
seen request IDs, cumulative counters), and the `expected` decision.

```json
{ "id": "v-016", "name": "replay detected",
  "grant": { "…": "…" },
  "signal": { "…": "…" },
  "signer": "key:ed25519:…",
  "context": { "now": "…", "seen": ["req-0001"], "counters": { "…": 0 } },
  "expected": "replay_detected" }
```

Decisions are `authorized`, `confirmation_required`, or a rejection code
from §10.4: `invalid_request`, `unauthenticated`, `no_matching_grant`,
`intent_not_allowed`, `grant_expired`, `grant_revoked`, `grant_paused`,
`grant_suspended`, `request_expired`, `replay_detected`, `limit_exceeded`,
or `capability_unavailable`.

The decision layer is separate from the crypto layer: `signer` is the
already-authenticated requester key (signature verification is covered by
`ed25519.json`), and the signal is already parsed (malformed input is
covered by `canonical-json.json`). Timestamps are compared as strings
because every vector uses the same normalized RFC 3339 UTC form.

## `v4/identity.json`

Three arrays, all keyed by `id`:

- `identities` — each entry has a signed `document`, a `now`, optional
  `expected_identity` / `manifest_digest` / `policy_digest` inputs, and an
  `expected` result: `valid` or an identity-layer code such as
  `unauthenticated`, `identity_expired`, `identity_changed`,
  `manifest_mismatch`, `policy_mismatch`, or `invalid_request`.
- `policies` — the same shape for `ccp.admission-policy.v1`, with
  `expected_host` as the optional pin and `policy_expired` added to the
  possible results.
- `admissions` — a verified `policy`, a `verify_now`, a `request`
  (`requester_key`, `contact_id`, `intent`, `risk`, optional
  `destination`, `now`), and an `expected` decision of `allow`, `confirm`,
  or `deny`. When the decision is `allow`, `expected_rule` names the rule.
  A `revoked` array holds deterministic grant ids the host has revoked, and
  `expected_reason` pins the reason (for example `grant_revoked`).

The vector file is produced by `v4/generate.py`, which signs every document
with a fixed seed and self-checks the admission decisions with a small
reference evaluator.

## `v5/hosts.json`

One array of host-contract cases:

- `host` is the runtime host identifier.
- `profile` is the contract: `class`, `risk`, `minConfirmation`,
  `idempotency`, `network`, `placement`, and `fields`.
- `expected` is `valid` or `invalid_request`.

The first cases are the catalogue both SDKs ship; the rest are rejections:
missing class, suppressed confirmation on a write or irreversible host,
undeclared fields on a network disclose host, unknown placement, duplicate
fields, and a non-boolean `network`.
