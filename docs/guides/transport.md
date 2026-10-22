# Transport binding profile: HTTP

**Status:** normative for the HTTP profile; see §25.7. This guide is
explanatory.

**Scope:** endpoints, body encoding, channel binding, status mapping, retries,
confirmation, and limits for providers that accept CCP signals over HTTP. It
does **not** define identity bootstrap (out of band, §7.2) or a browser UI.

Recall the separation in §13: transport security protects the channel, request
signatures bind a request to an identity and exact content, grants decide
whether that identity may ask, and the runtime limits what happens. This
profile never moves authorization into the transport.

## 1. Transport requirements

- The signal endpoint MUST be served over HTTPS with TLS 1.2 or later (TLS 1.3
  recommended). Plain HTTP is acceptable only for loopback development and
  MUST be documented as such.
- The provider MUST reject a body larger than a configured limit (64 KiB is a
  reasonable default) with `413`.
- The provider SHOULD apply connect/read timeouts and per-credential rate
  limits.
- A reverse proxy MAY terminate TLS. The provider MUST accept a forwarded
  client identity only from a trusted proxy, never from a client-supplied
  header alone.

## 2. Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` / `HEAD` | `/manifest` | Serve the signed manifest wire verbatim |
| `POST` | `/ccp` | Submit one signed signal |
| `POST` | `/ccp/confirm` | Resolve a pending confirmation from trusted UI |
| `GET` | `/healthz` | Liveness only; no CCP data |

- `/manifest` returns `200` with `content-type: application/json` and the exact
  string produced by `signManifest`. The provider MUST NOT re-serialize it; a
  consumer verifies the bytes it received.
- `/ccp` accepts a signal. Authorization never happens in the HTTP layer.
- `/ccp/confirm` is provider-controlled. It MUST NOT be reachable with the
  requester's credential (see §8).
- `/healthz` MUST NOT disclose grants, signals, or keys.

## 3. Channel binding (§25.4)

This is the part §25.4 requires every profile to define.

1. The transport MUST authenticate the caller and resolve that caller to
   exactly one Ed25519 public key: the contact's bound key.
2. The resolved key MUST equal the contact's key and the grant's
   `requester_key`. The runtime performs the final comparison (§10.3 step 2).
3. The provider MUST NOT take the requester key from the signal. A signal
   authenticates content; it never establishes identity.
4. An unknown or unauthenticated caller is rejected by the transport with
   `401`. A resolved key that does not match the grant is rejected by the
   runtime with `403 unauthenticated`.

A deployment selects one binding source:

| Source | Caller proves | Resolves to |
| --- | --- | --- |
| Opaque bearer/API credential | possession of a secret | stored contact record → key |
| Mutual TLS | possession of a client certificate | pinned mapping / certificate identity → key |
| Authenticated session | a verified login session | session → contact record → key |

An `x-contact-id`-style header is only a lookup hint. It MUST be paired with a
credential the provider verifies; it is never trusted by itself.

Binding lifecycle:

- Establish the binding out of band before creating a grant (§7.2, §25.4).
- Changing the transport credential or the CCP signing key requires re-binding
  and suspending affected grants (§7.4).
- Revocation must be visible to the next request; do not cache a resolved key
  across requests without invalidation.

## 4. Body encoding

The signal endpoint accepts one of:

- the raw canonical signal JSON as the request body (`content-type:
  application/json`), or
- the envelope `{"signal": "<canonical json string>"}`.

Either way the **exact wire bytes** produced by `signDocument`/`signSignal`
MUST reach the runtime unchanged. The provider MUST NOT parse-then-rewrite the
signal; the strict parser must see the original bytes.

Responses are JSON objects of the shape:

```json
{ "outcome": "authorized", "request_id": "…", "result": { … } }
{ "outcome": "confirmation_required", "request_id": "…", "pending_id": "…" }
{ "outcome": "replay_detected", "error": "replay_detected" }
```

Errors use only §10.4 codes. Responses MUST NOT include stack traces, keys,
signatures, or provider internals.

## 5. Status mapping

All reference adapters share this mapping (`sdk/typescript/src/adapters/status.ts`).

| Condition | Status | Body |
| --- | --- | --- |
| `authorized` | 200 | decision with result |
| `confirmation_required` | 200 | decision with `pending_id` |
| `invalid_request` | 400 | `invalid_request` |
| unknown sender (transport resolved no key) | 401 | `unauthenticated` |
| `unauthenticated` (key mismatch or bad signature) | 403 | `unauthenticated` |
| `no_matching_grant` | 403 | `no_matching_grant` |
| other refusals (§10.4) | 409 | the refusal code |
| unexpected exception | 500 | `outcome_unknown` |

`confirmation_required` is `200`, not an error: the request was accepted and
now needs a trusted decision.

## 6. Replay and retries

- The CCP `request_id` is the replay key (§10.3 step 8). Use a fresh
  `request_id` for every logical request.
- Resending the same signal is a replay and MUST be rejected. Do not use
  transport-level retries as a substitute for a new request.
- After a transport failure whose outcome is unknown, a client MUST NOT blindly
  resend a side-effecting signal. Reconcile first (§14, §26.3). Read-only
  intents may be retried with a new `request_id`.
- The replay store MUST be durable and shared across provider instances. The
  in-memory defaults are single-process only; see `persistence.md`.

## 7. Limits and denial of service

- Enforce the body-size limit and return `413`.
- Rate-limit by credential and, where appropriate, by source; return `429`
  with `Retry-After`. A rate-limited request MUST NOT execute.
- Bound pending confirmations with a TTL sweeper and release their limit
  reservations (`persistence.md`).
- Reject unknown intents and unavailable host functions through the runtime, not
  with bespoke transport checks.

## 8. Confirmation

`confirmation_required` is not an execution. The provider's trusted UI or
device MUST:

1. render the §11.4 card from the runtime's interpretation, not from
   provider-controlled text;
2. authenticate the human decision separately from the requester's credential;
3. call `runtime.confirm(pending_id, approved)` at most once (`take` is
   atomic);
4. re-check grant state at confirm time, because the grant may have changed
   while the prompt was open (§9.4.3).

`/ccp/confirm` MUST be protected as a UI/admin action (session, CSRF, origin
checks). If confirmation happens on a device, the endpoint need not exist.

## 9. Privacy and logging

- Do not log signal params, signatures, or keys. Audit events are runtime
  controlled and local by default (`persistence.md`).
- TLS protects the channel; it does not make a relay observe nothing, and it
  does not stop a remote executor from reading data it receives (§13, §16).
- Browser providers SHOULD restrict CORS origins. The manifest endpoint may be
  public; the signal endpoint should not be.

## 10. Reference implementations

| Runtime | Signal | Manifest |
| --- | --- | --- |
| Express (`ccp-core/express`) | `providerMiddleware` (raw text or `{signal}`) | serve `manifestWire` yourself |
| Next/Web (`ccp-core/next`) | `createSignalHandler` (raw body) | `createManifestHandler` |
| FastAPI (`ccp.adapters.fastapi`) | `provider_router` (`{signal}` envelope) | `manifest_router` |

Adapters only parse the envelope, resolve the sender key, and call the runtime.
To check a new adapter: it MUST forward the exact wire bytes, resolve the key
from the transport (never the signal), and map decisions per §5.

## 11. Open decisions

- **Envelope vs raw body.** Recommendation: accept both, document the raw
  canonical body as the canonical form. The reference adapters already do.
- **Mandatory credential.** Recommendation: TLS plus either a verified bearer
  credential or mTLS; both satisfy channel binding. Do not standardize a single
  vendor mechanism in the core profile.
- **Group transport.** MLS remains a future group profile (§25.4).
- **Normative adoption.** This policy is normative in §19.2.1; this guide is
  explanatory.
