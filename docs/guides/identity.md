# Identity bootstrap and admission

How a provider publishes who it is, how two parties meet, and how a host
answers a request without asking a human every time.

Normative text: §25.8, with §7.2 (introduction), §7.3 (contact is not
trust), and §7.4 (key changes). This guide is explanatory; where it and
the spec differ, the spec wins.

The design rule in one sentence:

> Publishing is free. Connecting is cheap. Authority is never automatic.

## The three layers

| Layer | Artifact | Signed by | May be automatic? |
| --- | --- | --- | --- |
| Identity | `ccp.identity.v1` document | the identity itself | yes |
| Introduction | invite link, QR, well-known URL | transport | yes, for the *contact* |
| Admission | `ccp.admission-policy.v1` | the host | only for `read`/`disclose` under a reviewed policy |

An identity document and a manifest grant nothing. A contact record grants
nothing. Only a grant authorizes anything, and only the consumer's device
creates one.

### Who is which

- A **provider** publishes a manifest and accepts requests. It publishes
  its identity document automatically — there is no invite step, because
  publishing is what a provider does.
- A **consumer host** owns the resources. It creates grants. Its
  automation lives in an admission policy, approved once by the owner.
- A developer app is usually provider and requester, not consumer. It
  rarely needs to accept an invitation at all.

## Identity document

```json
{
  "ccp": "0.5-draft",
  "type": "ccp.identity.v1",
  "identity": "key:ed25519:BASE64_PUBLIC_KEY",
  "name": "Example Service",
  "roles": ["provider"],
  "endpoints": [
    {
      "transport": "https",
      "manifest": "https://example.com/manifest",
      "signal": "https://example.com/ccp"
    }
  ],
  "manifest_digest": "sha256:HEX_DIGEST",
  "policy_digest": "sha256:HEX_DIGEST",
  "issued_at": "2026-10-22T00:00:00Z",
  "expires_at": "2027-10-22T00:00:00Z",
  "signature": "ed25519:BASE64_SIGNATURE"
}
```

`identity` is the key that verifies `signature`. That is the whole point:
the document is self-certifying, so a registry can help you *find* it but
can never be needed to *check* it.

`manifest_digest` and `policy_digest` bind the document to what the
service currently publishes. Reissue the document when either changes.

### Build

```ts
import {
  buildIdentityDocument,
  verifyManifest,
} from "ccp-core";

const manifest = verifyManifest(manifestWire);

const document = buildIdentityDocument(
  {
    name: "Example Service",
    roles: ["provider"],
    endpoints: [
      {
        transport: "https",
        manifest: "https://example.com/manifest",
        signal: "https://example.com/ccp",
      },
    ],
    manifestDigest: manifest.digest,
    issuedAt: "2026-10-22T00:00:00Z",
    expiresAt: "2027-10-22T00:00:00Z",
  },
  seed
);
```

```python
from ccp import build_identity_document, verify_manifest

manifest = verify_manifest(manifest_wire)

document = build_identity_document(
    {
        "name": "Example Service",
        "roles": ["provider"],
        "endpoints": [
            {
                "transport": "https",
                "manifest": "https://example.com/manifest",
                "signal": "https://example.com/ccp",
            }
        ],
        "manifest_digest": manifest.digest,
        "issued_at": "2026-10-22T00:00:00Z",
        "expires_at": "2027-10-22T00:00:00Z",
    },
    signing_key,
)
```

`ccp.identity.v1` documents are accepted under the `0.5-draft` and
`0.4-draft` labels.

### Verify

```ts
import { verifyIdentityDocument } from "ccp-core";

const peer = verifyIdentityDocument(document, {
  expectedIdentity: knownContactKey,
  manifestDigest: manifest.digest,
  now: "2026-10-22T12:00:00Z",
});

console.log(peer.identity, peer.name);
```

```python
from ccp import verify_identity_document

peer = verify_identity_document(
    document,
    expected_identity=known_contact_key,
    manifest_digest=manifest.digest,
    now="2026-10-22T12:00:00Z",
)
```

`now` defaults to the current clock in both SDKs. Pass it explicitly in
tests and in anything that must be reproducible.

## Introducing a contact

An invitation is a transport artifact. It must resolve to an identity
document plus a fingerprint, and the fingerprint must be verifiable out of
band (§7.2, §25.4).

```text
https://example.com/join?identity=key%3Aed25519%3A...&fp=3f9a...
```

The flow:

1. The host fetches or scans the document.
2. It verifies it with `verifyIdentityDocument`.
3. It compares the fingerprint with the one the person read out, scanned,
   or received over an authenticated channel.
4. It creates a **contact record**: verified identity, name, channel
   binding, source, first-seen time.

Step 4 is the end of it. In this profile, accepting an invitation creates
a contact and nothing else. It does **not**:

- create a grant;
- pre-authorize any intent;
- install an admission rule.

That is deliberate (§7.3). If accepting an invite also granted access,
the invite would be the permission, and an invite is a link you paste into
a chat window.

A single-use invite is still not proof of identity: whoever used the link
may not be the person you meant. Verify the fingerprint.

## Admission policy

An admission policy lets a host say yes to a class of requests without a
click. It is a signed local document; the requester never holds it, and it
cannot widen the requester's authority.

```json
{
  "ccp": "0.5-draft",
  "type": "ccp.admission-policy.v1",
  "host": "key:ed25519:BASE64_PUBLIC_KEY",
  "version": 1,
  "default": "confirm",
  "rules": [
    {
      "id": "r-agent-reads",
      "contacts": ["c-agent-1"],
      "intents": ["files.search", "calendar.read"],
      "risk": "read",
      "limits": { "calls_per_hour": 60 },
      "confirmation": "none",
      "expires_at": "2027-01-01T00:00:00Z"
    }
  ],
  "issued_at": "2026-10-22T00:00:00Z",
  "expires_at": "2027-01-01T00:00:00Z",
  "signature": "ed25519:BASE64_SIGNATURE"
}
```

The constraints that keep this from becoming a back door:

- `default` must be `confirm` or `deny`. `allow` is rejected.
- Every rule must name `contacts` or `requesters`. A rule that names
  neither would match everyone.
- `risk` must be `read` or `disclose`. `write` and `irreversible` can
  never be admitted unattended (§26.2).
- A `disclose` rule must pin `destinations`, and the request's
  destination must be in that list.
- Rules are evaluated in order; the first match wins.
- An expired rule is skipped. An expired policy denies everything.

### Evaluate

The supported path is the runtime, because it must also create the grant and
record the admitting rule (§25.8.3):

```ts
import { verifyAdmissionPolicy } from "ccp-core";

const policy = verifyAdmissionPolicy(policyWire, { expectedHost: hostKey });

const { result, grant } = await runtime.admitRequest({
  policy,
  request: {
    requesterKey,
    contactId: "c-agent-1",
    intent: "files.search",
    risk: "read",
    now: "2026-10-22T12:00:00Z",
  },
  manifest,
});
// result.decision is "allow", "confirm", or "deny".
// grant is the deterministic grant, present only on "allow".
```

```python
from ccp import verify_admission_policy

policy = verify_admission_policy(policy_wire, expected_host=host_key)

outcome = runtime.admit_request(
    policy,
    AdmissionRequest(
        requester_key=requester_key,
        contact_id="c-agent-1",
        intent="files.search",
        risk="read",
        now="2026-10-22T12:00:00Z",
    ),
    manifest,
)
# outcome.result.decision; outcome.grant
```

`admitRequest` does the parts that are easy to get wrong: it reads revoked
ids from the grant store, computes the deterministic grant id, reuses an
existing record instead of widening it, audits `{event: "admitted", rule_id}`,
and sets `confirmation: none` only because the policy is the consumer's
explicit automation decision.

`admit()` and `admittedGrant()` remain exported for embedding and testing.
They are pure: they cannot enforce revocation or audit for you.

`allow` is not an execution. It means "a reviewed rule covers this, so a
narrow grant now exists". The request still goes through `runtime.submit` and
the normal §10.3 decision.

### Revocation wins

A policy match must not resurrect a grant the consumer revoked. The SDK
makes that work by giving every policy-created grant a deterministic id:

```text
pg- + sha256(canonical JSON of {intent, policy, requester, rule})[:32]
```

The record you revoke today is the same record tomorrow's request
resolves to. `admitRequest` already consults the grant store, so the only
thing you call is the revocation itself:

```ts
await runtime.revokeGrant(grant.id, "user asked");
```

```python
runtime.revoke_grant(grant.id, "user asked")
```

Changing the policy changes its digest, which changes every id — that is
the explicit re-approval step. Without deterministic ids, two failures
compound: the revocation binds nothing, and the next matching request
mints the same access under a new id.

That call persists the state, appends a `revoked` audit event, and
invalidates any confirmation still waiting on that grant. The next admission of the
same rule returns `deny / grant_revoked`.

## Result codes

Identity-layer results are separate from the §10.4 decision codes and
must never be returned as a signal outcome.

| Code | Meaning | What to do |
| --- | --- | --- |
| `invalid_request` | malformed, unknown field value, bad window | reject |
| `unauthenticated` | signature does not verify | reject |
| `identity_expired` | outside the validity window (120 s skew) | re-fetch |
| `identity_changed` | key differs from the known contact | suspend grants, re-introduce |
| `manifest_mismatch` | document does not bind the manifest you hold | re-fetch both |
| `policy_mismatch` | document does not bind the policy you hold | re-fetch both |
| `policy_expired` | policy past its `expires_at` | re-approve |

## Key changes

One signing key per identity (§25.2). If a known contact presents a new
key, the runtime suspends the affected grants and the contact must be
re-introduced (§7.4). Use the runtime verifier, not the pure helper, so
the suspension actually happens:

```ts
import { IdentityError } from "ccp-core";

try {
  const peer = await runtime.verifyContactIdentity(document, {
    contactId: "c-agent-1",
    expectedIdentity: contact.identity,
  });
} catch (error) {
  if (error instanceof IdentityError && error.code === "identity_changed") {
    // Grants for c-agent-1 are now suspended and audited.
    // Re-introduce the contact, then create a new grant.
  }
}
```

```python
from ccp import IdentityError

try:
    peer = runtime.verify_contact_identity(
        document,
        contact_id="c-agent-1",
        expected_identity=contact.identity,
    )
except IdentityError as error:
    if error.code == "identity_changed":
        ...  # grants are suspended; re-introduce and create a new grant
```

Two rules make this safe:

- **A forged document suspends nothing.** Only a valid signature from a
  *different* key counts as a change. Otherwise anyone could force a
  suspension by sending garbage.
- **A key-change suspension cannot be resumed.** The old grant is bound
  to the old key, so resuming it would restore authority to a key that no
  longer represents the contact. Create a new grant after the
  introduction.

Multi-device identities, continuity proofs, and recovery are reserved for
a later profile.

## What not to build

- Do not cache an identity document and skip verification because "it
  worked last time". Signatures are cheap.
- Do not treat a registry badge as verification.
- Do not auto-create a grant from an invitation.
- Do not let a policy admit `write` or `irreversible` intents. If a
  product needs that, it needs a separately reviewed profile, not a
  looser parser.

## Vectors

`test-vectors/v4/identity.json` pins the documents, policies, and
admission decisions. Regenerate with:

```sh
/usr/bin/python3 test-vectors/v4/generate.py
```
