# Intent namespace policy

**Status:** normative; see §19.2.1. This guide is explanatory.

**Scope:** intent names carried in a manifest and referenced by a signal or
grant. It does not rename host functions, define a discovery registry's
contents, or change the wire format.

## 1. Three different namespaces

Keep these separate; conflating them is the most common naming mistake.

| Namespace | Example | Defined by | Authority |
| --- | --- | --- | --- |
| Intent name | `com.example.mail.search` | the publisher | domain control or the core registry |
| Host function | `store.read`, `files.search` | the runtime (§26.4) | the implementation |
| Schema id | `schema:example.lookup.params.v1` | the publisher | referenced by the manifest |

Host functions are installed by the runtime and are not publisher-controlled.
Intent names are the publisher's vocabulary and are the subject of this policy.

The wire format does not restrict the `intent` string; canonical JSON allows
any string. These rules are a profile convention enforced by manifests,
registries, and runtimes, not a new encoding constraint.

## 2. Syntax

An intent name is ASCII and lowercase:

```
intent  = segment *( "." segment )
segment = ALPHA_LOWER *( ALPHA_LOWER / DIGIT / "-" )
```

Constraints:

- at least two segments;
- each segment starts with a lowercase letter and is 1–63 characters;
- only `a-z`, `0-9`, and `-` inside a segment; no leading or trailing `-`;
- no uppercase, underscores, empty segments, or consecutive dots;
- total length at most 128 characters;
- no wildcards (`*`), no version suffixes (`…​.v2`), and no non-ASCII
  characters.

Rejecting non-ASCII and uppercase is deliberate: it avoids homograph and
case-folding collisions in permission cards and logs.

### Valid

```
ccp.payment.address.resolve
com.example.mail.search
io.acme.calendar.read
```

### Invalid

```
Example.Lookup        # uppercase
example_lookup        # underscore
example..lookup       # empty segment
example.lookup.v2     # version in the name
*.mail.search         # wildcard
- example.lookup      # leading hyphen / space
com.example.mail!     # punctuation
```

## 3. Namespace tiers

### Protocol-reserved: `ccp.*`

Only intents defined by the protocol belong under `ccp.`. A runtime that does
not implement the named intent MUST reject it (fail closed); it MUST NOT
execute an unknown `ccp.*` intent because a signed manifest listed it.

The current draft's worked examples (`payment.address.resolve`, etc.) are
illustrative. If they are promoted to the core profile, they move under
`ccp.*` (for example `ccp.payment.address.resolve`).

### Publisher: reverse-domain

Third-party intents SHOULD use reverse-domain identifiers, as §19.2 suggests:

```
<reversed domain> . <intent path>
com.example.mail.search      -> publisher controls example.com
uk.co.example.calendar.read  -> publisher controls example.co.uk
```

The publisher may use a namespace only if it controls the corresponding
domain (or has been delegated authority by that domain's owner). Domain control
is the default authority; a registry may index the name but does not grant it.

### Documentation and test names

Two-segment names that are not under `ccp.` — including the frozen
`example.lookup` vector name — are reserved for documentation and tests and
MUST NOT be presented as a production third-party intent.

## 4. Authority and verification

- The runtime cannot verify DNS. A manifest claiming a reverse-domain name is
  a self-assertion.
- Clients SHOULD show the claimed namespace as untrusted text and SHOULD warn
  when the signer's identity is not plausibly associated with that domain.
- The authoritative checks remain local: the contact binding, the signed
  manifest, the grant, and the permission card (§7, §11.4, §19.3).
- A registry listing, review, or badge MUST NOT authorize anything (§19.3).

## 5. Versioning and deprecation

- An intent name is stable. Version changes belong to the manifest `version`
  and the schema ids, never to the name.
- Within one name, changes MUST be additive: new optional parameters, new
  optional result fields. A breaking change needs a new intent name.
- A name MUST NOT be repurposed. Deprecate it, keep resolving it for a
  published sunset window, then retire it; never reuse it for different
  behavior.
- Deprecation and sunset windows for `ccp.*` are a core-registry decision.

## 6. Core registry rules

If a core registry exists, it owns only the `ccp.*` namespace and:

- **Ownership:** a named maintainer group, with a documented change process.
- **Review tiers:** read/control intents need a lightweight review; write,
  egress, compute, and high-impact intents (payments, device control) need a
  stricter, independent review (§19.2, §26.4).
- **Deprecation:** announce, publish a sunset window, and keep the vector
  suites covering the name until retirement.
- **Compatibility:** additive changes only; breaking changes get a new name.
- **Neutrality:** the registry is optional, must not become a trust authority,
  and must not be required for a local runtime to enforce grants.

## 7. Runtime and client behavior

- A runtime MUST NOT execute an intent that is not installed, even when it
  appears in a validly signed manifest (§19.2, §26.4). This already yields
  `intent_not_allowed` or `capability_unavailable`.
- A runtime SHOULD reject manifest or signal intent names that violate §2.
- A runtime MUST reject a `ccp.*` intent it does not implement (fail closed).
- Grant matching is exact string equality. The initial profile has no
  wildcard or prefix grants.
- Permission cards render the intent name plus the provider's description;
  the description is untrusted display text (§11.4).

## 8. Migration notes

- Frozen test vectors keep `example.lookup`; v1 is not edited (see
  `test-vectors/README.md`).
- Production manifests should move to `ccp.*` or reverse-domain names. The
  manifest `version` distinguishes generations during the transition.
- The host catalogue's host identifiers are unchanged; they are a separate
  namespace.

## 9. Open decisions

- **Enforce syntax in the runtime or only in manifests?** Recommendation:
  validate in the runtime's manifest loader and reject invalid names; the wire
  parser stays permissive.
- **Require reverse-DNS for all third parties?** Recommendation: yes, with the
  two-segment `example.*` carve-out for documentation and frozen vectors.
- **Promote the worked examples to `ccp.*`?** Recommendation: yes, when the
  core intent profile is frozen; until then they remain illustrative.
- **Normative adoption.** This policy is normative in §19.2.1; this guide is
  explanatory.
